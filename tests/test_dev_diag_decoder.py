import builtins
import json
import io
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import dev_diag_decoder as cli
from decoder_modules import nsg_nas


def diag_frame(log_id, body):
    header = bytearray(
        bytes([0x98, 1, 0, 0, 0, 0, 0, 0, 0x10, 0])
        + struct.pack("<H", 12 + len(body)) * 2
        + struct.pack("<H", log_id)
        + bytes(8)
    )
    return bytes(header) + body + bytes(2) + bytes([0x7E])


def wrapped_diag(*frames):
    payload = b"".join(frames)
    return struct.pack("<III", 0x20, 1, len(payload)) + payload


def pxdg(payload):
    return (
        struct.pack("<4sHHII", b"PXDG", 1, 16, 0, 0)
        + struct.pack("<IIQ", len(payload), 0, 123456789)
        + payload
    )


class DecoderCliTest(unittest.TestCase):
    def test_optional_cryptomobile_warning_is_suppressed(self):
        sentinel = object()
        real_import = builtins.__import__

        def noisy_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "pycrate_mobile":
                print("warning: optional CryptoMobile missing")
                print("warning: optional CryptoMobile missing", file=sys.stderr)
                return type("FakePycrateMobile", (), {"NASLTE": sentinel})()
            return real_import(name, globals, locals, fromlist, level)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch("builtins.__import__", side_effect=noisy_import):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                module, failure = nsg_nas._load_naslte()
        self.assertIs(module, sentinel)
        self.assertIsNone(failure)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")

    def test_help_documents_usage_formats_and_dependencies(self):
        help_text = cli.build_parser().format_help()
        self.assertIn("Supported input formats:", help_text)
        self.assertIn("requirements.txt", help_text)
        self.assertIn("--output JSON_FILE", help_text)
        self.assertIn("Exit codes:", help_text)
        self.assertIn("JSON export is always written", help_text)

    def test_python_decoder_continues_after_unsupported_and_malformed(self):
        valid = bytes.fromhex("02803503063515")
        payload = wrapped_diag(
            diag_frame(0x5B2F, valid),
            diag_frame(0xFFFF, bytes([1])),
            diag_frame(0xB0C1, bytes([2])),
            diag_frame(0x5B2F, valid),
        )
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "capture.arbitrary-extension"
            capture.write_bytes(pxdg(payload))
            events = cli.decode_capture(capture)
        self.assertEqual(
            [item["status"] for item in events[:-1]],
            ["SUCCESS", "UNSUPPORTED", "MALFORMED", "SUCCESS"],
        )
        self.assertEqual(events[-1]["decoded"], 2)
        self.assertEqual(events[-1]["unsupported"], 1)
        self.assertEqual(events[-1]["malformed"], 1)
        self.assertEqual(
            events[-1]["signals"],
            [
                {
                    "log_id": "0x5B2F",
                    "name": "GERAN RR DSDS signaling",
                    "found": 2,
                    "decoded": 2,
                },
                {
                    "log_id": "0xB0C1",
                    "name": "LTE RRC MIB message",
                    "found": 1,
                    "decoded": 0,
                },
                {
                    "log_id": "0xFFFF",
                    "name": "Unclassified signal",
                    "found": 1,
                    "decoded": 0,
                },
            ],
        )

    def test_python_decoder_reports_invalid_frame_and_continues(self):
        valid_body = bytes.fromhex("02803503063515")
        invalid = bytearray(diag_frame(0x5B2F, valid_body))
        invalid[10:12] = struct.pack("<H", 999)
        payload = wrapped_diag(bytes(invalid), diag_frame(0x5B2F, valid_body))
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "mixed"
            capture.write_bytes(pxdg(payload))
            events = cli.decode_capture(capture)
        self.assertEqual(events[0]["status"], "SUCCESS")
        self.assertEqual(events[-1]["packets"], 1)
        self.assertEqual(events[-1]["rejected_candidates"], 1)

    def test_terminal_statistics_hide_unclassified_signals(self):
        events = [{
            "type": "summary",
            "input_format": "PXDG_V1",
            "pxdg_records": 1,
            "packets": 2,
            "decoded": 1,
            "unsupported": 1,
            "malformed": 0,
            "rejected_candidates": 0,
            "signals": [
                {"log_id": "0xB0C0", "name": "LTE RRC OTA packet", "found": 1, "decoded": 1},
                {"log_id": "0xFFFF", "name": "Unclassified signal", "found": 1, "decoded": 0},
            ],
        }]
        output = io.StringIO()
        with redirect_stdout(output):
            cli.print_statistics(events)
        self.assertIn("0xB0C0", output.getvalue())
        self.assertNotIn("0xFFFF", output.getvalue())
        self.assertNotIn("Unclassified signal", output.getvalue())

    def test_python_decoder_accepts_raw_wrapped_diag(self):
        valid = bytes.fromhex("02803503063515")
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "anything"
            capture.write_bytes(wrapped_diag(diag_frame(0x5B2F, valid)))
            events = cli.decode_capture(capture)
        self.assertEqual(events[0]["status"], "SUCCESS")
        self.assertEqual(events[-1]["input_format"], "QUALCOMM_DIAG_RAW")

    def test_python_decoder_decodes_safe_gmm_vector(self):
        body = bytes.fromhex("02011402000814") + bytes(250)
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "gmm.pxdg"
            capture.write_bytes(pxdg(wrapped_diag(diag_frame(0x5C30, body))))
            events = cli.decode_capture(capture)
        self.assertEqual(events[0]["status"], "SUCCESS")
        self.assertEqual(
            events[0]["fields"]["gmm"]["message"],
            "AUTHENTICATION_AND_CIPHERING_REJECT",
        )

    def test_python_decoder_reuses_lte_reference_module(self):
        body = bytes([2]) + struct.pack("<H", 321) + struct.pack("<I", 1650)
        body += struct.pack("<H", 512) + bytes([2, 100])
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "mib.no-extension"
            capture.write_bytes(pxdg(wrapped_diag(diag_frame(0xB0C1, body))))
            events = cli.decode_capture(capture)
        self.assertEqual(events[0]["status"], "SUCCESS")
        self.assertEqual(events[0]["schema_id"], "lte-rrc-mib-b0c1-v2")
        self.assertEqual(events[0]["fields"]["physical_cell_id"], 321)

    def test_write_json_exports_packets_and_summary(self):
        events = [
            {
                "type": "packet",
                "index": 0,
                "timestamp_nanos": 10,
                "log_id": "0xB0C1",
                "payload_bytes": 11,
                "status": "SUCCESS",
                "schema_id": "lte-rrc-mib-b0c1-v2",
                "fields": {"pci": 1},
                "warnings": [],
            },
            {
                "type": "summary",
                "input_format": "PXDG_V1",
                "pxdg_records": 1,
                "packets": 1,
                "decoded": 1,
                "unsupported": 0,
                "malformed": 0,
                "pending_bytes": 0,
                "rejected_candidates": 0,
                "discarded_bytes": 0,
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            cli.write_json(output, Path("capture.any"), events)
            result = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(result["summary"]["decoded"], 1)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["packets"][0]["fields"], {"pci": 1})
        self.assertNotIn("type", result["packets"][0])
        self.assertIn("redacted", result["privacy"])

    def test_missing_capture_returns_usage_error(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "definitely-missing.capture"
            timestamp = "20260823T120000000000Z"
            with patch.object(cli, "PROJECT_ROOT", Path(directory)):
                with patch.object(cli, "utc_filename_timestamp", return_value=timestamp):
                    with redirect_stderr(io.StringIO()):
                        self.assertEqual(cli.main([str(capture), "--device", "poco-x3-surya"]), 2)
            error_output = cli.default_output_path(capture, timestamp)
            error_output = Path(directory) / error_output.name
            self.assertEqual(
                json.loads(error_output.read_text(encoding="utf-8"))["status"],
                "error",
            )

    def test_default_output_uses_project_root(self):
        timestamp = "20260823T120000000000Z"
        with tempfile.TemporaryDirectory() as directory:
            project_root = Path(directory) / "tool"
            capture = Path(directory) / "captures" / "input.pxdg"
            with patch.object(cli, "PROJECT_ROOT", project_root):
                output = cli.default_output_path(capture, timestamp)
        self.assertEqual(
            output,
            project_root / f"input.pxdg.decoded-{timestamp}.json",
        )

    def test_output_cannot_overwrite_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "capture"
            capture.write_bytes(b"PXDG")
            with patch.object(cli, "PROJECT_ROOT", Path(directory)):
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(
                        cli.main([str(capture), "--device", "poco-x3-surya", "--output", str(capture)]), 2
                    )

    def test_main_always_exports_json_and_keeps_progress_off_stdout(self):
        valid = bytes.fromhex("02803503063515")
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "capture.anything"
            capture.write_bytes(pxdg(wrapped_diag(diag_frame(0x5B2F, valid))))
            stdout = io.StringIO()
            stderr = io.StringIO()
            timestamp = "20260823T120000000000Z"
            with patch.object(cli, "PROJECT_ROOT", Path(directory)):
                with patch.object(cli, "utc_filename_timestamp", return_value=timestamp):
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        exit_code = cli.main([str(capture), "--device", "poco-x3-surya"])
            output = Path(directory) / cli.default_output_path(capture, timestamp).name
            document = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(exit_code, 0)
        self.assertEqual(document["status"], "success")
        self.assertEqual(document["summary"]["packets"], 1)
        self.assertIn("Decoding:", stderr.getvalue())
        self.assertIn("Writing JSON:", stderr.getvalue())
        self.assertNotIn("Decoding:", stdout.getvalue())
        self.assertIn("Statistics:", stdout.getvalue())
        self.assertIn("Packets found:      1", stdout.getvalue())
        self.assertIn(
            "0x5B2F  found=1 decoded=1  GERAN RR DSDS signaling",
            stdout.getvalue(),
        )
        self.assertNotIn("0xB0C1", stdout.getvalue())
        self.assertNotIn("[000000]", stdout.getvalue())
        self.assertNotIn("schema=", stdout.getvalue())

    def test_failure_is_logged_and_exported_as_json(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "unsupported.input"
            capture.write_text("not a DIAG capture", encoding="utf-8")
            stderr = io.StringIO()
            timestamp = "20260823T120000000000Z"
            with patch.object(cli, "PROJECT_ROOT", Path(directory)):
                with patch.object(cli, "utc_filename_timestamp", return_value=timestamp):
                    with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                        exit_code = cli.main([str(capture), "--device", "poco-x3-surya"])
            output = Path(directory) / cli.default_output_path(capture, timestamp).name
            document = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(exit_code, 1)
        self.assertEqual(document["status"], "error")
        self.assertIn("error: unsupported capture content", stderr.getvalue())

    def test_custom_output_receives_timestamp_before_json_suffix(self):
        timestamp = "20260823T120000000000Z"
        output = cli.timestamped_json_path(Path("result.json"), timestamp)
        self.assertEqual(output, Path(f"result-{timestamp}.json"))


if __name__ == "__main__":
    unittest.main()
