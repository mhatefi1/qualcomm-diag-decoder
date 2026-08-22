#!/usr/bin/env python3
"""Decode Poco X3 Dev/Diag captures with the self-contained Python modules."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, TextIO

from dev_diag_decoder_core import (
    CaptureFormatError,
    ReferenceDecoders,
    UnsupportedPacket,
    iter_capture,
    redact,
)


class DecoderError(RuntimeError):
    """A user-facing decoder setup or execution error."""


LOGGER = logging.getLogger("dev_diag_decoder")
PROJECT_ROOT = Path(__file__).resolve().parent


def configure_logging(stream: TextIO | None = None) -> None:
    """Send readable CLI errors to stderr without affecting stdout or JSON."""
    LOGGER.handlers.clear()
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(logging.Formatter("error: %(message)s"))
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.ERROR)
    LOGGER.propagate = False


class ProgressBar:
    """Small dependency-free progress bar that writes only to stderr."""

    def __init__(
        self,
        label: str,
        stream: TextIO | None = None,
        width: int = 28,
        unit: str = "bytes",
    ):
        self.label = label
        self.stream = stream or sys.stderr
        self.width = width
        self.unit = unit
        self.last_percent = -1
        self.terminal = bool(getattr(self.stream, "isatty", lambda: False)())

    def update(self, completed: int, total: int) -> None:
        denominator = max(total, 1)
        percent = min(100, max(0, int(completed * 100 / denominator)))
        if not self.terminal and percent not in {0, 100}:
            if self.last_percent >= 0 and percent < self.last_percent + 10:
                return
        if percent == self.last_percent:
            return
        filled = min(self.width, int(self.width * percent / 100))
        bar = "#" * filled + "-" * (self.width - filled)
        ending = "\r" if self.terminal else "\n"
        self.stream.write(
            f"{self.label}: [{bar}] {percent:3d}% "
            f"({min(completed, total)}/{total} {self.unit}){ending}"
        )
        self.stream.flush()
        self.last_percent = percent

    def finish(self, total: int) -> None:
        self.update(total, total)
        if self.terminal:
            self.stream.write("\n")
            self.stream.flush()

    def abort(self) -> None:
        if self.terminal and self.last_percent >= 0:
            self.stream.write("\n")
            self.stream.flush()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dev_diag_decoder.py",
        description=(
            "Decode Poco X3 Dev/Diag captures with the bundled Python decoder "
            "modules. Input format is detected from content; extensions are ignored."
        ),
        epilog=(
            "Supported input formats:\n"
            "  - PXDG version 1 capture streams\n"
            "  - Raw Poco X3 Qualcomm 0x20-wrapped DIAG data\n"
            "\n"
            "Behavior:\n"
            "  Aggregate statistics are printed to stdout; individual decoded\n"
            "  packets are written only to JSON. Unsupported and malformed packets\n"
            "  do not stop later packets. Progress and errors use stderr.\n"
            "  JSON export is always written with a UTC timestamp in its filename.\n"
            "\n"
            "Dependencies:\n"
            "  python -m pip install -r requirements.txt\n"
            "\n"
            "Examples:\n"
            "  python dev_diag_decoder.py capture_file\n"
            "  python dev_diag_decoder.py capture_file --output result.json\n"
            "\n"
            "Exit codes:\n"
            "  0  Capture processed successfully\n"
            "  1  Decoder, format, import, or output error\n"
            "  2  Invalid command line or input/output path"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "capture_file",
        type=Path,
        metavar="CAPTURE_FILE",
        help="PXDG v1 or raw wrapped-DIAG capture; any filename extension is accepted",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        metavar="JSON_FILE",
        help=(
            "override the mandatory JSON export base path; a UTC timestamp is "
            "inserted before .json (default in project folder: "
            "CAPTURE_FILE.decoded-TIMESTAMP.json)"
        ),
    )
    return parser


def decode_capture(
    capture: Path,
    progress: Callable[[int, int], None] | None = None,
) -> list[dict[str, Any]]:
    try:
        decoders = ReferenceDecoders()
        input_format, total_bytes, chunks = iter_capture(capture)
        if progress:
            progress(0, total_bytes)
        events: list[dict[str, Any]] = []
        decoded = unsupported = malformed = records = rejected_candidates = 0
        signal_counts: dict[int, dict[str, Any]] = {}
        for chunk in chunks:
            records += 1
            for frame, log_id, valid_frame in decoders.frames(chunk.payload):
                body_length = max(0, len(frame) - 26)
                event: dict[str, Any] = {
                    "type": "packet",
                    "index": len(events),
                    "timestamp_nanos": chunk.timestamp_nanos,
                    "log_id": f"0x{log_id:04X}",
                    "payload_bytes": body_length,
                    "schema_id": None,
                    "fields": {},
                    "warnings": [],
                }
                if not valid_frame:
                    rejected_candidates += 1
                    continue
                signal = signal_counts.setdefault(
                    log_id,
                    {
                        "log_id": f"0x{log_id:04X}",
                        "name": decoders.signal_name(log_id),
                        "found": 0,
                        "decoded": 0,
                    },
                )
                signal["found"] += 1
                try:
                    schema_id, fields = decoders.decode(frame, log_id)
                    event.update(
                        status="SUCCESS",
                        schema_id=schema_id,
                        fields=redact(fields),
                    )
                    decoded += 1
                    signal["decoded"] += 1
                except UnsupportedPacket as failure:
                    event["status"] = "UNSUPPORTED"
                    event["warnings"] = [
                        {"code": "unsupported-packet", "message": str(failure)}
                    ]
                    unsupported += 1
                except Exception as failure:
                    event["status"] = "MALFORMED"
                    event["warnings"] = [
                        {
                            "code": "malformed-packet",
                            "message": f"{type(failure).__name__}: {failure}",
                        }
                    ]
                    malformed += 1
                events.append(event)
            if progress:
                progress(chunk.processed_bytes, total_bytes)
        if not events and input_format != "PXDG_V1":
            raise DecoderError(
                "unsupported capture content: expected PXDG v1 or Poco X3 "
                "Qualcomm 0x20-wrapped DIAG data"
            )
        events.append(
            {
                "type": "summary",
                "input_format": input_format,
                "pxdg_records": records if input_format == "PXDG_V1" else 0,
                "packets": len(events),
                "decoded": decoded,
                "unsupported": unsupported,
                "malformed": malformed,
                "pending_bytes": 0,
                "rejected_candidates": rejected_candidates,
                "signals": [signal_counts[key] for key in sorted(signal_counts)],
            }
        )
        if progress:
            progress(total_bytes, total_bytes)
        return events
    except (CaptureFormatError, OSError, ImportError) as failure:
        raise DecoderError(str(failure)) from failure


def print_statistics(events: list[dict[str, Any]]) -> None:
    """Print aggregate processing statistics without exposing decoded records."""
    summary = next(event for event in reversed(events) if event["type"] == "summary")
    print("Statistics:")
    print(f"  Input format:       {summary['input_format']}")
    print(f"  Capture records:    {summary['pxdg_records']}")
    print(f"  Packets found:      {summary['packets']}")
    print(f"  Decoded:            {summary['decoded']}")
    print(f"  Unsupported:        {summary['unsupported']}")
    print(f"  Malformed:          {summary['malformed']}")
    print(f"  Rejected frames:    {summary.get('rejected_candidates', 0)}")
    signals = [
        signal
        for signal in summary.get("signals", [])
        if signal.get("name") != "Unclassified signal"
    ]
    if signals:
        print("  Signals present:")
        for signal in signals:
            print(
                f"    {signal['log_id']}  found={signal['found']} "
                f"decoded={signal['decoded']}  {signal['name']}"
            )


def write_json(path: Path, capture: Path, events: list[dict[str, Any]]) -> None:
    packets = [event for event in events if event["type"] == "packet"]
    summary = next(event for event in reversed(events) if event["type"] == "summary")
    document = {
        "status": "success",
        "capture_file": str(capture),
        "privacy": "sensitive identifiers and binary/security fields are redacted",
        "summary": {key: value for key, value in summary.items() if key != "type"},
        "packets": [{key: value for key, value in item.items() if key != "type"} for item in packets],
    }
    write_json_document(path, document)


def write_error_json(path: Path, capture: Path, message: str, exit_code: int) -> None:
    document = {
        "status": "error",
        "capture_file": str(capture),
        "privacy": "no capture payload was exported",
        "error": {"message": message, "exit_code": exit_code},
        "summary": None,
        "packets": [],
    }
    write_json_document(path, document)


def write_json_document(path: Path, document: dict[str, Any]) -> None:
    destination = path.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            json.dump(document, temporary, ensure_ascii=False, indent=2)
            temporary.write("\n")
        Path(temporary_name).replace(destination)
    except OSError as failure:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)
        raise DecoderError(f"could not write JSON output '{destination}': {failure}") from failure


def utc_filename_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def timestamped_json_path(path: Path, timestamp: str) -> Path:
    """Append a timestamp to an output base name and guarantee a .json suffix."""
    name = path.name[:-5] if path.name.lower().endswith(".json") else path.name
    return path.with_name(f"{name}-{timestamp}.json")


def default_output_path(capture: Path, timestamp: str | None = None) -> Path:
    stamp = timestamp or utc_filename_timestamp()
    return PROJECT_ROOT / f"{capture.name}.decoded-{stamp}.json"


def report_failure(
    message: str,
    exit_code: int,
    output: Path,
    capture: Path,
) -> int:
    LOGGER.error(message)
    try:
        write_error_json(output, capture, message, exit_code)
        LOGGER.error("failure details written to JSON: %s", output)
    except DecoderError as export_failure:
        LOGGER.error("could not write mandatory JSON error output: %s", export_failure)
    return exit_code


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    args = build_parser().parse_args(argv)
    capture = args.capture_file.expanduser().resolve()
    timestamp = utc_filename_timestamp()
    requested_output = args.output.expanduser().resolve() if args.output else None
    output = (
        timestamped_json_path(requested_output, timestamp)
        if requested_output
        else default_output_path(capture, timestamp)
    )
    if requested_output == capture:
        fallback = default_output_path(capture, timestamp)
        return report_failure(
            "--output must not overwrite the input capture; "
            f"error JSON will use '{fallback}'",
            2,
            fallback,
            capture,
        )
    if not capture.exists():
        return report_failure(
            f"capture file does not exist: '{capture}'", 2, output, capture
        )
    if not capture.is_file():
        return report_failure(
            f"capture path is not a file: '{capture}'", 2, output, capture
        )
    decode_progress = ProgressBar("Decoding")
    try:
        events = decode_capture(capture, decode_progress.update)
        decode_progress.finish(capture.stat().st_size)
        export_progress = ProgressBar("Writing JSON", unit="step")
        export_progress.update(0, 1)
        write_json(output, capture, events)
        export_progress.finish(1)
        print_statistics(events)
        print(f"JSON output: {output}")
        return 0
    except DecoderError as failure:
        decode_progress.abort()
        return report_failure(str(failure), 1, output, capture)


if __name__ == "__main__":
    raise SystemExit(main())
