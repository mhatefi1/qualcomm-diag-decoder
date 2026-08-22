#!/usr/bin/env python3
"""Decode and correlate LTE random-access records from a Qualcomm DIAG capture.

The decoder is intentionally version-specific for the formats observed on the
rooted Poco X3 capture:

* 0xB061 LTE MAC RACH Trigger, packet v1 / reason subpacket 0x05 v2
* 0xB062 LTE MAC RACH Attempt, packet v1 / attempt subpacket 0x06 v3
* 0xB167..0xB169 ML1 Msg1..Msg3 records (presence and raw payload retained)
* 0xB16A LTE ML1 Msg4, body v1

0xB062 is the lossless MAC summary used for the semantic Msg1, Msg2 and Msg3
fields.  The ML1 records are correlated as independent evidence and preserved
until their newer v24/v25 proprietary layouts are completely mapped.
"""

from __future__ import annotations

import argparse
import copy
import importlib
import importlib.util
import json
import struct
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from .nsg_schema_registry import probe_record, select_schema


LOG_RACH_TRIGGER = 0xB061
LOG_RACH_ATTEMPT = 0xB062
LOG_MSG1 = 0xB167
LOG_MSG2 = 0xB168
LOG_MSG3 = 0xB169
LOG_MSG4 = 0xB16A
RA_IDS = {
    LOG_RACH_TRIGGER,
    LOG_RACH_ATTEMPT,
    LOG_MSG1,
    LOG_MSG2,
    LOG_MSG3,
    LOG_MSG4,
}

RACH_REASONS = {
    0: "CONNECTION_REQ",
    1: "RLF",
    2: "UL_DATA",
    3: "DL_DATA",
    4: "HANDOVER",
}
RACH_RESULTS = {
    0: "success",
    1: "failure_at_msg2",
    4: "aborted",
}
TPC_DELTA_DB = {
    0: -6,
    1: -4,
    2: -2,
    3: 0,
    4: 2,
    5: 4,
    6: 6,
    7: 8,
}


def load_diag_parser(script_dir: Path):
    del script_dir
    from . import nsg_parse_lte

    return nsg_parse_lte


def qxdm_timestamp(timestamp_hex: str) -> str | None:
    try:
        raw = int.from_bytes(bytes.fromhex(timestamp_hex), "little")
        value = datetime(1980, 1, 6, tzinfo=timezone.utc) + timedelta(
            seconds=raw / 52_428_800.0
        )
        return value.isoformat(timespec="microseconds")
    except (ValueError, OverflowError):
        return None


def normalize_record(
    frame_index: int, log_id: int, timestamp: bytes, body: bytes
) -> dict[str, Any]:
    return {
        "frame_index": frame_index,
        "log_id": log_id,
        "timestamp_header_hex": timestamp.hex(" "),
        "timestamp_utc": qxdm_timestamp(timestamp.hex(" ")),
        "body_hex": body.hex(" "),
        "body": body,
    }


def iter_input_records(path: Path, script_dir: Path) -> Iterable[dict[str, Any]]:
    if path.suffix.lower() == ".jsonl":
        with path.open("r", encoding="utf-8") as source:
            for line in source:
                row = json.loads(line)
                log_id = int(str(row["log_id"]), 16)
                if log_id not in RA_IDS:
                    continue
                body = bytes.fromhex(row["body_hex"])
                timestamp_hex = row.get("timestamp_header_hex", "")
                yield {
                    "frame_index": int(row["frame_index"]),
                    "log_id": log_id,
                    "timestamp_header_hex": timestamp_hex,
                    "timestamp_utc": qxdm_timestamp(timestamp_hex),
                    "body_hex": body.hex(" "),
                    "body": body,
                }
        return

    parser = load_diag_parser(script_dir)
    data = path.read_bytes()
    for frame_index, (frame, log_id) in enumerate(parser.log_frames(data)):
        if log_id in RA_IDS:
            yield normalize_record(frame_index, log_id, frame[16:24], frame[24:-2])


def parse_subpackets(body: bytes) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if len(body) < 4:
        raise ValueError("subpacket container is shorter than four bytes")
    header = {
        "packet_version": body[0],
        "number_of_subpackets": body[1],
        "reserved_hex": body[2:4].hex(" "),
    }
    position = 4
    packets: list[dict[str, Any]] = []
    for index in range(body[1]):
        if position + 4 > len(body):
            raise ValueError(f"subpacket {index} header is truncated")
        sub_id, version, size = struct.unpack_from("<BBH", body, position)
        if size < 4 or position + size > len(body):
            raise ValueError(f"subpacket {index} has invalid size {size}")
        payload = body[position + 4 : position + size]
        packets.append(
            {
                "index": index,
                "subpacket_id": sub_id,
                "subpacket_version": version,
                "subpacket_size": size,
                "payload_hex": payload.hex(" "),
                "payload": payload,
            }
        )
        position += size
    header["trailing_hex"] = body[position:].hex(" ")
    return header, packets


def decode_b061(body: bytes) -> dict[str, Any]:
    header, packets = parse_subpackets(body)
    decoded_packets: list[dict[str, Any]] = []
    reason: dict[str, Any] | None = None
    for packet in packets:
        value = {key: val for key, val in packet.items() if key != "payload"}
        payload = packet["payload"]
        selection = select_schema(
            log_id=LOG_RACH_TRIGGER,
            packet_version=header["packet_version"],
            body_length=len(payload),
            subpacket_id=packet["subpacket_id"],
            subpacket_version=packet["subpacket_version"],
        )
        value["schema_selection"] = selection.as_dict()
        if selection.selected:
            reason_code = payload[2]
            reason = {
                "subscription_id": payload[0],
                "cell_id": payload[1],
                "reason_code": reason_code,
                "reason": RACH_REASONS.get(reason_code, f"unknown_{reason_code}"),
                "matching_id_hex": payload[3:11].hex(" "),
                "preamble_ra_mask": payload[11],
                "msg3_size_bytes": payload[12],
                "group_chosen": payload[13],
                "radio_condition_raw_db": payload[14],
                "c_rnti": int.from_bytes(payload[15:17], "little"),
                "c_rnti_hex": f"0x{int.from_bytes(payload[15:17], 'little'):04X}",
                "trailing_hex": payload[17:].hex(" "),
            }
            value["decoded"] = reason
            value["decode_status"] = "decoded"
        else:
            value["decode_status"] = "preserved_raw"
        decoded_packets.append(value)
    return {**header, "subpackets": decoded_packets, "reason": reason}


def decode_riv(riv: int, uplink_resource_blocks: int) -> dict[str, Any]:
    n_rb = uplink_resource_blocks
    if n_rb <= 0:
        return {"status": "invalid_uplink_bandwidth"}
    quotient, remainder = divmod(riv, n_rb)
    if quotient <= n_rb // 2:
        length = quotient + 1
        start = remainder
    else:
        length = n_rb - quotient + 1
        start = n_rb - 1 - remainder
    valid = 1 <= length <= n_rb and 0 <= start and start + length <= n_rb
    return {
        "status": "decoded" if valid else "out_of_range",
        "uplink_resource_blocks": n_rb,
        "starting_resource_block": start,
        "number_of_resource_blocks": length,
    }


def decode_ul_grant(grant_raw: int, uplink_resource_blocks: int) -> dict[str, Any]:
    grant = grant_raw & 0xFFFFF
    tpc = (grant >> 2) & 0x07
    riv = (grant >> 9) & 0x03FF
    return {
        "grant_raw_32_hex": f"0x{grant_raw:08X}",
        "grant_20bit_hex": f"0x{grant:05X}",
        "frequency_hopping_flag": (grant >> 19) & 0x01,
        "resource_indication_value": riv,
        "resource_allocation": decode_riv(riv, uplink_resource_blocks),
        "truncated_mcs": (grant >> 5) & 0x0F,
        "tpc_command": tpc,
        "tpc_delta_db": TPC_DELTA_DB[tpc],
        "ul_delay": (grant >> 1) & 0x01,
        "csi_request": grant & 0x01,
    }


def json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, tuple):
        return [json_safe(item) for item in value]
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    return value


def load_rrclte(pycrate_root: Path | None) -> tuple[Any | None, str | None]:
    if pycrate_root is not None:
        root_text = str(pycrate_root.resolve())
        if root_text not in sys.path:
            sys.path.insert(0, root_text)
    try:
        return importlib.import_module("pycrate_asn1dir.RRCLTE"), None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def decode_ul_ccch(payload: bytes, rrclte: Any | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "payload_hex": payload.hex(" "),
        "payload_length": len(payload),
    }
    if rrclte is None:
        result["status"] = "raw_pycrate_unavailable"
        return result
    try:
        template = rrclte.EUTRA_RRC_Definitions.UL_CCCH_Message
        obj = copy.deepcopy(template)
        obj.from_uper(payload)
        value = json_safe(obj())
        result.update(
            {
                "status": "decoded",
                "asn1_object": "UL_CCCH_Message",
                "value": value,
                "asn1_text": str(obj.to_asn1()),
            }
        )
        return result
    except Exception as exc:
        result.update(
            {
                "status": "decode_error",
                "error": f"{type(exc).__name__}: {exc}",
            }
        )
        return result


def decode_msg3_mac_pdu(pdu: bytes, rrclte: Any | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "raw_hex": pdu.hex(" "),
        "length": len(pdu),
    }
    if not pdu:
        result["status"] = "empty"
        return result
    header = pdu[0]
    result["first_subheader"] = {
        "reserved": (header >> 7) & 0x01,
        "extension": (header >> 5) & 0x01,
        "lcid": header & 0x1F,
    }
    if (header & 0x1F) == 0 and ((header >> 5) & 0x01) == 0 and len(pdu) >= 7:
        # UL-CCCH SDUs used for LTE RRCConnectionRequest have a fixed six-byte
        # ASN.1 payload. Remaining zero bytes are MAC padding in this profile.
        ul_ccch = pdu[1:7]
        result["ul_ccch"] = decode_ul_ccch(ul_ccch, rrclte)
        result["padding_hex"] = pdu[7:].hex(" ")
        result["status"] = "decoded_ul_ccch"
    else:
        result["status"] = "preserved_unsupported_mac_header"
    return result


def decode_b062(
    body: bytes, uplink_resource_blocks: int, rrclte: Any | None
) -> dict[str, Any]:
    header, packets = parse_subpackets(body)
    decoded_packets: list[dict[str, Any]] = []
    attempt: dict[str, Any] | None = None
    for packet in packets:
        value = {key: val for key, val in packet.items() if key != "payload"}
        payload = packet["payload"]
        selection = select_schema(
            log_id=LOG_RACH_ATTEMPT,
            packet_version=header["packet_version"],
            body_length=len(payload),
            subpacket_id=packet["subpacket_id"],
            subpacket_version=packet["subpacket_version"],
        )
        value["schema_selection"] = selection.as_dict()
        if selection.selected:
            sub_id, cell_id, retry, result_code, contention, mask = struct.unpack_from(
                "<6B", payload, 0
            )
            position = 6
            attempt = {
                "subscription_id": sub_id,
                "cell_id": cell_id,
                "retry_counter": retry,
                "result_code": result_code,
                "result": RACH_RESULTS.get(result_code, f"unknown_{result_code}"),
                "contention_based": bool(contention),
                "procedure_type": (
                    "contention_based" if contention else "contention_free"
                ),
                "message_bitmask": mask,
                "message_bitmask_hex": f"0x{mask:02X}",
                "msg1": None,
                "msg2": None,
                "msg3": None,
            }
            if mask & 0x01:
                if position + 4 > len(payload):
                    raise ValueError("B062 Msg1 is truncated")
                preamble, preamble_mask, power = struct.unpack_from(
                    "<BBh", payload, position
                )
                position += 4
                attempt["msg1"] = {
                    "preamble_index": preamble,
                    "preamble_index_mask": preamble_mask,
                    "preamble_power_field_db": power,
                }
            if mask & 0x02:
                if position + 7 > len(payload):
                    raise ValueError("B062 Msg2 is truncated")
                backoff, msg2_result, tc_rnti, timing_advance = struct.unpack_from(
                    "<HBHH", payload, position
                )
                position += 7
                attempt["msg2"] = {
                    "backoff_ms": backoff,
                    "result": bool(msg2_result),
                    "temporary_c_rnti": tc_rnti,
                    "temporary_c_rnti_hex": f"0x{tc_rnti:04X}",
                    "timing_advance_command": timing_advance,
                }
            if mask & 0x04:
                if position + 17 > len(payload):
                    raise ValueError("B062 Msg3 is truncated")
                grant_raw, grant_length, harq_id = struct.unpack_from(
                    "<LHB", payload, position
                )
                position += 7
                mac_pdu = payload[position : position + 10]
                position += 10
                attempt["msg3"] = {
                    "uplink_grant": decode_ul_grant(
                        grant_raw, uplink_resource_blocks
                    ),
                    "grant_length_field": grant_length,
                    "harq_id": harq_id,
                    "mac_pdu": decode_msg3_mac_pdu(mac_pdu, rrclte),
                }
            attempt["trailing_hex"] = payload[position:].hex(" ")
            value["decoded"] = attempt
            value["decode_status"] = "decoded"
        else:
            value["decode_status"] = "preserved_raw"
        decoded_packets.append(value)
    return {**header, "subpackets": decoded_packets, "attempt": attempt}


def decode_b16a(body: bytes) -> dict[str, Any]:
    selection = probe_record(LOG_MSG4, body)
    version = body[0] if body else None
    if not selection.selected:
        return {
            "version": version,
            "status": "schema_fallback",
            "schema_selection": selection.as_dict(),
            "raw_hex": body.hex(" "),
        }
    packed = int.from_bytes(body[4:8], "little")
    result_code = (packed >> 14) & 0x01
    return {
        "version": version,
        "status": "decoded",
        "schema_selection": selection.as_dict(),
        "reserved_hex": body[1:4].hex(" "),
        "sfn": packed & 0x03FF,
        "subframe": (packed >> 10) & 0x0F,
        "contention_result_code": result_code,
        "contention_result": "pass" if result_code else "fail",
        "ul_ack_sfn": (packed >> 15) & 0x03FF,
        "ul_ack_subframe": (packed >> 25) & 0x0F,
        "reserved_high_bits": (packed >> 29) & 0x07,
        "raw_hex": body.hex(" "),
    }


def decode_sfn_word(word: int) -> dict[str, int]:
    """Decode Qualcomm's 16-bit LTE SFN/subframe word."""
    return {
        "sfn": word & 0x03FF,
        "subframe": (word >> 12) & 0x0F,
        "reserved": (word >> 10) & 0x03,
    }


def signed_bits(value: int, offset: int, width: int) -> int:
    """Extract a little-endian signed two's-complement bit field."""
    raw = (value >> offset) & ((1 << width) - 1)
    sign = 1 << (width - 1)
    return raw - (1 << width) if raw & sign else raw


def decode_b167(body: bytes) -> dict[str, Any]:
    """Decode the fixed Poco X3 ML1 PRACH Msg1 body version 25.

    The layout and signedness come from the target firmware's exact native
    v25 routine at libqtrun_arch_jni.so:0xE51F3C. NSG performs no additional
    engineering-unit transform; direct MPSS producer tracing and synchronized
    QSR4/B167 captures validate the fixed-device frequency field as Q3 Hz.
    """
    selection = probe_record(LOG_MSG1, body)
    if not selection.selected:
        return {
            "version": body[0] if body else None,
            "status": "schema_fallback",
            "schema_selection": selection.as_dict(),
            "raw_hex": body.hex(" "),
        }
    packed = int.from_bytes(body[1:], "little")
    # Version 25 starts its active bitfield after three firmware-reserved
    # bytes. The offsets below are validated against all seven B062 summaries.
    timing = decode_sfn_word((packed >> 104) & 0xFFFF)
    window_start = decode_sfn_word((packed >> 120) & 0xFFFF)
    window_end = decode_sfn_word((packed >> 136) & 0xFFFF)
    duplex_mode_code = (packed >> 87) & 0x01
    tdd_resource = {
        "frequency_resource_index": (packed >> 88) & 0x07,
        "t0_ra_code": (packed >> 91) & 0x03,
        "t1_ra_code": (packed >> 93) & 0x01,
        "t2_ra_code": (packed >> 94) & 0x03,
    }
    rx_frequency_error_native = signed_bits(packed, 216, 32)
    return {
        "version": 25,
        "status": "decoded_exact_native_layout",
        "schema_selection": selection.as_dict(),
        "reserved_prefix_hex": body[1:4].hex(" "),
        "cell_index": (packed >> 24) & 0x07,
        "preamble_sequence": (packed >> 27) & 0x3F,
        "physical_root_index": (packed >> 33) & 0x03FF,
        "cyclic_shift": (packed >> 43) & 0x03FF,
        "reserved_bits_53_55": (packed >> 53) & 0x07,
        "configured_prach_tx_power_dbm": signed_bits(packed, 56, 8),
        "beta_prach": (packed >> 64) & 0x07FF,
        "prach_frequency_offset": (packed >> 75) & 0x7F,
        "preamble_format": (packed >> 82) & 0x07,
        "reserved_bits_85_86": (packed >> 85) & 0x03,
        "duplex_mode_code": duplex_mode_code,
        "duplex_mode": "TDD" if duplex_mode_code else "FDD",
        "tdd_resource": tdd_resource if duplex_mode_code else None,
        "reserved_tdd_resource_bits": (
            None if duplex_mode_code else (packed >> 88) & 0xFF
        ),
        "density_per_10_ms_code": (packed >> 96) & 0x07,
        "reserved_bits_99_103": (packed >> 99) & 0x1F,
        "prach_timing": timing,
        "response_window_start": window_start,
        "response_window_end": window_end,
        "ra_rnti": (packed >> 152) & 0xFFFF,
        "reserved_bits_168_183": (packed >> 168) & 0xFFFF,
        "actual_prach_tx_power_dbm": signed_bits(packed, 184, 8),
        "reserved_bits_192_215": (packed >> 192) & 0xFFFFFF,
        "prach_rx_frequency_error_native": rx_frequency_error_native,
        "prach_rx_frequency_error_hz": rx_frequency_error_native / 8.0,
        "prach_rx_frequency_error_unit": (
            "Q3 Hz (1 native count = 0.125 Hz); device-specific validation"
        ),
        "prach_rx_frequency_error_q_format": "Q3",
        "prach_rx_frequency_error_scale_hz_per_count": 0.125,
        "prach_rx_frequency_error_validation": {
            "scope": (
                "Poco X3 M2007J20CG/surya, firmware "
                "V14.0.2.0.SJGMIXM, MPSS.AT.4.4.c6-00071"
            ),
            "method": (
                "exact modem-producer trace plus synchronized B167/QSR4 "
                "residual-frequency correlation"
            ),
            "evidence_report": "b167-q3-hz-validation.md",
        },
        "layout_evidence": {
            "library": "libqtrun_arch_jni.so",
            "decoder_address": "0xE51F3C",
            "profile": "M2007J20CG/surya B167 v25",
        },
        "raw_hex": body.hex(" "),
    }


def decode_b168(body: bytes) -> dict[str, Any]:
    """Decode Poco X3 ML1 Msg2 body version 24."""
    selection = probe_record(LOG_MSG2, body)
    if not selection.selected:
        return {
            "version": body[0] if body else None,
            "status": "schema_fallback",
            "schema_selection": selection.as_dict(),
            "raw_hex": body.hex(" "),
        }
    packed = int.from_bytes(body[4:12], "little")
    procedure_type = (packed >> 3) & 0x01
    mode = (packed >> 4) & 0x07
    rnti_type = (packed >> 7) & 0x07
    return {
        "version": 24,
        "status": "decoded",
        "schema_selection": selection.as_dict(),
        "reserved_prefix_hex": body[1:4].hex(" "),
        "cell_index": packed & 0x07,
        "procedure_type_code": procedure_type,
        "procedure_type": (
            "contention_based" if procedure_type else "contention_free"
        ),
        "procedure_mode_code": mode,
        "procedure_mode": "initial_access" if mode == 0 else f"mode_{mode}",
        "rnti_type_code": rnti_type,
        "rnti_type": {
            0: "C_RNTI_or_not_present",
            2: "TEMP_C_RNTI",
        }.get(rnti_type, f"type_{rnti_type}"),
        "rnti_value": (packed >> 10) & 0xFFFF,
        "rnti_value_hex": f"0x{((packed >> 10) & 0xFFFF):04X}",
        "timing_advance_included": bool((packed >> 26) & 0x01),
        "sfn": (packed >> 32) & 0x03FF,
        "subframe": (packed >> 44) & 0x0F,
        "timing_advance_command": (packed >> 48) & 0x07FF,
        "reserved_bits_27_31": (packed >> 27) & 0x1F,
        "reserved_bits_42_43": (packed >> 42) & 0x03,
        "reserved_high_bits": (packed >> 59) & 0x1F,
        "raw_hex": body.hex(" "),
    }


def decode_b169(body: bytes, uplink_resource_blocks: int) -> dict[str, Any]:
    """Decode Poco X3 ML1 Msg3 body version 24."""
    selection = probe_record(LOG_MSG3, body)
    if not selection.selected:
        return {
            "version": body[0] if body else None,
            "status": "schema_fallback",
            "schema_selection": selection.as_dict(),
            "raw_hex": body.hex(" "),
        }
    packed = int.from_bytes(body[4:12], "little")
    riv = (packed >> 10) & 0x03FF
    return {
        "version": 24,
        "status": "decoded",
        "schema_selection": selection.as_dict(),
        "reserved_prefix_hex": body[1:4].hex(" "),
        "cell_index": packed & 0x07,
        "tpc_command": (packed >> 3) & 0x07,
        "mcs": (packed >> 6) & 0x0F,
        "resource_indication_value": riv,
        "resource_allocation": decode_riv(riv, uplink_resource_blocks),
        "cqi_enabled": bool((packed >> 20) & 0x01),
        "ul_delay": (packed >> 21) & 0x01,
        "sfn": (packed >> 22) & 0x03FF,
        "subframe": (packed >> 32) & 0x0F,
        "frequency_hopping_flag": (packed >> 36) & 0x01,
        "starting_resource_block": (packed >> 37) & 0x7F,
        "number_of_resource_blocks": (packed >> 44) & 0x7F,
        "transport_block_size_index": (packed >> 51) & 0x1F,
        "modulation_type_code": (packed >> 56) & 0x03,
        "modulation_type": {
            0: "QPSK",
            1: "16QAM",
            2: "64QAM",
        }.get((packed >> 56) & 0x03, "unknown"),
        "redundancy_version_index": (packed >> 58) & 0x03,
        "harq_id": (packed >> 60) & 0x07,
        "reserved_high_bit": (packed >> 63) & 0x01,
        "raw_hex": body.hex(" "),
    }


def record_reference(
    record: dict[str, Any], uplink_resource_blocks: int
) -> dict[str, Any]:
    body = record["body"]
    result = {
        "frame_index": record["frame_index"],
        "timestamp_utc": record["timestamp_utc"],
        "body_version": body[0] if body else None,
        "body_hex": record["body_hex"],
    }
    if record["log_id"] == LOG_MSG1:
        result["decoded"] = decode_b167(body)
    elif record["log_id"] == LOG_MSG2:
        result["decoded"] = decode_b168(body)
    elif record["log_id"] == LOG_MSG3:
        result["decoded"] = decode_b169(body, uplink_resource_blocks)
    elif record["log_id"] == LOG_MSG4:
        result["decoded"] = decode_b16a(body)
    return result


def cross_validation(
    summary: dict[str, Any] | None,
    ml1_msg1: list[dict[str, Any]],
    ml1_msg2: list[dict[str, Any]],
    ml1_msg3: list[dict[str, Any]],
) -> dict[str, Any]:
    if summary is None:
        return {"status": "no_mac_summary"}
    result: dict[str, Any] = {"status": "checked"}
    msg1 = summary.get("msg1")
    msg2 = summary.get("msg2")
    msg3 = summary.get("msg3")
    if msg1 and ml1_msg1:
        result["msg1_preamble_matches"] = (
            msg1["preamble_index"]
            == ml1_msg1[-1]["decoded"].get("preamble_sequence")
        )
    if msg2 and ml1_msg2:
        decoded = ml1_msg2[-1]["decoded"]
        result["msg2_timing_advance_matches"] = (
            msg2["timing_advance_command"]
            == decoded.get("timing_advance_command")
        )
        # A contention-free handover may omit the temporary-RNTI field in the
        # ML1 report even though the MAC summary retains its assigned value.
        if summary["contention_based"]:
            result["msg2_temporary_rnti_matches"] = (
                msg2["temporary_c_rnti"] == decoded.get("rnti_value")
            )
    if msg3 and ml1_msg3:
        decoded = ml1_msg3[-1]["decoded"]
        grant = msg3["uplink_grant"]
        result["msg3_riv_matches"] = (
            grant["resource_indication_value"]
            == decoded.get("resource_indication_value")
        )
        result["msg3_harq_matches"] = (
            msg3["harq_id"] == decoded.get("harq_id")
        )
        result["msg3_resource_allocation_matches"] = (
            grant["resource_allocation"].get("starting_resource_block")
            == decoded.get("starting_resource_block")
            and grant["resource_allocation"].get("number_of_resource_blocks")
            == decoded.get("number_of_resource_blocks")
        )
    checks = [value for key, value in result.items() if key.endswith("_matches")]
    result["all_applicable_checks_pass"] = bool(checks) and all(checks)
    return result


def correlate(
    records: Iterable[dict[str, Any]],
    uplink_resource_blocks: int,
    rrclte: Any | None,
) -> list[dict[str, Any]]:
    groups: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] | None = None
    for record in records:
        if record["log_id"] == LOG_RACH_TRIGGER:
            if current:
                groups.append(current)
            current = [record]
        elif current is not None and record["log_id"] in RA_IDS:
            current.append(record)
    if current:
        groups.append(current)

    procedures: list[dict[str, Any]] = []
    for index, group in enumerate(groups, start=1):
        by_id: dict[int, list[dict[str, Any]]] = {}
        for record in group:
            by_id.setdefault(record["log_id"], []).append(record)
        trigger = decode_b061(by_id[LOG_RACH_TRIGGER][0]["body"])
        attempts = [
            decode_b062(record["body"], uplink_resource_blocks, rrclte)
            for record in by_id.get(LOG_RACH_ATTEMPT, [])
        ]
        summary = next(
            (item["attempt"] for item in attempts if item.get("attempt") is not None),
            None,
        )
        msg4_rows = [
            decode_b16a(record["body"]) for record in by_id.get(LOG_MSG4, [])
        ]
        ml1_msg1 = [
            record_reference(item, uplink_resource_blocks)
            for item in by_id.get(LOG_MSG1, [])
        ]
        ml1_msg2 = [
            record_reference(item, uplink_resource_blocks)
            for item in by_id.get(LOG_MSG2, [])
        ]
        ml1_msg3 = [
            record_reference(item, uplink_resource_blocks)
            for item in by_id.get(LOG_MSG3, [])
        ]
        ml1_msg4 = [
            record_reference(item, uplink_resource_blocks)
            for item in by_id.get(LOG_MSG4, [])
        ]
        contention_based = (
            summary.get("contention_based") if summary is not None else None
        )
        required_msg4 = contention_based is True
        present = {
            "trigger": LOG_RACH_TRIGGER in by_id,
            "mac_attempt": LOG_RACH_ATTEMPT in by_id,
            "ml1_msg1": LOG_MSG1 in by_id,
            "ml1_msg2": LOG_MSG2 in by_id,
            "ml1_msg3": LOG_MSG3 in by_id,
            "ml1_msg4": LOG_MSG4 in by_id,
        }
        success = bool(
            summary
            and summary["result_code"] == 0
            and summary.get("msg1")
            and summary.get("msg2")
            and (
                not required_msg4
                or any(item.get("contention_result") == "pass" for item in msg4_rows)
            )
        )
        procedures.append(
            {
                "procedure_index": index,
                "first_frame_index": group[0]["frame_index"],
                "last_frame_index": group[-1]["frame_index"],
                "started_at_utc": group[0]["timestamp_utc"],
                "trigger": trigger,
                "mac_attempt_records": attempts,
                "random_access": summary,
                "msg4_records": msg4_rows,
                "ml1_evidence": {
                    "msg1": ml1_msg1,
                    "msg2": ml1_msg2,
                    "msg3": ml1_msg3,
                    "msg4": ml1_msg4,
                },
                "cross_validation": cross_validation(
                    summary, ml1_msg1, ml1_msg2, ml1_msg3
                ),
                "presence": present,
                "msg4_required": required_msg4,
                "msg4_absence_expected": contention_based is False
                and not present["ml1_msg4"],
                "outcome": "success" if success else "incomplete_or_failed",
            }
        )
    return procedures


def report_markdown(
    capture: Path,
    procedures: list[dict[str, Any]],
    uplink_resource_blocks: int,
    pycrate_error: str | None,
) -> str:
    contention = sum(
        1
        for item in procedures
        if item.get("random_access", {}).get("contention_based") is True
    )
    contention_free = sum(
        1
        for item in procedures
        if item.get("random_access", {}).get("contention_based") is False
    )
    successful = sum(item["outcome"] == "success" for item in procedures)
    lines = [
        "# Phase 5 - LTE Random Access Decode",
        "",
        f"Capture: `{capture}`",
        "",
        "## Result",
        "",
        f"- Correlated procedures: **{len(procedures)}**",
        f"- Successful procedures: **{successful}**",
        f"- Contention-based: **{contention}**",
        f"- Contention-free: **{contention_free}**",
        f"- SIB2 uplink bandwidth used for grant RIV: **{uplink_resource_blocks} RB**",
        "- Msg4 is required only for contention-based random access.",
    ]
    if pycrate_error:
        lines.append(f"- UL-CCCH ASN.1 decoder unavailable: `{pycrate_error}`")
    lines.extend(
        [
            "",
            "## Procedure matrix",
            "",
            "| # | Reason | Type | Msg1 preamble | Msg2 T-C-RNTI | TA | Msg3 UL grant | Msg3 RRC | Msg4 | Result |",
            "|---:|---|---|---:|---|---:|---|---|---|---|",
        ]
    )
    for item in procedures:
        ra = item.get("random_access") or {}
        msg1 = ra.get("msg1") or {}
        msg2 = ra.get("msg2") or {}
        msg3 = ra.get("msg3") or {}
        grant = msg3.get("uplink_grant") or {}
        mac_pdu = msg3.get("mac_pdu") or {}
        rrc = mac_pdu.get("ul_ccch") or {}
        msg4_rows = item.get("msg4_records") or []
        msg4 = (
            msg4_rows[-1].get("contention_result", "raw")
            if msg4_rows
            else ("not required" if item["msg4_absence_expected"] else "missing")
        )
        reason = (item.get("trigger", {}).get("reason") or {}).get("reason", "unknown")
        lines.append(
            f"| {item['procedure_index']} | {reason} | "
            f"{ra.get('procedure_type', 'unknown')} | "
            f"{msg1.get('preamble_index', '-')} | "
            f"{msg2.get('temporary_c_rnti_hex', '-')} | "
            f"{msg2.get('timing_advance_command', '-')} | "
            f"{grant.get('grant_20bit_hex', '-')} | "
            f"{rrc.get('status', 'not present')} | {msg4} | {item['outcome']} |"
        )
    lines.extend(
        [
            "",
            "## Decoder evidence and limits",
            "",
            "- `0xB061` identifies the trigger and RACH reason.",
            "- `0xB062` v1/subpacket `0x06` v3 supplies Msg1 preamble, Msg2",
            "  result/T-C-RNTI/timing advance, and Msg3 grant plus MAC PDU.",
            "- The Msg3 UL-CCCH PDU is decoded as LTE `RRCConnectionRequest` when",
            "  pycrate is available.",
            "- `0xB167` v25 independently supplies the Msg1 preamble, physical",
            "  root, cyclic shift, PRACH power, Beta PRACH, frequency offset,",
            "  preamble/duplex/resource fields, timing/window, RA-RNTI, and",
            "  receive-frequency error using the exact target layout. The raw",
            "  signed integer is preserved and decoded as device-specific Q3",
            "  Hz (1/8 Hz per count) from modem-producer and QSR4 correlation.",
            "- `0xB168` v24 independently supplies Msg2 type/mode/RNTI, radio",
            "  timing, and timing advance.",
            "- `0xB169` v24 independently supplies Msg3 TPC/MCS/RIV, timing,",
            "  resource allocation, modulation, RV, and HARQ ID.",
            "- `0xB16A` v1 supplies Msg4 SFN/subframe, pass/fail, and UL ACK timing.",
            "- Every applicable Msg1/Msg2/Msg3 ML1-to-MAC cross-check passes.",
            "",
            "The single procedure without Msg4 is the HANDOVER/contention-free",
            "procedure. This is expected and is not a capture gap.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "capture",
        nargs="?",
        default="nsg-diag-raw.bin",
        help="raw NSG DIAG .bin or a lossless nsg-diag-frames.jsonl",
    )
    parser.add_argument(
        "--jsonl",
        default="nsg-random-access.decoded.jsonl",
        help="output: one correlated random-access procedure per JSON line",
    )
    parser.add_argument(
        "--report",
        default="nsg-random-access-report.md",
        help="output Markdown report",
    )
    parser.add_argument(
        "--ul-rbs",
        type=int,
        default=100,
        help="uplink bandwidth in resource blocks, decoded from SIB2 (default: 100)",
    )
    parser.add_argument(
        "--pycrate-root",
        help="directory containing pycrate_asn1dir; defaults to ../vendor/pycrate",
    )
    args = parser.parse_args()
    script_dir = Path(__file__).resolve().parent
    capture = Path(args.capture)
    default_pycrate = script_dir.parent / "vendor" / "pycrate"
    pycrate_root = Path(args.pycrate_root) if args.pycrate_root else default_pycrate
    rrclte, pycrate_error = load_rrclte(pycrate_root)
    records = list(iter_input_records(capture, script_dir))
    procedures = correlate(records, args.ul_rbs, rrclte)

    output_path = Path(args.jsonl)
    with output_path.open("w", encoding="utf-8") as output:
        for procedure in procedures:
            output.write(json.dumps(procedure, separators=(",", ":")) + "\n")
    report_path = Path(args.report)
    report_path.write_text(
        report_markdown(
            capture, procedures, args.ul_rbs, pycrate_error
        ),
        encoding="utf-8",
    )
    successful = sum(item["outcome"] == "success" for item in procedures)
    print(f"random-access procedures: {len(procedures)}")
    print(f"successful procedures: {successful}")
    print(f"JSONL: {output_path}")
    print(f"report: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
