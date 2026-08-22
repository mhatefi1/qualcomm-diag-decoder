#!/usr/bin/env python3
"""Decode LTE serving-cell and signaling records from nsg-diag-dump.js output.

The dump contains 0x0198 containers, each carrying HDLC-delimited Qualcomm
multi-radio log packets.  It decodes the 0xB17F LTE ML1 Serving Cell
Measurement/Evaluation record, the B193 version-39 serving-cell measurement
record found on the captured modem, and the version-20 B0C0 LTE RRC OTA header
plus its exact ASN.1 payload bytes.
"""

from __future__ import annotations

import argparse
import json
import struct
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .nsg_schema_registry import probe_record
from .nsg_rrc import decode_rrc


CONTAINER = 0x20
MULTI_RADIO = b"\x98\x01\x00\x00"
LOG_B17F = 0xB17F
LOG_B193 = 0xB193
RRC_IDS = {0xB0C0, 0xB0C1, 0xB0C2, 0xB0CD}
# LTE ML1 measurement records are kept separate from the RRC/NAS protocol
# dump.  Their layouts are Qualcomm/firmware specific, but retaining the
# complete bodies lets us compare them with external parsers (for example
# SCAT) before assigning field offsets such as SINR.
MEASUREMENT_IDS = {
    0xB179, 0xB17F, 0xB180, 0xB181, 0xB192, 0xB193, 0xB194,
    0xB195, 0xB196, 0xB197,
}
# Qualcomm/SCAT uses these IDs for LTE ESM/EMM and state records. B0E5 is the
# ESM bearer-context record; it is present here even though it is not an OTA
# NAS PDU.
NAS_IDS = {0xB0E0, 0xB0E1, 0xB0E2, 0xB0E3, 0xB0E5, 0xB0EA, 0xB0EB, 0xB0EC, 0xB0ED, 0xB0EE}
RANDOM_ACCESS_IDS = {
    0xB061,  # LTE MAC RACH Trigger
    0xB062,  # LTE MAC RACH Attempt
    0xB167,  # LTE ML1 Random Access Request (Msg1)
    0xB168,  # LTE ML1 Random Access Response (Msg2)
    0xB169,  # LTE ML1 UE Identification (Msg3)
    0xB16A,  # LTE ML1 Contention Resolution (Msg4)
}

PROTOCOL_NAMES = {
    0xB0C0: "LTE RRC OTA packet",
    0xB0C1: "LTE RRC MIB message",
    0xB0C2: "LTE RRC serving-cell information",
    0xB0CD: "LTE RRC supported CA combinations",
    0xB0E0: "LTE NAS ESM security-protected incoming",
    0xB0E1: "LTE NAS ESM security-protected outgoing",
    0xB0E2: "LTE NAS ESM plain incoming",
    0xB0E3: "LTE NAS ESM plain outgoing",
    0xB0E5: "LTE NAS ESM bearer-context information",
    0xB0EA: "LTE NAS EMM security-protected incoming",
    0xB0EB: "LTE NAS EMM security-protected outgoing",
    0xB0EC: "LTE NAS EMM plain incoming",
    0xB0ED: "LTE NAS EMM plain outgoing",
    0xB0EE: "LTE NAS EMM state",
    0xB061: "LTE MAC RACH trigger",
    0xB062: "LTE MAC RACH attempt",
    0xB167: "LTE ML1 random-access request (Msg1)",
    0xB168: "LTE ML1 random-access response (Msg2)",
    0xB169: "LTE ML1 UE identification (Msg3)",
    0xB16A: "LTE ML1 contention resolution (Msg4)",
}

# Names are limited to records identified by this project. Unknown IDs are
# still printed by --inventory for later mapping to RRC/NAS or other layers.
LOG_NAMES = {
    0xB17F: "LTE ML1 serving-cell measurement/evaluation",
    0xB193: "LTE serving-cell measurement response (newer format)",
    0xB179: "LTE ML1 connected-mode intra-frequency measurement",
    0xB180: "LTE ML1 neighbor measurement",
    0xB181: "LTE ML1 intra-frequency cell reselection",
    0xB192: "LTE ML1 neighbor-cell measurement request/response",
    0xB194: "LTE ML1 search request/response",
    0xB195: "LTE ML1 connected-mode neighbor measurement request/response",
    0xB196: "LTE cell measurement result",
    0xB197: "LTE serving-cell information",
    0xB0C0: "LTE RRC signaling",
    0xB0C1: "LTE RRC MIB message",
    0xB0C2: "LTE RRC serving-cell information",
    0xB0CD: "LTE RRC supported CA combinations",
    0xB0E0: "LTE NAS ESM security-protected incoming",
    0xB0E1: "LTE NAS ESM security-protected outgoing",
    0xB0E2: "LTE NAS ESM signaling",
    0xB0E3: "LTE NAS ESM signaling",
    0xB0E5: "LTE NAS ESM bearer-context information",
    0xB0EA: "LTE NAS EMM security-protected incoming",
    0xB0EB: "LTE NAS EMM security-protected outgoing",
    0xB0EC: "LTE NAS EMM signaling",
    0xB0ED: "LTE NAS EMM signaling",
    0xB0EE: "LTE NAS EMM state",
}


def u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def i32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little", signed=True)


def u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def unescape(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 0x7D and i + 1 < len(data):
            out.append(data[i + 1] ^ 0x20)
            i += 2
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


def chunks_from_dump(data: bytes):
    """Yield payload chunks from concatenated outer 0x20 wrappers."""
    offset = 0
    while offset + 12 <= len(data):
        if u32(data, offset) != CONTAINER:
            offset += 1
            continue
        count = u32(data, offset + 4)
        pos = offset + 8
        chunks = []
        valid = True
        for _ in range(count):
            if pos + 4 > len(data):
                valid = False
                break
            length = u32(data, pos)
            pos += 4
            if pos + length > len(data):
                valid = False
                break
            chunks.append(data[pos : pos + length])
            pos += length
        if valid:
            yield from chunks
            offset = pos
        else:
            offset += 1


def valid_diag_log_frame(frame: bytes) -> bool:
    """Return True only for a complete Qualcomm DIAG log frame.

    The multi-radio marker also occurs inside unrelated traffic, so the DIAG
    header and its little-endian length field must agree before decoding.
    """
    return (
        len(frame) >= 26
        and frame.startswith(MULTI_RADIO)
        and frame[8:10] == b"\x10\x00"
        and frame[10:12] == frame[12:14]
        and int.from_bytes(frame[10:12], "little") == len(frame) - 14
    )


def log_frames(data: bytes, strict: bool = True):
    """Yield unescaped Qualcomm frames and their 16-bit log id.

    With ``strict=True`` (the default), marker matches that are not complete
    DIAG log records are excluded. ``strict=False`` is useful for diagnostics
    and inventory accounting of rejected candidates.
    """
    for chunk in chunks_from_dump(data):
        search = 0
        while True:
            start = chunk.find(MULTI_RADIO, search)
            if start < 0:
                break
            end = chunk.find(b"\x7E", start + 4)
            if end < 0:
                break
            frame = unescape(chunk[start:end])
            search = start + 4
            if len(frame) >= 26 and frame.startswith(MULTI_RADIO):
                if strict and not valid_diag_log_frame(frame):
                    continue
                yield frame, int.from_bytes(frame[14:16], "little")


def decode_b17f(frame: bytes):
    # 8-byte multi-radio header + 16-byte DIAG log header + body + 2-byte CRC.
    body = frame[24:-2]
    selection = probe_record(LOG_B17F, body)
    if not selection.selected:
        return None
    rrc_rel, _reserved, earfcn, pci_prio, measured, average, rsrq, rssi, _rxlev, _search = struct.unpack(
        "<BHLH2xLLLLLL", body[1:36]
    )
    pci = pci_prio & 0x1FF
    to_rsrp = lambda value: -180.0 + (value & 0xFFF) * 0.0625
    to_rsrq = lambda value: -30.0 + (value & 0x3FF) * 0.0625
    to_rssi = lambda value: -110.0 + ((value >> 10) & 0x7FF) * 0.0625
    return {
        "schema_selection": selection.as_dict(),
        "rrc": rrc_rel,
        "earfcn": earfcn,
        "pci": pci,
        "rsrp": to_rsrp(measured),
        "avg_rsrp": to_rsrp(average),
        "rsrq": to_rsrq(rsrq),
        "rssi": to_rssi(rssi),
    }


def decode_b193_header(frame: bytes):
    """Decode the common outer header of B193."""
    body = frame[24:-2]
    if len(body) < 24 or body[0] != 1 or body[1] != 1:
        return None
    sub_id, sub_version, sub_size = body[4], body[5], int.from_bytes(body[6:8], "little")
    if sub_id != 0x19 or len(body) < 20:
        return None
    earfcn, cells, valid_rx, _rx_map = struct.unpack("<LHHL", body[8:20])
    first_cell = body[20:]
    pci = None
    is_serving = None
    if len(first_cell) >= 2:
        val0 = int.from_bytes(first_cell[:2], "little")
        pci = val0 & 0x1FF
        is_serving = (val0 >> 12) & 1
    return {
        "packet_version": body[0],
        "version": sub_version,
        "size": sub_size,
        "earfcn": earfcn,
        "cells": cells,
        "valid_rx": valid_rx,
        "pci": pci,
        "is_serving": is_serving,
    }


def decode_b193_v39(frame: bytes):
    """Decode the B193 subpacket 0x19 version 39 found in this capture.

    Qualcomm changed the B193 cell layout between modem generations.  The
    public SCAT parser has layouts for v36 and v48/50, but not this v39 layout,
    so applying either neighbouring layout would shift every field.  The v39
    outer header and the first serving-cell fields are unambiguous in the
    capture.  The RSRP/RSRQ/RSSI offsets below are additionally cross-checked
    against the same-timestamp B17F record.  The exact v39 switch branch and
    conversion routine in this device's libqtrun_arch_jni.so confirm the
    FTL/RS-SNR and Projected-SIR engineering-unit conversions below.
    """
    body = frame[24:-2] if len(frame) >= 26 else b""
    selection = probe_record(LOG_B193, body)
    if not selection.selected or len(body) < 20 or body[1] != 1:
        return None
    sub_id = body[4]
    sub_version = body[5]
    sub_size = u16(body, 6)
    if sub_id != 0x19 or sub_version != 39 or sub_size < 12:
        return None

    earfcn, num_cells, valid_rx, rx_map = struct.unpack("<LHHL", body[8:20])
    # The B193 subpacket size includes its four-byte id/version/size header.
    declared_end = 4 + sub_size
    available_end = min(len(body), declared_end)
    # After that header, the v39 outer fields occupy 12 bytes.
    cell_bytes = max(0, sub_size - 16)
    cells = []
    # This firmware reserves four fixed 140-byte cell slots. num_cells says
    # how many leading slots are populated; the rest are zero padding.
    cell_size = 140 if cell_bytes >= num_cells * 140 else 0
    allocated_cell_slots = cell_bytes // 140 if cell_bytes % 140 == 0 else 0
    for index in range(num_cells if cell_size else 0):
        start = 20 + index * cell_size if cell_size else 20
        end = start + cell_size if cell_size else available_end
        cell = body[start:min(end, available_end)]
        if not cell:
            break
        value0 = u16(cell, 0) if len(cell) >= 2 else None
        packed_time = u16(cell, 4) if len(cell) >= 6 else None
        item = {
            "index": index,
            "offset": start,
            "length": len(cell),
            "physical_cell_id": value0 & 0x1FF if value0 is not None else None,
            "serving_cell_index": (value0 >> 9) & 0x7 if value0 is not None else None,
            "is_serving_cell": bool((value0 >> 12) & 1) if value0 is not None else None,
            "sfn": (packed_time >> 4) & 0x3FF if packed_time is not None else None,
            "subframe": packed_time & 0xF if packed_time is not None else None,
            "cell_hex": cell.hex(" "),
        }

        # These three 16-bit values use the usual LTE ML1 quantization.  The
        # offsets are relative to the beginning of the v39 cell, not the log.
        # They matched the adjacent B17F record for 61/66, 62/66 and 59/66
        # paired samples respectively (minor differences are expected because
        # the two logs are generated on adjacent modem ticks).
        if len(cell) >= 62:
            rsrp_raw = u16(cell, 36) & 0x0FFF
            rsrq_raw = u16(cell, 48) & 0x03FF
            rssi_raw = u16(cell, 60) & 0x07FF
            item.update(
                {
                    "instantaneous_rsrp_raw": rsrp_raw,
                    "instantaneous_rsrp_dbm": -180.0 + rsrp_raw * 0.0625,
                    "instantaneous_rsrq_raw": rsrq_raw,
                    "instantaneous_rsrq_db": -30.0 + rsrq_raw * 0.0625,
                    "instantaneous_rssi_raw": rssi_raw,
                    "instantaneous_rssi_dbm": -110.0 + rssi_raw * 0.0625,
                }
            )
        if len(cell) >= 122:
            # Native NSG metadata calls this field Post Ic Rsrq.  It is kept
            # separately because it can differ from instantaneous RSRQ on
            # another firmware, even though it matches in this capture.
            post_ic_rsrq_raw = u16(cell, 120) & 0x03FF
            item.update(
                {
                    "post_ic_rsrq_raw": post_ic_rsrq_raw,
                    "post_ic_rsrq_db": -30.0 + post_ic_rsrq_raw * 0.0625,
                }
            )
        if len(cell) >= 140:
            # Each pair of FTL/RS SNR values occupies the low 18 bits of a
            # 32-bit word: two unsigned 9-bit values followed by 14 padding
            # bits. The target native v39 routine converts each as
            # raw / 10 - 20 dB. Projected SIR is signed Q4 (raw / 16 dB).
            def snr_pair(offset: int) -> list[int]:
                packed = u32(cell, offset)
                return [packed & 0x1FF, (packed >> 9) & 0x1FF]

            ftl_snr_raw = snr_pair(84) + snr_pair(88)
            rs_snr_raw = snr_pair(100) + snr_pair(104)
            projected_sir_raw = i32(cell, 116)
            cinr_raw = [i32(cell, off) for off in (124, 128, 132, 136)]
            cinr_db = [value / 256.0 for value in cinr_raw]
            valid_rx_indexes = [
                rx_index for rx_index in range(4) if valid_rx & (1 << rx_index)
            ]
            valid_cinr_db = [cinr_db[rx_index] for rx_index in valid_rx_indexes]
            item.update(
                {
                    "ftl_snr_raw": ftl_snr_raw,
                    "ftl_snr_db": [
                        round(value / 10.0 - 20.0, 1) for value in ftl_snr_raw
                    ],
                    "rs_snr_raw": rs_snr_raw,
                    "rs_snr_db": [
                        round(value / 10.0 - 20.0, 1) for value in rs_snr_raw
                    ],
                    "projected_sir_raw": projected_sir_raw,
                    "projected_sir_db": projected_sir_raw / 16.0,
                    "cinr_raw": cinr_raw,
                    "cinr_db": cinr_db,
                    "cinr_unit": "signed Q8 dB (raw / 256)",
                    "valid_rx_indexes": valid_rx_indexes,
                }
            )
            item["native_named_raw_candidates"] = {
                "ftl_snr_packed_words": [u32(cell, off) for off in (84, 88)],
                "ftl_padding_words": [u32(cell, off) for off in (92, 96)],
                "rs_snr_packed_words": [u32(cell, off) for off in (100, 104)],
                "rs_padding_words": [u32(cell, off) for off in (108, 112)],
                "projected_sir_word": projected_sir_raw,
                "post_ic_rsrq_word": u32(cell, 120),
                "cinr_words": cinr_raw,
                "scale_status": (
                    "FTL/RS SNR and Projected SIR decoded with the target "
                    "native v39 routine; CINR Q8 and serving SINR aggregation "
                    "validated against synchronized NSG screenshots"
                ),
            }
            item["sinr_db"] = max(valid_cinr_db) if valid_cinr_db else None
            item["sinr_status"] = (
                "maximum CINR across valid receivers; signed Q8 conversion and "
                "aggregation validated against five synchronized NSG values"
            )
        cells.append(item)

    return {
        "schema_selection": selection.as_dict(),
        "packet_version": body[0],
        "subpacket_id": sub_id,
        "subpacket_version": sub_version,
        "subpacket_size": sub_size,
        "earfcn": earfcn,
        "num_cells": num_cells,
        "valid_rx": valid_rx,
        "logical_to_physical_rx_map": rx_map,
        "cell_size": cell_size,
        "allocated_cell_slots": allocated_cell_slots,
        "unused_cell_padding_bytes": max(0, cell_bytes - num_cells * cell_size),
        "cell_layout_ok": bool(cell_size),
        "declared_end": declared_end,
        "available_bytes": max(0, available_end - 20),
        "length_ok": declared_end <= len(body),
        "cells": cells,
        "decode_status": (
            "B193 subpacket v39 outer header, cell identity/timing, and "
            "RSRP/RSRQ/RSSI, FTL/RS SNR, Projected SIR, CINR and SINR decoded"
        ),
    }


def decode_b0c0_rrc(frame: bytes):
    """Decode the stable Qualcomm LTE RRC OTA header and expose its PDU.

    B0C0 records in this capture use the Qualcomm v20 layout.  The first
    nineteen bytes of the record body carry version/release, cell and timing
    metadata, SIB mask, and a little-endian message length; the RRC ASN.1
    message immediately follows.  We validate the declared length before
    returning it and preserve any unexpected trailing bytes.
    """
    body = frame[24:-2] if len(frame) >= 26 else b""
    selection = probe_record(0xB0C0, body)
    if not selection.selected:
        return None
    version = body[0]
    release_major = body[1]
    release_minor_raw = body[2]
    msg_len = u16(body, 17)
    available = len(body) - 19
    payload = body[19 : 19 + msg_len]
    trailing = body[19 + msg_len :]
    packed_sfn_subframe = u16(body, 10)
    transport_names = {
        1: "BCCH-BCH",
        2: "BCCH-DL-SCH",
        4: "MCCH",
        5: "PCCH",
        6: "DL-CCCH",
        7: "DL-DCCH",
        8: "UL-CCCH",
        9: "UL-DCCH",
        54: "BCCH-BCH-NB",
        55: "BCCH-DL-SCH-NB",
        56: "PCCH-NB",
        57: "DL-CCCH-NB",
        58: "DL-DCCH-NB",
        59: "UL-CCCH-NB",
        61: "UL-DCCH-NB",
    }
    return {
        "schema_selection": selection.as_dict(),
        "header_len": 19,
        "header_profile": "qualcomm-log-lte-rrc-ota-v20",
        "packet_version": version,
        "rrc_release": (
            f"{release_major}.{release_minor_raw >> 4}."
            f"{release_minor_raw & 0x0F}"
        ),
        "rrc_release_major_raw": release_major,
        "rrc_release_minor_raw": release_minor_raw,
        "radio_bearer_id": body[3],
        "physical_cell_id": u16(body, 4),
        "earfcn": u32(body, 6),
        "sfn_subframe_packed": packed_sfn_subframe,
        "sfn": (packed_sfn_subframe >> 4) & 0x03FF,
        "subframe": packed_sfn_subframe & 0x0F,
        "pdu_number": body[12],
        "rrc_transport": transport_names.get(body[12], "unknown RRC transport"),
        "sib_mask": u32(body, 13),
        "message_length": msg_len,
        "payload_offset": 19,
        "payload_len_available": available,
        "payload_hex": payload.hex(" "),
        "rrc": decode_rrc(body[12], payload),
        "trailing_hex": trailing.hex(" "),
        "length_ok": msg_len <= available,
        "length_exact": msg_len == available,
    }


def qxdm_timestamp(timestamp: bytes) -> str | None:
    """Convert the eight-octet Qualcomm timestamp to an ISO-8601 UTC value."""
    try:
        raw = int.from_bytes(timestamp, "little")
        value = datetime(1980, 1, 6, tzinfo=timezone.utc) + timedelta(
            seconds=raw / 52_428_800.0
        )
        return value.isoformat(timespec="microseconds")
    except (ValueError, OverflowError):
        return None


def extract_protocol_record(frame: bytes, log_id: int, frame_index: int | None = None):
    """Extract a lossless record for later RRC/NAS decoding.

    The bytes after the Qualcomm DIAG log header are retained verbatim.  The
    outer DIAG and multi-radio headers are included as hex too, so a future
    version-specific decoder can be applied without re-capturing the phone.
    B0C0 has a validated 19-byte Qualcomm header in this capture, so its exact
    ASN.1 payload is also split out.  Other RRC/NAS IDs remain raw because
    their layouts vary with modem firmware and an incorrect offset would
    corrupt payloads.
    """
    body = frame[24:-2] if len(frame) >= 26 else b""
    if log_id in RRC_IDS:
        protocol = "RRC"
    elif log_id in NAS_IDS:
        protocol = "NAS/EMM/ESM"
    elif log_id in MEASUREMENT_IDS:
        protocol = "LTE/ML1"
    else:
        protocol = "unknown"
    record = {
        "frame_index": frame_index,
        "log_id": f"0x{log_id:04X}",
        "protocol": protocol,
        "name": PROTOCOL_NAMES.get(log_id, LOG_NAMES.get(log_id, "unclassified")),
        "frame_len": len(frame),
        "timestamp_header_hex": frame[16:24].hex(" "),
        "timestamp_utc": qxdm_timestamp(frame[16:24]),
        "diag_header_hex": frame[8:24].hex(" "),
        "body_offset": 24,
        "body_len": len(body),
        "body_hex": body.hex(" "),
        "decode_status": "raw body extracted; version-specific ASN.1/NAS PDU decode pending",
    }
    selection = probe_record(log_id, body)
    record["schema_selection"] = selection.as_dict()
    if log_id == 0xB0C0:
        rrc = decode_b0c0_rrc(frame)
        if rrc is not None:
            record["rrc_header"] = rrc
            if rrc["length_ok"]:
                record["decode_status"] = (
                    "Qualcomm LTE RRC header decoded; ASN.1 payload extracted "
                    "(message-name decode pending)"
                )
            else:
                record["decode_status"] = (
                    "Qualcomm LTE RRC header decoded, but declared payload "
                    "length exceeds available bytes"
                )
    elif log_id == LOG_B193:
        b193_v39 = decode_b193_v39(frame)
        if b193_v39 is not None:
            record["b193_v39"] = b193_v39
            record["decode_status"] = b193_v39["decode_status"]
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dump", nargs="?", default="nsg-diag-raw.bin")
    parser.add_argument(
        "--inventory",
        action="store_true",
        help="print every inner Qualcomm log ID and its occurrence count",
    )
    parser.add_argument(
        "--protocol-dump",
        metavar="PATH",
        help="write lossless LTE RRC/NAS records as JSON Lines",
    )
    parser.add_argument(
        "--measurement-dump",
        metavar="PATH",
        help="write lossless LTE ML1 measurement records as JSON Lines",
    )
    parser.add_argument(
        "--frame-dump",
        metavar="PATH",
        help="write every strict-valid DIAG frame, including full frame_hex, as JSON Lines",
    )
    args = parser.parse_args()
    data = Path(args.dump).read_bytes()

    counts = Counter()
    b17f = []
    b193 = []
    b193_v39_cells = 0
    protocol_records = []
    measurement_records = []
    frame_dump = Path(args.frame_dump).open("w", encoding="utf-8") if args.frame_dump else None
    frame_index = 0
    for frame, log_id in log_frames(data):
        if frame_dump is not None:
            frame_dump.write(json.dumps({
                "frame_index": frame_index,
                "log_id": f"0x{log_id:04X}",
                "frame_len": len(frame),
                "diag_length": int.from_bytes(frame[10:12], "little"),
                "timestamp_header_hex": frame[16:24].hex(" "),
                "diag_header_hex": frame[8:24].hex(" "),
                "body_offset": 24,
                "body_len": len(frame[24:-2]),
                "body_hex": frame[24:-2].hex(" "),
                "frame_hex": frame.hex(" "),
            }, separators=(",", ":")) + "\n")
        current_frame_index = frame_index
        frame_index += 1
        counts[log_id] += 1
        if log_id in RRC_IDS or log_id in NAS_IDS:
            protocol_records.append(
                extract_protocol_record(frame, log_id, current_frame_index)
            )
        if log_id in MEASUREMENT_IDS:
            measurement_records.append(
                extract_protocol_record(frame, log_id, current_frame_index)
            )
        if log_id == LOG_B17F:
            decoded = decode_b17f(frame)
            if decoded is not None:
                b17f.append(decoded)
        elif log_id == LOG_B193:
            decoded = decode_b193_header(frame)
            if decoded is not None:
                b193.append(decoded)
            decoded_v39 = decode_b193_v39(frame)
            if decoded_v39 is not None:
                b193_v39_cells += len(decoded_v39["cells"])
    if frame_dump is not None:
        frame_dump.close()
        print(f"strict frame dump: {Path(args.frame_dump)}")

    print(f"inner Qualcomm frames: {sum(counts.values())}")
    print(f"0xB17F decoded records: {len(b17f)}")
    print(f"0xB193 decoded headers: {len(b193)}")
    print(f"0xB193 v39 decoded cells: {b193_v39_cells}")
    rrc_count = sum(counts[log_id] for log_id in RRC_IDS)
    nas_count = sum(counts[log_id] for log_id in NAS_IDS)
    print(f"LTE RRC records: {rrc_count}")
    print(f"LTE NAS/EMM/ESM records: {nas_count}")
    print(f"LTE ML1 measurement records: {len(measurement_records)}")
    print(
        "LTE B0C0 RRC headers/payloads decoded: "
        f"{sum(1 for record in protocol_records if record.get('rrc_header'))}"
    )
    if args.protocol_dump:
        protocol_path = Path(args.protocol_dump)
        with protocol_path.open("w", encoding="utf-8") as output:
            for record in protocol_records:
                output.write(json.dumps(record, separators=(",", ":")) + "\n")
        print(f"LTE RRC/NAS records extracted: {len(protocol_records)}")
        print(f"protocol dump: {protocol_path}")
    if args.measurement_dump:
        measurement_path = Path(args.measurement_dump)
        with measurement_path.open("w", encoding="utf-8") as output:
            for record in measurement_records:
                output.write(json.dumps(record, separators=(",", ":")) + "\n")
        print(f"LTE ML1 measurement records extracted: {len(measurement_records)}")
        print(f"measurement dump: {measurement_path}")
    if args.inventory:
        print("\nQualcomm log-ID inventory:")
        print("log_id  count  description")
        for log_id, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
            description = LOG_NAMES.get(log_id, "unclassified")
            print(f"0x{log_id:04X} {count:6d}  {description}")

    print("\nB17F serving-cell samples:")
    print("EARFCN  PCI  RSRP(dBm)  RSRQ(dB)  RSSI(dBm)")
    for item in b17f[:20]:
        print(
            f"{item['earfcn']:6d} {item['pci']:4d} "
            f"{item['rsrp']:9.2f} {item['rsrq']:8.2f} {item['rssi']:9.2f}"
        )
    if b193:
        print("\nB193 header summary (newer subpacket version):")
        versions = Counter(item["version"] for item in b193)
        earfcns = Counter(item["earfcn"] for item in b193)
        pcis = Counter(item["pci"] for item in b193)
        print("versions:", dict(versions))
        print("EARFCNs:", dict(earfcns))
        print("PCIs:", dict(pcis))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
