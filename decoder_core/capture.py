"""Model-independent PXDG/raw capture reading and JSON/privacy utilities."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

STREAM_HEADER = struct.Struct("<4sHHII")
RECORD_HEADER = struct.Struct("<IIQ")
MAX_PXDG_PAYLOAD = 65_536
RAW_READ_SIZE = 1024 * 1024
MAX_RAW_CHUNKS = 4096
MAX_RAW_CHUNK_SIZE = 1024 * 1024
class CaptureFormatError(ValueError):
    pass


class UnsupportedPacket(ValueError):
    pass


@dataclass(frozen=True)
class CaptureChunk:
    timestamp_nanos: int
    payload: bytes
    processed_bytes: int


def iter_capture(path: Path) -> tuple[str, int, Iterator[CaptureChunk]]:
    total_bytes = path.stat().st_size
    with path.open("rb") as source:
        magic = source.read(4)
    if magic == b"PXDG":
        return "PXDG_V1", total_bytes, iter_pxdg(path)
    return "QUALCOMM_DIAG_RAW", total_bytes, iter_raw(path)


def iter_pxdg(path: Path) -> Iterator[CaptureChunk]:
    with path.open("rb") as source:
        header = source.read(STREAM_HEADER.size)
        if len(header) != STREAM_HEADER.size:
            raise CaptureFormatError("capture is shorter than the PXDG stream header")
        magic, version, header_size, _flags, _reserved = STREAM_HEADER.unpack(header)
        if magic != b"PXDG" or version != 1 or header_size != STREAM_HEADER.size:
            raise CaptureFormatError(
                f"unsupported PXDG header magic={magic!r} version={version} "
                f"size={header_size}"
            )
        previous_timestamp = -1
        record_index = 0
        while True:
            record_header = source.read(RECORD_HEADER.size)
            if not record_header:
                return
            if len(record_header) != RECORD_HEADER.size:
                raise CaptureFormatError(
                    f"truncated PXDG record header at record {record_index}"
                )
            length, _flags, timestamp = RECORD_HEADER.unpack(record_header)
            if length > MAX_PXDG_PAYLOAD:
                raise CaptureFormatError(
                    f"PXDG record {record_index} exceeds {MAX_PXDG_PAYLOAD} bytes"
                )
            if timestamp < previous_timestamp:
                raise CaptureFormatError(
                    f"PXDG timestamps are not monotonic at record {record_index}"
                )
            payload = source.read(length)
            if len(payload) != length:
                raise CaptureFormatError(
                    f"truncated PXDG payload at record {record_index}: "
                    f"need {length}, have {len(payload)}"
                )
            yield CaptureChunk(timestamp, payload, source.tell())
            previous_timestamp = timestamp
            record_index += 1


def iter_raw(path: Path) -> Iterator[CaptureChunk]:
    """Stream complete Qualcomm 0x20 containers without loading the file."""
    pending = bytearray()
    consumed = 0
    with path.open("rb") as source:
        eof = False
        while not eof:
            block = source.read(RAW_READ_SIZE)
            eof = not block
            pending.extend(block)
            offset = 0
            while offset + 8 <= len(pending):
                if _u32(pending, offset) != 0x20:
                    offset += 1
                    continue
                count = _u32(pending, offset + 4)
                if count > MAX_RAW_CHUNKS:
                    offset += 1
                    continue
                position = offset + 8
                incomplete = False
                invalid = False
                for _ in range(count):
                    if position + 4 > len(pending):
                        incomplete = True
                        break
                    length = _u32(pending, position)
                    position += 4
                    if length > MAX_RAW_CHUNK_SIZE:
                        invalid = True
                        break
                    if position + length > len(pending):
                        incomplete = True
                        break
                    position += length
                if invalid:
                    offset += 1
                    continue
                if incomplete:
                    break
                yield CaptureChunk(
                    0,
                    bytes(pending[offset:position]),
                    consumed + position,
                )
                offset = position
            if offset:
                del pending[:offset]
                consumed += offset
            if eof:
                return


def _u32(data: bytes | bytearray, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(key): json_safe(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(child) for child in value]
    return value


SENSITIVE_TOKENS = {
    "imsi", "imei", "imeisv", "msisdn", "supi", "suci", "guti", "tmsi",
    "mtmsi", "stmsi", "subscriberidentity", "mobileidentity", "knasenc",
    "knasint", "kasme", "kamf", "securitykey", "authkey",
    "authenticationresponse", "rand", "autn", "sqnxak", "sres", "mac",
    "dedicatedinfonas", "ueidentity", "pagingrecord",
}


def redact(value: Any, key: str = "", depth: int = 0) -> Any:
    normalized = "".join(character for character in key.lower() if character.isalnum())
    if normalized in {"digit1", "digits"} or any(
        token in normalized for token in SENSITIVE_TOKENS
    ):
        return "<redacted>"
    if normalized.endswith("hex") or "payloadhex" in normalized or "ciphertext" in normalized:
        if isinstance(value, str):
            compact = "".join(character for character in value if character in "0123456789abcdefABCDEF")
            return f"<binary {(len(compact) + 1) // 2} bytes omitted>"
        return "<binary content omitted>"
    if depth >= 12:
        return value
    if isinstance(value, dict):
        return {child_key: redact(child, str(child_key), depth + 1) for child_key, child in value.items()}
    if isinstance(value, list):
        return [redact(child, "", depth + 1) for child in value]
    if isinstance(value, bytes):
        return f"<binary {len(value)} bytes omitted>"
    return value
