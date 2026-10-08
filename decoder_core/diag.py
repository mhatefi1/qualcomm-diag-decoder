"""Strict Qualcomm routed-DIAG normalization, independent of phone models."""
from dataclasses import dataclass, field
from .capture import UnsupportedPacket


def uint(data, offset, size=1):
    require_range(data, offset, size)
    return int.from_bytes(data[offset:offset + size], "little")


def require_range(data, offset, length):
    if offset < 0 or length < 0 or offset + length > len(data):
        raise ValueError("declared field exceeds the bounded body")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def supported(condition, message):
    if not condition:
        raise UnsupportedPacket(message)


def crc16(data):
    crc = 0xffff
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0x8408 if crc & 1 else 0)
    return crc ^ 0xffff


@dataclass
class DiagRecord:
    body: bytes = b""
    metadata: dict = field(default_factory=dict)
    failure: Exception | None = None

    def __len__(self):
        return len(self.body) + 26


def routed_frames(payload, allowed_peripherals=None):
    """One SOCK_SEQPACKET payload per PXDG record; failures stay local to it."""
    record = DiagRecord()
    log_id = None
    try:
        require(14 <= len(payload) <= 100_000, "invalid-routed-packet-length")
        local_type, peripheral, size = (uint(payload, n, 4) for n in (0, 4, 8))
        record.metadata.update(wrapper="direct", router_peripheral=peripheral)
        supported(local_type == 32, "unsupported-local-type")
        if allowed_peripherals is not None:
            supported(peripheral in allowed_peripherals, "unsupported-router-peripheral")
        require(size == len(payload) - 12, "routed-encoded-length-mismatch")
        require(payload[-1] == 0x7e, "missing-final-delimiter")
        decoded = bytearray()
        cursor = 12
        while cursor < len(payload) - 1:
            value = payload[cursor]
            require(value != 0x7e, "early-delimiter")
            if value == 0x7d:
                cursor += 1
                require(cursor < len(payload) - 1, "dangling-escape")
                value = payload[cursor] ^ 0x20
            decoded.append(value)
            cursor += 1
        require(len(decoded) >= 3, "truncated-routed-checksum")
        require(uint(decoded, len(decoded) - 2, 2) == crc16(decoded[:-2]),
                "routed-checksum-mismatch")
        offset = 0
        if decoded[0] == 0x98:
            require(len(decoded) >= 27, "truncated-multi-radio-envelope")
            supported(decoded[1] == 1, "unsupported-multi-radio-version")
            require(uint(decoded, 2, 2) == 0, "nonzero-multi-radio-reserved")
            record.metadata.update(wrapper="multi-radio-v1", radio_id=uint(decoded, 4, 4))
            offset = 8
        supported(decoded[offset] == 0x10, "unsupported-diag-command")
        require(len(decoded) >= offset + 19, "truncated-diag-log-header")
        require(decoded[offset + 1] == 0, "nonzero-diag-log-reserved")
        packet_length, record_length = (uint(decoded, offset + n, 2) for n in (2, 4))
        require(packet_length == record_length, "diag-length-fields-disagree")
        require(record_length >= 13, "diag-record-missing-version")
        require(len(decoded) == offset + record_length + 6, "diag-record-boundary-mismatch")
        log_id = uint(decoded, offset + 6, 2)
        record.body = bytes(decoded[offset + 16:offset + 4 + record_length])
        record.metadata["record_version"] = record.body[0]
    except (ValueError, IndexError) as failure:
        record.failure = failure
    yield record, log_id, True
