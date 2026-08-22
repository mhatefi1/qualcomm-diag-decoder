#!/usr/bin/env python3
"""Reusable LTE EPS NAS security primitives and protected-PDU processing.

This module intentionally has no dependency on the NSG capture format, UI,
Android, or project state.  It implements the byte-aligned EPS NAS use of:

* 128-EEA2: AES-128 in CTR mode (3GPP TS 33.401, Annex B.1)
* 128-EIA2: AES-128 CMAC, truncated to 32 bits (Annex B.2)

The caller must supply the already-derived K_NASenc/K_NASint keys and the full
32-bit NAS COUNT.  Keys are never serialized by result objects.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


Direction = Literal[0, 1]


def _validate_common(key: bytes, count: int, bearer: int, direction: int) -> None:
    if len(key) != 16:
        raise ValueError("LTE EEA2/EIA2 keys must be exactly 16 bytes")
    if not 0 <= count <= 0xFFFFFFFF:
        raise ValueError("COUNT must be an unsigned 32-bit integer")
    if not 0 <= bearer <= 0x1F:
        raise ValueError("BEARER must be a 5-bit integer")
    if direction not in (0, 1):
        raise ValueError("DIRECTION must be 0 (uplink) or 1 (downlink)")


def _prefix(count: int, bearer: int, direction: int) -> bytes:
    """Return COUNT || BEARER || DIRECTION || 26 zero bits."""
    return count.to_bytes(4, "big") + bytes([(bearer << 3) | (direction << 2)]) + b"\0" * 3


def _validate_bit_length(data: bytes, bit_length: int | None) -> int:
    length = len(data) * 8 if bit_length is None else bit_length
    if not 0 <= length <= len(data) * 8:
        raise ValueError("bit_length is outside the supplied byte buffer")
    return length


def eea2_crypt(
    key: bytes,
    count: int,
    bearer: int,
    direction: Direction,
    data: bytes,
    *,
    bit_length: int | None = None,
) -> bytes:
    """Encrypt or decrypt an LTE bit string with 128-EEA2.

    AES-CTR is symmetric.  Valid bits occupy the most-significant bits of the
    final octet.  Any unused low-order bits in the returned final octet are
    cleared, matching the representation used by 3GPP test vectors.
    """
    _validate_common(key, count, bearer, direction)
    length = _validate_bit_length(data, bit_length)
    used_bytes = (length + 7) // 8
    if used_bytes == 0:
        return b""
    counter = _prefix(count, bearer, direction) + b"\0" * 8
    encryptor = Cipher(algorithms.AES(key), modes.CTR(counter)).encryptor()
    result = bytearray(encryptor.update(data[:used_bytes]) + encryptor.finalize())
    remainder = length % 8
    if remainder:
        result[-1] &= (0xFF << (8 - remainder)) & 0xFF
    return bytes(result)


def eia2_mac(
    key: bytes,
    count: int,
    bearer: int,
    direction: Direction,
    message: bytes,
    *,
    bit_length: int | None = None,
) -> bytes:
    """Calculate the four-octet 128-EIA2 MAC-I for a byte-aligned message."""
    _validate_common(key, count, bearer, direction)
    length = _validate_bit_length(message, bit_length)
    if length % 8:
        raise ValueError(
            "this NAS EIA2 implementation accepts byte-aligned messages only"
        )
    calculator = cmac.CMAC(algorithms.AES(key))
    calculator.update(_prefix(count, bearer, direction) + message[: length // 8])
    return calculator.finalize()[:4]


@dataclass(frozen=True)
class EPSSecurityContext:
    """Inputs required to verify/decrypt one LTE EPS NAS direction."""

    cipher_algorithm: str
    integrity_algorithm: str
    k_nas_enc: bytes
    k_nas_int: bytes
    uplink_count: int
    downlink_count: int
    bearer: int = 0

    def __post_init__(self) -> None:
        if self.cipher_algorithm.upper() != "EEA2":
            raise ValueError("only EEA2 is implemented for this device profile")
        if self.integrity_algorithm.upper() != "EIA2":
            raise ValueError("only EIA2 is implemented for this device profile")
        _validate_common(self.k_nas_enc, self.uplink_count, self.bearer, 0)
        _validate_common(self.k_nas_int, self.downlink_count, self.bearer, 1)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "EPSSecurityContext":
        required = (
            "cipher_algorithm",
            "integrity_algorithm",
            "k_nas_enc_hex",
            "k_nas_int_hex",
            "uplink_count",
            "downlink_count",
        )
        missing = [name for name in required if name not in value]
        if missing:
            raise ValueError("missing EPS security-context fields: " + ", ".join(missing))
        try:
            k_enc = bytes.fromhex(str(value["k_nas_enc_hex"]))
            k_int = bytes.fromhex(str(value["k_nas_int_hex"]))
        except ValueError as exc:
            raise ValueError("NAS keys must be hexadecimal") from exc
        return cls(
            cipher_algorithm=str(value["cipher_algorithm"]).upper(),
            integrity_algorithm=str(value["integrity_algorithm"]).upper(),
            k_nas_enc=k_enc,
            k_nas_int=k_int,
            uplink_count=int(value["uplink_count"]),
            downlink_count=int(value["downlink_count"]),
            bearer=int(value.get("bearer", 0)),
        )

    def count_for(self, direction: Direction) -> int:
        return self.uplink_count if direction == 0 else self.downlink_count

    def public_description(self) -> dict[str, Any]:
        """Return safe metadata; deliberately excludes both secret keys."""
        return {
            "cipher_algorithm": self.cipher_algorithm,
            "integrity_algorithm": self.integrity_algorithm,
            "uplink_count": self.uplink_count,
            "downlink_count": self.downlink_count,
            "bearer": self.bearer,
        }


def process_security_protected_nas(
    pdu: bytes,
    direction: Direction,
    context: EPSSecurityContext,
    *,
    count: int | None = None,
) -> dict[str, Any]:
    """Verify and, when necessary, decrypt one security-protected EPS NAS PDU.

    The integrity-protected message is the NAS sequence-number octet followed
    by the protected NAS payload.  The ciphering operation applies only to the
    bytes following that sequence number.
    """
    if len(pdu) < 6:
        raise ValueError("security-protected EPS NAS PDU is shorter than 6 bytes")
    if (pdu[0] & 0x0F) != 7:
        raise ValueError("PDU is not EPS mobility-management NAS")
    security_header_type = pdu[0] >> 4
    if security_header_type not in (1, 2, 3, 4):
        raise ValueError("PDU does not use a supported protected security header")

    full_count = context.count_for(direction) if count is None else count
    if not 0 <= full_count <= 0xFFFFFFFF:
        raise ValueError("COUNT must be an unsigned 32-bit integer")
    sequence_number = pdu[5]
    if (full_count & 0xFF) != sequence_number:
        raise ValueError(
            f"COUNT low octet 0x{full_count & 0xff:02x} does not match "
            f"NAS sequence number 0x{sequence_number:02x}"
        )

    received_mac = pdu[1:5]
    integrity_input = pdu[5:]
    expected_mac = eia2_mac(
        context.k_nas_int,
        full_count,
        context.bearer,
        direction,
        integrity_input,
    )
    protected_payload = pdu[6:]
    ciphered = security_header_type in (2, 4)
    plaintext = (
        eea2_crypt(
            context.k_nas_enc,
            full_count,
            context.bearer,
            direction,
            protected_payload,
        )
        if ciphered
        else protected_payload
    )
    return {
        "security_header_type": security_header_type,
        "direction": "MO" if direction == 0 else "MT",
        "count": full_count,
        "bearer": context.bearer,
        "sequence_number": sequence_number,
        "integrity_algorithm": context.integrity_algorithm,
        "received_mac_hex": received_mac.hex(),
        "expected_mac_hex": expected_mac.hex(),
        "integrity_valid": received_mac == expected_mac,
        "cipher_algorithm": context.cipher_algorithm if ciphered else "not-applied",
        "ciphered": ciphered,
        "protected_payload_hex": protected_payload.hex(),
        "plaintext_payload_hex": plaintext.hex(),
    }
