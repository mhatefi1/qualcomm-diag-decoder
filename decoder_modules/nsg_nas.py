#!/usr/bin/env python3
"""LTE EPS NAS extraction and semantic decoding for the fixed Poco X3 profile.

The Qualcomm LTE NAS OTA log records used by this project have a four-octet
version header followed by the 3GPP NAS PDU:

    packet-version, RRC-release, major-version, minor-version, NAS...

That layout is documented by both the vendored MobileInsight and SCAT
implementations and is confirmed by this device's B0ED records.  The actual
NAS PDU is decoded with pycrate's TS 24.301 implementation.  Unknown wrapper
versions and undecodable PDUs are preserved losslessly.
"""

from __future__ import annotations

import json
import io
import sys
from contextlib import redirect_stderr, redirect_stdout
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .nsg_schema_registry import probe_record

if TYPE_CHECKING:
    from .nsg_nas_security import EPSSecurityContext

_VENDOR_PYCRATE = Path(__file__).resolve().parent.parent / "vendor" / "pycrate"
if _VENDOR_PYCRATE.is_dir() and str(_VENDOR_PYCRATE) not in sys.path:
    sys.path.insert(0, str(_VENDOR_PYCRATE))


NAS_LOG_PROFILES: dict[str, dict[str, str]] = {
    "0xB0E0": {"direction": "MT", "plane": "ESM", "form": "security-protected"},
    "0xB0E1": {"direction": "MO", "plane": "ESM", "form": "security-protected"},
    "0xB0E2": {"direction": "MT", "plane": "ESM", "form": "plain"},
    "0xB0E3": {"direction": "MO", "plane": "ESM", "form": "plain"},
    "0xB0EA": {"direction": "MT", "plane": "EMM", "form": "security-protected"},
    "0xB0EB": {"direction": "MO", "plane": "EMM", "form": "security-protected"},
    "0xB0EC": {"direction": "MT", "plane": "EMM", "form": "plain"},
    "0xB0ED": {"direction": "MO", "plane": "EMM", "form": "plain"},
}


FRIENDLY_MESSAGE_NAMES = {
    "EMMServiceRequest": "SERVICE_REQUEST",
    "EMMAttachRequest": "ATTACH_REQUEST",
    "EMMAttachAccept": "ATTACH_ACCEPT",
    "EMMAttachComplete": "ATTACH_COMPLETE",
    "EMMAttachReject": "ATTACH_REJECT",
    "EMMAuthenticationRequest": "AUTHENTICATION_REQUEST",
    "EMMAuthenticationResponse": "AUTHENTICATION_RESPONSE",
    "EMMAuthenticationReject": "AUTHENTICATION_REJECT",
    "EMMAuthenticationFailure": "AUTHENTICATION_FAILURE",
    "EMMSecurityModeCommand": "SECURITY_MODE_COMMAND",
    "EMMSecurityModeComplete": "SECURITY_MODE_COMPLETE",
    "EMMSecurityModeReject": "SECURITY_MODE_REJECT",
    "EMMTrackingAreaUpdateRequest": "TRACKING_AREA_UPDATE_REQUEST",
    "EMMTrackingAreaUpdateAccept": "TRACKING_AREA_UPDATE_ACCEPT",
    "EMMTrackingAreaUpdateComplete": "TRACKING_AREA_UPDATE_COMPLETE",
    "EMMTrackingAreaUpdateReject": "TRACKING_AREA_UPDATE_REJECT",
    "ESMPDNConnectivityRequest": "PDN_CONNECTIVITY_REQUEST",
    "ESMPDNConnectivityReject": "PDN_CONNECTIVITY_REJECT",
    "ESMInformationRequest": "ESM_INFORMATION_REQUEST",
    "ESMInformationResponse": "ESM_INFORMATION_RESPONSE",
    "ESMActDefaultEPSBearerCtxtRequest": "ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST",
    "ESMActDefaultEPSBearerCtxtAccept": "ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT",
    "ESMActDedicatedEPSBearerCtxtRequest": "ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST",
    "ESMActDedicatedEPSBearerCtxtAccept": "ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_ACCEPT",
    "EMMSecProtNASMessage": "SECURITY_PROTECTED_NAS_MESSAGE",
}


SECURITY_HEADER_NAMES = {
    0: "plain NAS message",
    1: "integrity protected",
    2: "integrity protected and ciphered",
    3: "integrity protected with new EPS security context",
    4: "integrity protected and ciphered with new EPS security context",
    12: "service request",
}


def _load_naslte() -> tuple[Any | None, str | None]:
    try:
        # pycrate emits an import-time warning when its optional CryptoMobile
        # backend is absent. This CLI uses its own cryptography-based EEA2/EIA2
        # implementation, so keep that irrelevant third-party warning out of
        # the user's terminal while preserving real import failures below.
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            from pycrate_mobile import NASLTE

        return NASLTE, None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _pycrate_value(message: Any) -> Any:
    """Return pycrate's decoded tree in JSON-safe form."""
    try:
        return json.loads(message.to_json())
    except Exception:
        try:
            return message.get_val()
        except Exception:
            return str(message)


def _collect_nested_messages(node: Any, outer_class: str) -> list[str]:
    found: list[str] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                class_name = str(key)
                if class_name != outer_class and class_name in FRIENDLY_MESSAGE_NAMES:
                    friendly = FRIENDLY_MESSAGE_NAMES[class_name]
                    if friendly not in found:
                        found.append(friendly)
                visit(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                visit(child)

    visit(node)
    return found


def _security_metadata(payload: bytes) -> dict[str, Any]:
    if not payload:
        return {}
    protocol_discriminator = payload[0] & 0x0F
    security_header_type = payload[0] >> 4 if protocol_discriminator == 7 else 0
    result: dict[str, Any] = {
        "protocol_discriminator": protocol_discriminator,
        "security_header_type": security_header_type,
        "security_header_name": SECURITY_HEADER_NAMES.get(
            security_header_type, "reserved/unknown"
        ),
    }
    if protocol_discriminator == 7 and security_header_type in {1, 2, 3, 4}:
        if len(payload) >= 6:
            result.update(
                {
                    "mac_hex": payload[1:5].hex(),
                    "sequence_number": payload[5],
                    "protected_payload_hex": payload[6:].hex(),
                }
            )
        result["integrity_validation"] = (
            "not-validated: K_NASint, integrity algorithm, bearer direction, "
            "and full NAS COUNT are unavailable"
        )
        if security_header_type in {2, 4}:
            result["ciphering"] = (
                "ciphertext preserved; K_NASenc, ciphering algorithm, and full "
                "NAS COUNT are required to decrypt"
            )
        else:
            result["ciphering"] = "not ciphered; inner NAS can be decoded"
    elif protocol_discriminator == 7 and security_header_type == 12 and len(payload) >= 4:
        ksi_sequence = payload[1]
        result.update(
            {
                "ksi": (ksi_sequence >> 5) & 0x07,
                "short_sequence_number": ksi_sequence & 0x1F,
                "short_mac_hex": payload[2:4].hex(),
                "integrity_validation": (
                    "not-validated: EPS security context and full NAS COUNT are unavailable"
                ),
            }
        )
    return result


def decode_lte_nas(
    payload: bytes,
    direction: str,
    naslte: Any | None = None,
    *,
    security_context: "EPSSecurityContext | None" = None,
    full_count: int | None = None,
    allow_proprietary_tail: bool = True,
) -> dict[str, Any]:
    """Decode one LTE EPS NAS PDU.

    ``direction`` is ``MO`` for UE-to-network and ``MT`` for network-to-UE.
    """
    direction = direction.upper()
    result: dict[str, Any] = {
        "payload_hex": payload.hex(),
        "payload_length": len(payload),
        "direction": direction,
    }
    result.update(_security_metadata(payload))
    if not payload:
        return {**result, "status": "decode-error", "error": "empty NAS PDU"}
    if not any(payload):
        return {
            **result,
            "status": "placeholder",
            "reason": "all-zero Qualcomm NAS log placeholder; no over-air PDU",
        }
    if direction not in {"MO", "MT"}:
        return {
            **result,
            "status": "decode-error",
            "error": f"invalid NAS direction {direction!r}",
        }

    security_header_type = result.get("security_header_type")
    if security_context is not None and security_header_type in {1, 2, 3, 4}:
        from .nsg_nas_security import process_security_protected_nas

        try:
            security = process_security_protected_nas(
                payload,
                0 if direction == "MO" else 1,
                security_context,
                count=full_count,
            )
        except ValueError as exc:
            result["security_processing"] = {
                "status": "context-error",
                "error": str(exc),
            }
        else:
            result["security_processing"] = {
                "status": "processed",
                **security,
            }
            plaintext = bytes.fromhex(security["plaintext_payload_hex"])
            result["decrypted_nas"] = decode_lte_nas(
                plaintext, direction, naslte=naslte
            )

    import_error: str | None = None
    if naslte is None:
        naslte, import_error = _load_naslte()
    if naslte is None:
        return {
            **result,
            "status": "decoder-unavailable",
            "error": import_error or "pycrate NASLTE unavailable",
        }

    parser = naslte.parse_NASLTE_MO if direction == "MO" else naslte.parse_NASLTE_MT
    try:
        with redirect_stdout(io.StringIO()):
            message, error_code = parser(payload, inner=True, sec_hdr=True)
    except Exception as exc:
        return {
            **result,
            "status": "decode-error",
            "error": f"{type(exc).__name__}: {exc}",
        }
    trimmed_tail = b""
    # This Poco X3 firmware can append a proprietary 16-byte suffix to a
    # B0E2 ESM OTA record.  Standards decoders reject the otherwise valid PDU.
    # Retry only plain ESM, keep the first shortest trim that fully decodes,
    # and preserve every removed byte for auditability.
    if allow_proprietary_tail and message is None and (payload[0] & 0x0F) == 2:
        for trim in range(1, min(32, len(payload) - 2) + 1):
            try:
                with redirect_stdout(io.StringIO()):
                    candidate, candidate_error = parser(
                        payload[:-trim], inner=True, sec_hdr=True
                    )
            except Exception:
                continue
            if candidate is not None and candidate_error == 0:
                message = candidate
                error_code = 0
                trimmed_tail = payload[-trim:]
                break
    if message is None:
        return {
            **result,
            "status": "decode-error",
            "pycrate_error_code": error_code,
        }

    class_name = type(message).__name__
    decoded_fields = _pycrate_value(message)
    result.update(
        {
            "status": "decoded",
            "message": FRIENDLY_MESSAGE_NAMES.get(class_name, class_name),
            "decoder_class": class_name,
            "decoded_fields": decoded_fields,
        }
    )
    nested_messages = _collect_nested_messages(decoded_fields, class_name)
    if nested_messages:
        result["nested_messages"] = nested_messages
    if trimmed_tail:
        result.update(
            {
                "input_transform": "trimmed proprietary Qualcomm ESM tail",
                "decoded_payload_length": len(payload) - len(trimmed_tail),
                "preserved_trailing_hex": trimmed_tail.hex(),
            }
        )
    if error_code:
        # pycrate may successfully decode the outer EMM message while an
        # optional nested ESM/NAS container fails.  Keep the valid outer
        # result and expose the narrower failure rather than discarding both.
        result["nested_decode_warning"] = {
            "pycrate_error_code": error_code,
            "scope": "optional nested NAS/ESM container",
        }
    # Ciphered security-protected messages expose their envelope, not their
    # hidden inner message.  Make that distinction explicit for UI consumers.
    if result.get("security_header_type") in {2, 4}:
        result["decode_scope"] = "security envelope only; inner NAS is ciphered"
    elif result.get("security_header_type") in {1, 3}:
        result["decode_scope"] = "security envelope and clear-text inner NAS"
    else:
        result["decode_scope"] = "complete unencrypted NAS PDU"
    return result


def extract_qualcomm_nas(
    record: dict[str, Any],
    *,
    security_context: "EPSSecurityContext | None" = None,
    full_count: int | None = None,
) -> dict[str, Any] | None:
    """Extract and decode a supported Qualcomm B0E* NAS OTA record."""
    log_id = str(record.get("log_id", "")).upper().replace("X", "x")
    # Normalize Python-style 0X prefixes without changing hexadecimal digits.
    if log_id.startswith("0X"):
        log_id = "0x" + log_id[2:]
    profile = NAS_LOG_PROFILES.get(log_id)
    if profile is None:
        return None
    try:
        body = bytes.fromhex(str(record.get("body_hex", "")))
    except ValueError:
        return {
            "source": "qualcomm-diag",
            "log_id": log_id,
            "status": "extract-error",
            "error": "body_hex is not valid hexadecimal",
        }
    correlation = {
        key: record[key]
        for key in (
            "frame_index",
            "timestamp_header_hex",
            "timestamp_utc",
            "diag_header_hex",
        )
        if record.get(key) is not None
    }
    base: dict[str, Any] = {
        "source": "qualcomm-diag",
        "log_id": log_id,
        **correlation,
        **profile,
        "raw_body_hex": body.hex(),
    }
    selection = probe_record(int(log_id, 16), body)
    base["schema_selection"] = selection.as_dict()
    if len(body) < 4:
        return {
            **base,
            "status": "extract-error",
            "error": "NAS OTA body is shorter than its four-octet Qualcomm header",
        }
    header = {
        "packet_version": body[0],
        "rrc_release_number": body[1],
        "major_version": body[2],
        "minor_version": body[3],
    }
    base["qualcomm_header"] = header
    if body[0] != 1:
        return {
            **base,
            "status": "unsupported-wrapper-version",
            "nas_payload_hex": body[4:].hex(),
        }
    payload = body[4:]
    return {
        **base,
        "nas_payload_hex": payload.hex(),
        "nas": decode_lte_nas(
            payload,
            profile["direction"],
            security_context=security_context,
            full_count=full_count,
        ),
    }


def _walk_dedicated_info_nas(node: Any, path: str = "") -> Iterator[tuple[str, bytes]]:
    if isinstance(node, dict):
        for key, value in node.items():
            child_path = f"{path}.{key}" if path else str(key)
            if str(key) == "dedicatedInfoNAS" and isinstance(value, str):
                try:
                    yield child_path, bytes.fromhex(value)
                except ValueError:
                    pass
            yield from _walk_dedicated_info_nas(value, child_path)
    elif isinstance(node, (list, tuple)):
        for index, value in enumerate(node):
            yield from _walk_dedicated_info_nas(value, f"{path}[{index}]")


def extract_rrc_nested_nas(
    record: dict[str, Any],
    *,
    security_context: "EPSSecurityContext | None" = None,
) -> list[dict[str, Any]]:
    """Decode every dedicatedInfoNAS value in a semantically decoded RRC row."""
    semantic = record.get("semantic_decode")
    if not isinstance(semantic, dict):
        return []
    value = semantic.get("value")
    if value is None:
        return []
    header = record.get("rrc_header")
    transport = header.get("rrc_transport", "") if isinstance(header, dict) else ""
    direction = "MO" if str(transport).upper().startswith("UL-") else "MT"
    events = []
    for path, payload in _walk_dedicated_info_nas(value):
        correlation = {
            key: record[key]
            for key in (
                "frame_index",
                "timestamp_header_hex",
                "timestamp_utc",
                "diag_header_hex",
            )
            if record.get(key) is not None
        }
        events.append(
            {
                "source": "rrc-dedicatedInfoNAS",
                "log_id": record.get("log_id"),
                **correlation,
                "direction": direction,
                "rrc_transport": transport,
                "tree_path": path,
                "nas_payload_hex": payload.hex(),
                "nas": decode_lte_nas(
                    payload, direction, security_context=security_context
                ),
            }
        )
    return events


def extract_nas_events(
    record: dict[str, Any],
    *,
    security_context: "EPSSecurityContext | None" = None,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    raw = extract_qualcomm_nas(record, security_context=security_context)
    if raw is not None:
        events.append(raw)
    events.extend(
        extract_rrc_nested_nas(record, security_context=security_context)
    )
    return events
