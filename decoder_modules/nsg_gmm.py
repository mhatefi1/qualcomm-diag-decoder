"""TS 24.008 GMM decoders and the Poco X3 0x5C30 adapter."""

from __future__ import annotations

from typing import Any

from .nsg_schema_registry import probe_record


GMM_PD = 8
AUTH_REQUEST, AUTH_RESPONSE, AUTH_REJECT = 18, 19, 20
RAU_REQUEST, RAU_REJECT = 8, 11
TRAILING_BYTES = 250


class _Cursor:
    def __init__(self, data: bytes, position: int = 0):
        self.data, self.position = data, position

    def remaining(self) -> int:
        return len(self.data) - self.position

    def peek(self) -> int:
        if self.remaining() < 1:
            raise ValueError("unexpected end of GMM PDU")
        return self.data[self.position]

    def u8(self) -> int:
        value = self.peek()
        self.position += 1
        return value

    def take(self, length: int) -> bytes:
        if length < 0 or self.position + length > len(self.data):
            raise ValueError(f"need {length} GMM bytes, only {self.remaining()} remain")
        value = self.data[self.position:self.position + length]
        self.position += length
        return value


def _header(pdu: bytes) -> tuple[int, int, int]:
    if len(pdu) < 2:
        raise ValueError("GMM PDU is shorter than its header")
    skip, pd, message_type = pdu[0] >> 4, pdu[0] & 15, pdu[1]
    if skip:
        raise ValueError("GMM skip indicator must be zero")
    if pd != GMM_PD:
        raise ValueError("GMM protocol discriminator must be 8")
    return skip, pd, message_type


def _tlv(cursor: _Cursor, tag: int, name: str, minimum: int, maximum: int) -> bytes:
    if cursor.u8() != tag:
        raise ValueError("internal TLV tag mismatch")
    length = cursor.u8()
    if not minimum <= length <= maximum:
        expected = str(minimum) if minimum == maximum else f"{minimum}..{maximum}"
        raise ValueError(f"{name} length must be {expected} bytes; got {length}")
    return cursor.take(length)


def _imeisv(value: bytes) -> dict[str, Any]:
    if len(value) != 9:
        raise ValueError("IMEISV must contain 9 encoded bytes")
    first, digits = value[0], ""
    first_digit, odd, identity_type = first >> 4, bool((first >> 3) & 1), first & 7
    if identity_type != 3 or odd or first_digit > 9:
        raise ValueError("IMEISV identity type, parity, or first digit is invalid")
    digits = str(first_digit)
    for index, octet in enumerate(value[1:], 1):
        low, high = octet & 15, octet >> 4
        if low > 9:
            raise ValueError("IMEISV low nibble is not decimal")
        digits += str(low)
        if index == len(value) - 1:
            if high != 15:
                raise ValueError("IMEISV filler must be 0xF")
        else:
            if high > 9:
                raise ValueError("IMEISV high nibble is not decimal")
            digits += str(high)
    if len(digits) != 16:
        raise ValueError("IMEISV must contain 16 digits")
    return {"identity_type": 3, "identity_type_name": "IMEISV", "first_digit": first_digit, "odd_number_of_digits": False, "digits": digits}


def _auth(pdu: bytes) -> dict[str, Any]:
    _, pd, message_type = _header(pdu)
    cursor = _Cursor(pdu, 2)
    if message_type == AUTH_REJECT:
        if len(pdu) != 2:
            raise ValueError("Authentication and Ciphering Reject must be exactly 2 bytes")
        return {"status": "decoded", "message": "AUTHENTICATION_AND_CIPHERING_REJECT", "protocol_discriminator": pd, "message_type": message_type}
    if message_type == AUTH_REQUEST:
        algorithm_byte, reference_byte = cursor.u8(), cursor.u8()
        requested, ciphering = algorithm_byte >> 4, algorithm_byte & 15
        reference, standby = reference_byte >> 4, reference_byte & 15
        if requested > 1 or ciphering > 7:
            raise ValueError("Authentication Request IMEISV or ciphering algorithm bits are invalid")
        if standby > 1:
            raise ValueError("force-to-standby spare bits must be zero")
        result: dict[str, Any] = {
            "status": "decoded", "message": "AUTHENTICATION_AND_CIPHERING_REQUEST",
            "protocol_discriminator": pd, "message_type": message_type,
            "terminal_identity_requested": requested == 1, "ciphering_algorithm": ciphering,
            "ciphering_algorithm_name": "ciphering not used" if ciphering == 0 else f"GEA/{ciphering}",
            "authentication_ciphering_reference": reference, "force_to_standby": standby == 1,
        }
        seen: set[int] = set()
        while cursor.remaining():
            tag = cursor.peek()
            identity = tag >> 4 if tag >> 4 in {8, 9} else tag
            if identity in seen:
                raise ValueError(f"duplicate Authentication Request IE 0x{identity:02X}")
            seen.add(identity)
            if tag == 0x21:
                cursor.u8(); result["rand_hex"] = cursor.take(16).hex()
            elif tag & 0xF0 == 0x80:
                cursor.u8(); value = tag & 15
                if value > 7: raise ValueError("GPRS CKSN must be in range 0..7")
                result["ciphering_key_sequence"] = value
            elif tag == 0x28:
                result["autn_hex"] = _tlv(cursor, tag, "AUTN", 16, 16).hex()
            elif tag == 0x31:
                value = _tlv(cursor, tag, "MS Network Capability", 1, 255)
                result["ms_network_capability"] = {"length": len(value), "octets": list(value)}
            elif tag & 0xF0 == 0x90:
                cursor.u8(); value = tag & 15
                if value > 3: raise ValueError("GPRS integrity algorithm must be in range 0..3")
                result["integrity_algorithm"] = value
                result["integrity_algorithm_name"] = f"GIA/{value + 4}"
            elif tag == 0x43:
                result["mac_hex"] = _tlv(cursor, tag, "MAC", 4, 4).hex()
            elif tag == 0x33:
                value = _tlv(cursor, tag, "MS Radio Access Capability", 1, 255)
                result["ms_radio_access_capability"] = {"length": len(value), "octets": list(value)}
            else:
                raise ValueError(f"unsupported Authentication Request IE 0x{tag:02X}")
        return result
    if message_type != AUTH_RESPONSE:
        raise ValueError(f"unsupported Authentication and Ciphering message type {message_type}")
    reference_byte = cursor.u8()
    if reference_byte & 0xF0:
        raise ValueError("Authentication Response spare bits must be zero")
    result = {"status": "decoded", "message": "AUTHENTICATION_AND_CIPHERING_RESPONSE", "protocol_discriminator": pd, "message_type": message_type, "authentication_ciphering_reference": reference_byte & 15}
    seen: set[int] = set()
    while cursor.remaining():
        tag = cursor.peek()
        if tag in seen: raise ValueError(f"duplicate Authentication Response IE 0x{tag:02X}")
        seen.add(tag)
        if tag == 0x22:
            cursor.u8(); result["sres_hex"] = cursor.take(4).hex()
        elif tag == 0x23:
            result["imeisv"] = _imeisv(_tlv(cursor, tag, "IMEISV", 9, 9))
        elif tag == 0x29:
            result["authentication_response_extension_hex"] = _tlv(cursor, tag, "Authentication Response extension", 1, 12).hex()
        elif tag == 0x43:
            result["mac_hex"] = _tlv(cursor, tag, "MAC", 4, 4).hex()
        else:
            raise ValueError(f"unsupported Authentication Response IE 0x{tag:02X}")
    return result


def _bits(value: bytes, offset: int, width: int) -> int:
    if offset < 0 or width < 0 or offset + width > len(value) * 8:
        raise ValueError("invalid capability bit range")
    result = 0
    for bit in range(width):
        absolute = offset + bit
        result = (result << 1) | ((value[absolute >> 3] >> (7 - (absolute & 7))) & 1)
    return result


def _plmn(value: bytes) -> tuple[str, str]:
    if len(value) < 3: raise ValueError("PLMN is truncated")
    a, b, c = value[:3]
    mcc_digits = [a & 15, a >> 4, b & 15]
    mnc_digits = [c & 15, c >> 4, b >> 4]
    if any(x > 9 for x in mcc_digits + mnc_digits[:2]) or (mnc_digits[2] != 15 and mnc_digits[2] > 9):
        raise ValueError("PLMN contains a non-decimal digit")
    return "".join(map(str, mcc_digits)), "".join(map(str, mnc_digits[:2] if mnc_digits[2] == 15 else mnc_digits))


def _routing_area(value: bytes) -> dict[str, Any]:
    if len(value) != 6: raise ValueError("Routing Area Identity must be 6 bytes")
    mcc, mnc = _plmn(value)
    return {"mcc": mcc, "mnc": mnc, "lac": int.from_bytes(value[3:5], "big"), "rac": value[5]}


def _location_area(value: bytes) -> dict[str, Any]:
    if len(value) != 5: raise ValueError("Location Area Identity must be 5 bytes")
    mcc, mnc = _plmn(value)
    return {"mcc": mcc, "mnc": mnc, "lac": int.from_bytes(value[3:5], "big")}


def _mobile_identity(value: bytes) -> dict[str, Any]:
    if not value: raise ValueError("mobile identity is empty")
    first = value[0]; first_digit, odd, identity_type = first >> 4, bool((first >> 3) & 1), first & 7
    if identity_type == 4:
        if len(value) != 5 or first != 0xF4: raise ValueError("P-TMSI requires f4 followed by four bytes")
        return {"identity_type": 4, "identity_type_name": "TMSI", "first_digit": 15, "odd_number_of_digits": False, "ptmsi": int.from_bytes(value[1:], "big")}
    if identity_type not in {1, 2, 3} or first_digit > 9: raise ValueError("unsupported mobile identity")
    digits = str(first_digit)
    for index, octet in enumerate(value[1:], 1):
        low, high = octet & 15, octet >> 4
        if low > 9: raise ValueError("identity low nibble is not decimal")
        digits += str(low)
        if index == len(value) - 1 and not odd:
            if high != 15: raise ValueError("identity filler must be 0xF")
        else:
            if high > 9: raise ValueError("identity high nibble is not decimal")
            digits += str(high)
    if bool(len(digits) & 1) != odd: raise ValueError("identity odd/even flag contradicts digit count")
    return {"identity_type": identity_type, "identity_type_name": {1: "IMSI", 2: "IMEI", 3: "IMEISV"}[identity_type], "first_digit": first_digit, "odd_number_of_digits": odd, "identity_digits": digits}


def _access_name(value: int) -> str:
    return {0: "GSM P", 1: "GSM E", 2: "GSM R", 3: "GSM 1800", 4: "GSM 1900", 5: "GSM 450", 6: "GSM 480", 7: "GSM 850", 8: "GSM 750", 9: "GSM T 380", 10: "GSM T 410", 12: "GSM 710", 13: "GSM T 810", 15: "additional access technologies"}.get(value, "unused")


def _ms_ra_capability(value: bytes) -> dict[str, Any]:
    total, position, technologies = len(value) * 8, 0, []
    while position + 11 <= total:
        kind, width = _bits(value, position, 4), _bits(value, position + 4, 7)
        position += 11
        if position + width > total: raise ValueError("MS RA capability block exceeds LV boundary")
        technologies.append({"type": kind, "name": _access_name(kind), "capability_bits": width})
        position += width
        if position >= total: break
        more = _bits(value, position, 1); position += 1
        if not more:
            if any(_bits(value, bit, 1) for bit in range(position, total)): raise ValueError("MS RA capability has non-zero spare bits")
            break
    if not technologies: raise ValueError("MS RA capability has no access-technology block")
    return {"kind": "MS_RA_CAPABILITY", "octets": list(value), "fields": {}, "access_technologies": technologies}


def _network_capability(value: bytes) -> dict[str, Any]:
    if not value: raise ValueError("MS Network Capability is empty")
    names = ["gea1", "sm_dedicated", "sm_gprs", "ucs2", None, None, "solsa", "revision_level", "pfc", "gea2", "gea3", "gea4", "gea5", "gea6", "gea7", "lcs_va", "ps_ho_utran", "ps_ho_eutran", "emm_combined", "isr", "srvcc", "epc", "nf", "geran_network_sharing", "user_plane_integrity", "gia4", "gia5", "gia6", "gia7"]
    fields = {name: _bits(value, bit, 1) for bit, name in enumerate(names[:len(value) * 8]) if name}
    if len(value) * 8 >= 6: fields["ss_screening_indicator"] = _bits(value, 4, 2)
    return {"kind": "MS_NETWORK_CAPABILITY", "octets": list(value), "fields": fields, "access_technologies": []}


def _timer(octet: int, extended: bool = False) -> dict[str, Any]:
    unit, value = octet >> 5, octet & 31
    if extended:
        multipliers = [600, 3600, 36000, 2, 30, 60, 1152000, 0]
        names = ["10 minutes", "1 hour", "10 hours", "2 seconds", "30 seconds", "1 minute", "320 hours", "deactivated"]
    else:
        multipliers = [2, 60, 360, 0, 0, 0, 0, 0]
        names = ["2 seconds", "1 minute", "6 minutes", "reserved", "reserved", "reserved", "reserved", "deactivated"]
    result = {"format": "GPRS_TIMER_3" if extended else "GPRS_TIMER", "unit": unit, "value": value, "unit_name": names[unit], "deactivated": unit == 7}
    if extended or unit not in {3, 4, 5, 6}: result["seconds"] = multipliers[unit] * value
    return result


def _ie(tag: int, name: str, wire: str, encoded: int, value: Any) -> dict[str, Any]:
    return {"iei": tag, "name": name, "wire_format": wire, "encoded_length": encoded, "value": value}


def _request_ie(cursor: _Cursor) -> dict[str, Any]:
    tag = cursor.peek()
    if tag == 0x19:
        cursor.u8(); value = int.from_bytes(cursor.take(3), "big"); return _ie(tag, "Old P-TMSI Signature", "TV", 4, value)
    if tag == 0x17:
        cursor.u8(); return _ie(tag, "Requested READY Timer", "TV", 2, _timer(cursor.u8()))
    if tag == 0x27:
        cursor.u8(); value = cursor.take(2); second = value[1]
        return _ie(tag, "DRX Parameters", "TV", 3, {"split_paging_cycle_code": value[0], "cycle_length_coefficient": second >> 4, "split_on_ccch": bool(second & 8), "non_drx_timer": second & 7})
    high = tag & 0xF0
    if high in {0x90, 0xE0, 0xD0, 0xC0, 0xF0}:
        cursor.u8(); value = tag & 15
        name = {0x90: "TMSI Status", 0xE0: "P-TMSI Type", 0xD0: "Device Properties", 0xC0: "MS Network Feature Support", 0xF0: "Additional Update Type"}[high]
        if high != 0xF0 and value > 1: raise ValueError(f"{name} spare bits must be zero")
        return _ie(high >> 4, name, "T1TV", 1, value)
    cursor.u8(); length = cursor.u8(); value = cursor.take(length)
    if tag == 0x18: name, decoded = "P-TMSI", _mobile_identity(value)
    elif tag == 0x31: name, decoded = "MS Network Capability", _network_capability(value)
    elif tag == 0x32: name, decoded = "PDP Context Status", list(value)
    elif tag == 0x33: name, decoded = "PS LCS Capability", list(value)
    elif tag == 0x35: name, decoded = "MBMS Context Status", list(value)
    elif tag == 0x58: name, decoded = "UE Network Capability", list(value)
    elif tag == 0x1A: name, decoded = "Additional Mobile Identity", _mobile_identity(value)
    elif tag == 0x1B: name, decoded = "Additional Routing Area Identity", _routing_area(value)
    elif tag == 0x11:
        if length != 3: raise ValueError("MS Classmark 2 must be 3 bytes")
        name, decoded = "MS Classmark 2", list(value)
    elif tag == 0x20: name, decoded = "MS Classmark 3", list(value)
    elif tag == 0x40: name, decoded = "Supported Codec List", list(value)
    elif tag == 0x5D: name, decoded = "Voice Domain Preference", list(value)
    elif tag == 0x14: name, decoded = "Old Location Area Identity", _location_area(value)
    elif tag == 0x10: name, decoded = "TMSI Based NRI Container", list(value)
    elif tag == 0x6A:
        if length != 1: raise ValueError("T3324 must be 1 byte")
        name, decoded = "T3324", _timer(value[0])
    elif tag == 0x39:
        if length != 1: raise ValueError("T3312 Extended must be 1 byte")
        name, decoded = "T3312 Extended", _timer(value[0], True)
    elif tag == 0x6E:
        if length != 1: raise ValueError("Extended DRX Parameters must be 1 byte")
        name, decoded = "Extended DRX Parameters", value[0]
    else: raise ValueError(f"unsupported RAU Request optional IE 0x{tag:02X}")
    return _ie(tag, name, "TLV", length + 2, decoded)


def _cause_name(value: int) -> str:
    return {2: "IMSI unknown in HLR", 3: "Illegal MS", 5: "IMEI not accepted", 6: "Illegal ME", 7: "GPRS services not allowed", 8: "GPRS and non-GPRS services not allowed", 9: "MS identity cannot be derived", 10: "implicitly detached", 11: "PLMN not allowed", 12: "Location Area not allowed", 13: "Roaming not allowed in this location area", 14: "GPRS services not allowed in this PLMN", 15: "No suitable cells in Location Area", 16: "MSC temporarily not reachable", 17: "Network failure", 20: "MAC failure", 21: "Synchronization failure", 22: "Congestion", 23: "GSM authentication unacceptable", 25: "Not authorized for this CSG", 40: "No PDP context activated", 48: "Retry upon entry into a new cell", 95: "Semantically incorrect message", 96: "Invalid mandatory information", 97: "Message type not implemented", 98: "Message type incompatible with protocol state", 99: "Information element not implemented", 100: "Conditional IE error", 101: "Message incompatible with protocol state", 111: "Protocol error, unspecified"}.get(value, f"GMM cause {value}")


def _rau(pdu: bytes) -> dict[str, Any]:
    _, pd, message_type = _header(pdu); cursor = _Cursor(pdu, 2)
    if message_type == RAU_REQUEST:
        combined = cursor.u8(); cksn, update = combined >> 4, combined & 15
        if cksn > 7 or (update & 7) > 3: raise ValueError("invalid RAU CKSN or update type")
        old_rai = _routing_area(cursor.take(6)); length = cursor.u8()
        if not length: raise ValueError("MS Radio Access Capability must not be empty")
        capability = _ms_ra_capability(cursor.take(length)); optional = []
        while cursor.remaining(): optional.append(_request_ie(cursor))
        update_type = update & 7
        return {"status": "decoded", "message": "ROUTING_AREA_UPDATE_REQUEST", "protocol_discriminator": pd, "message_type": message_type, "ciphering_key_sequence": cksn, "no_ciphering_key_available": cksn == 7, "follow_on_request": bool(update & 8), "update_type": update_type, "update_type_name": ["RA updating", "combined RA/LA updating", "combined RA/LA updating with IMSI attach", "periodic updating"][update_type], "old_routing_area": old_rai, "ms_radio_access_capability": capability, "optional_elements": optional}
    if message_type != RAU_REJECT: raise ValueError(f"unsupported RAU message type {message_type}")
    cause, standby = cursor.u8(), cursor.u8()
    if (standby & 0xF0) or (standby & 0x0E): raise ValueError("RAU Reject force-to-standby spare bits must be zero")
    optional = []
    while cursor.remaining():
        tag = cursor.u8()
        if tag not in {0x2A, 0x3A}: raise ValueError(f"unsupported RAU Reject optional IE 0x{tag:02X}")
        length = cursor.u8()
        if length != 1: raise ValueError("RAU Reject timer must be one byte")
        optional.append(_ie(tag, "T3302" if tag == 0x2A else "T3346", "TLV", 3, _timer(cursor.u8())))
    return {"status": "decoded", "message": "ROUTING_AREA_UPDATE_REJECT", "protocol_discriminator": pd, "message_type": message_type, "gmm_cause": cause, "gmm_cause_name": _cause_name(cause), "force_to_standby": bool(standby & 1), "optional_elements": optional}


def _preserved(message: str, protocol: int, message_type: int, length: int) -> dict[str, Any]:
    return {"status": "preserved-unsupported", "message": message, "message_type": message_type, "protocol_discriminator": protocol, "payload_length": length}


def decode_5c30(body: bytes) -> dict[str, Any]:
    selection = probe_record(0x5C30, body)
    if not selection.selected: raise ValueError(selection.reason)
    radio_id, direction_code, diagnostic_type = body[:3]; declared = int.from_bytes(body[3:5], "little")
    if radio_id != 2: raise ValueError(f"0x5C30 fixed-device route requires radio ID 2; got {radio_id}")
    if direction_code not in {0, 1}: raise ValueError("0x5C30 direction must be uplink or downlink")
    if len(body) != 5 + declared + TRAILING_BYTES: raise ValueError(f"0x5C30 declares {declared} L3 bytes plus 250 trailing bytes; got {len(body)} total")
    if declared < 2: raise ValueError("0x5C30 L3 payload is too short")
    l3 = body[5:5 + declared]; protocol, message_type = l3[0] & 15, l3[1]
    if diagnostic_type != message_type: raise ValueError("0x5C30 wrapper message type does not match embedded L3 type")
    direction = "UPLINK" if direction_code == 0 else "DOWNLINK"
    result: dict[str, Any] = {"source": "qualcomm-diag", "log_id": "0x5C30", "schema_selection": selection.as_dict(), "qualcomm_transport": {"radio_id": radio_id, "direction": direction, "direction_code": direction_code, "diagnostic_message_type": diagnostic_type, "l3_length": declared, "opaque_trailing_bytes": TRAILING_BYTES, "packet_version_present": False}, "gmm_payload_hex": l3.hex()}
    if protocol == 10:
        result["gprs_l3"] = _preserved("SM", protocol, message_type, len(l3)); return result
    if protocol != GMM_PD:
        result["gprs_l3"] = _preserved(f"PROTOCOL_{protocol}", protocol, message_type, len(l3)); return result
    gmm_names = {1: "ATTACH_REQUEST", 2: "ATTACH_ACCEPT", 3: "ATTACH_COMPLETE", 4: "ATTACH_REJECT", 5: "DETACH_REQUEST", 6: "DETACH_ACCEPT", 8: "ROUTING_AREA_UPDATE_REQUEST", 9: "ROUTING_AREA_UPDATE_ACCEPT", 10: "ROUTING_AREA_UPDATE_COMPLETE", 11: "ROUTING_AREA_UPDATE_REJECT", 18: "AUTHENTICATION_AND_CIPHERING_REQUEST", 19: "AUTHENTICATION_AND_CIPHERING_RESPONSE", 20: "AUTHENTICATION_AND_CIPHERING_REJECT", 21: "IDENTITY_REQUEST", 22: "IDENTITY_RESPONSE"}
    if message_type not in {RAU_REQUEST, RAU_REJECT, AUTH_REQUEST, AUTH_RESPONSE, AUTH_REJECT}:
        result["gmm"] = _preserved(gmm_names.get(message_type, f"GMM_MESSAGE_{message_type}"), protocol, message_type, len(l3)); return result
    expected_direction = {RAU_REQUEST: 0, RAU_REJECT: 1, AUTH_REQUEST: 1, AUTH_RESPONSE: 0, AUTH_REJECT: 1}[message_type]
    if direction_code != expected_direction: raise ValueError(f"{gmm_names[message_type]} has the wrong 0x5C30 direction")
    result["gmm"] = _auth(l3) if message_type in {AUTH_REQUEST, AUTH_RESPONSE, AUTH_REJECT} else _rau(l3)
    return result
