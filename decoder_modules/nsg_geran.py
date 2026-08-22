"""TS 44.018 GERAN RR decoders and the Poco X3 0x5B2F adapter."""

from __future__ import annotations

from typing import Any

from .nsg_schema_registry import probe_record


RR_PD = 6
PAGING_RESPONSE = 0x27
CIPHERING_MODE_COMPLETE = 0x32
CIPHERING_MODE_COMMAND = 0x35


def _bit(value: bool) -> int:
    return int(value)


def _bcd_tail(digits: str) -> str:
    encoded = bytearray()
    for index in range(1, len(digits), 2):
        low = int(digits[index])
        high = int(digits[index + 1]) if index + 1 < len(digits) else 0x0F
        encoded.append(low | (high << 4))
    return encoded.hex()


def _decode_identity(value: bytes, *, imeisv_only: bool = False) -> dict[str, Any]:
    if not value:
        raise ValueError("mobile identity is empty")
    first = value[0]
    first_digit, odd, identity_type = first >> 4, bool((first >> 3) & 1), first & 7
    if imeisv_only:
        if identity_type != 3 or odd or len(value) != 9:
            raise ValueError("IMEISV must be a 9-byte, even, type-3 identity")
    if identity_type == 4 and not imeisv_only:
        if len(value) != 5 or first != 0xF4:
            raise ValueError("TMSI mobile identity requires f4 followed by 4 bytes")
        return {
            "identity_type": 4,
            "identity_type_name": "TMSI",
            "first_digit": 15,
            "odd_number_of_digits": False,
            "tmsi": int.from_bytes(value[1:], "big"),
        }
    allowed = {3} if imeisv_only else {1}
    if identity_type not in allowed:
        raise ValueError("Paging Response identity must be IMSI or TMSI")
    if first_digit > 9:
        raise ValueError("mobile identity first digit is not decimal")
    digits = str(first_digit)
    for index, octet in enumerate(value[1:], 1):
        low, high = octet & 15, octet >> 4
        if low > 9:
            raise ValueError("mobile identity contains a non-decimal low nibble")
        digits += str(low)
        last = index == len(value) - 1
        if last and not odd:
            if high != 0x0F:
                raise ValueError("even mobile identity requires 0xF filler")
        else:
            if high > 9:
                raise ValueError("mobile identity contains a non-decimal high nibble")
            digits += str(high)
    if bool(len(digits) & 1) != odd:
        raise ValueError("mobile identity odd/even indicator contradicts digit count")
    if imeisv_only and len(digits) != 16:
        raise ValueError("IMEISV must contain 16 digits")
    return {
        "identity_type": identity_type,
        "identity_type_name": "IMEISV" if imeisv_only else "IMSI",
        "first_digit": first_digit,
        "odd_number_of_digits": odd,
        "digits": digits,
    }


def _rr_header(name: str, first: int, message_type: int) -> dict[str, Any]:
    return {name: [
        {"SkipInd": first >> 4}, {"ProtDisc": first & 15}, {"Type": message_type}
    ]}


def _decode_ciphering(l3: bytes) -> dict[str, Any]:
    first, message_type = l3[:2]
    if first >> 4 or (first & 15) != RR_PD:
        raise ValueError("RR skip indicator must be zero and protocol discriminator must be 6")
    if message_type == CIPHERING_MODE_COMMAND:
        if len(l3) != 3:
            raise ValueError("Ciphering Mode Command must be exactly 3 bytes")
        setting = l3[2]
        response, algorithm = setting >> 4, (setting >> 1) & 7
        if response > 1:
            raise ValueError("Cipher Response spare bits must be zero")
        if algorithm == 7:
            raise ValueError("Cipher Mode algorithm identifier 7 is reserved")
        requested, start = response == 1, bool(setting & 1)
        tree = [
            _rr_header("RRHeader", first, message_type),
            {"CipherResp": [{"CipherResp": [{"spare": 0}, {"CR": _bit(requested)}]}]},
            {"CipherModeSetting": [{"CipherModeSetting": [
                {"AlgoId": algorithm}, {"SC": _bit(start)}
            ]}]},
        ]
        return {
            "status": "decoded", "message": "CIPHERING_MODE_COMMAND",
            "decoder_class": "RRCipheringModeCmd", "protocol_discriminator": RR_PD,
            "message_type": message_type, "terminal_identity_requested": requested,
            "algorithm_identifier": algorithm, "algorithm_name": f"A5/{algorithm + 1}",
            "start_ciphering": start,
            "decoded_fields": {"RRCipheringModeCmd": tree},
        }
    if len(l3) == 2:
        identity = None
    else:
        if len(l3) < 4 or l3[2] != 0x17:
            raise ValueError("Ciphering Mode Complete supports only Mobile Equipment Identity IE 0x17")
        length = l3[3]
        if length != 9 or len(l3) != 4 + length:
            raise ValueError("Ciphering Mode Complete IMEISV must be an exact 9-byte TLV value")
        identity = _decode_identity(l3[4:], imeisv_only=True)
    tree: list[Any] = [_rr_header("RRHeaderUL", first, message_type)]
    result: dict[str, Any] = {
        "status": "decoded", "message": "CIPHERING_MODE_COMPLETE",
        "decoder_class": "RRCipheringModeComplete", "protocol_discriminator": RR_PD,
        "message_type": message_type, "terminal_identity_present": identity is not None,
    }
    if identity is not None:
        result["imeisv"] = identity
        tree.append({"MEId": [
            {"T": 23}, {"L": 9}, {"ID": [
                {"Digit1": identity["first_digit"]},
                {"Odd": _bit(identity["odd_number_of_digits"])},
                {"Type": identity["identity_type"]},
                {"Digits": _bcd_tail(identity["digits"])},
            ]}
        ]})
    result["decoded_fields"] = {"RRCipheringModeComplete": tree}
    return result


def _decode_paging_response(l3: bytes) -> dict[str, Any]:
    if len(l3) < 4:
        raise ValueError("Paging Response PDU is shorter than four bytes")
    first, message_type = l3[:2]
    if first >> 4 or (first & 15) != RR_PD or message_type != PAGING_RESPONSE:
        raise ValueError("invalid Paging Response RR header")
    key = l3[2]
    if key >> 4 or (key & 15) > 7:
        raise ValueError("invalid Paging Response ciphering key sequence")
    pos = 3
    cm_len = l3[pos]
    pos += 1
    if cm_len != 3 or pos + 4 > len(l3):
        raise ValueError("MS Classmark 2 must be exactly 3 bytes")
    a, b, c = l3[pos:pos + 3]
    pos += 3
    if (a & 0x80) or (b & 0x80) or (c & 0x40):
        raise ValueError("MS Classmark 2 spare bits must be zero")
    revision, rf_class, screening = (a >> 5) & 3, a & 7, (b >> 4) & 3
    revisions = ["reserved for GSM phase 1", "GSM phase 2 MS", "MS supporting R99 or later", "future use"]
    screenings = ["phase 1 default", "phase 2 ellipsis and error handling", "future use", "future use"]
    cm = {
        "revision_level": revision, "revision_level_name": revisions[revision],
        "early_classmark_sending": bool(a & 0x10), "a5_1_available": not bool(a & 8),
        "rf_power_capability": rf_class,
        "rf_power_capability_name": f"class {rf_class + 1}" if rf_class <= 4 else "reserved",
        "packet_switched_capability": bool(b & 0x40), "ss_screening_indicator": screening,
        "ss_screening_indicator_name": screenings[screening],
        "mobile_terminated_sms_capability": bool(b & 8), "vbs_notification_capability": bool(b & 4),
        "vgcs_notification_capability": bool(b & 2), "frequency_capability": bool(b & 1),
        "classmark3_capability": bool(c & 0x80), "lcs_value_added_capability": bool(c & 0x20),
        "ucs2_treatment": bool(c & 0x10), "solsa_capability": bool(c & 8),
        "cm_service_prompt": bool(c & 4), "a5_3_available": bool(c & 2),
        "a5_2_available": bool(c & 1),
    }
    identity_len = l3[pos]
    pos += 1
    if not identity_len or pos + identity_len > len(l3):
        raise ValueError("Paging Response mobile identity length is invalid")
    identity = _decode_identity(l3[pos:pos + identity_len])
    pos += identity_len
    additional = None
    if pos < len(l3):
        if len(l3) - pos != 1 or l3[pos] >> 4 != 0x0C or (l3[pos] & 0x0C):
            raise ValueError("unsupported Paging Response optional IE")
        additional = {"cs_mobile_originated": bool(l3[pos] & 2), "cs_mobile_terminated": bool(l3[pos] & 1)}
    identity_public = {k: v for k, v in identity.items() if k != "digits"}
    if "digits" in identity:
        identity_public["imsi_digits"] = identity["digits"]
    cm_tree = [
        {"spare": 0}, {"RevLevel": revision}, {"EarlyCmCap": _bit(cm["early_classmark_sending"])},
        {"NoA51": _bit(not cm["a5_1_available"])}, {"RFClass": rf_class}, {"spare": 0},
        {"PSCap": _bit(cm["packet_switched_capability"])}, {"SSScreeningCap": screening},
        {"MTSMSCap": _bit(cm["mobile_terminated_sms_capability"])},
        {"VBSNotifCap": _bit(cm["vbs_notification_capability"])},
        {"VGCSNotifCap": _bit(cm["vgcs_notification_capability"])},
        {"FCFreqCap": _bit(cm["frequency_capability"])}, {"MSCm3Cap": _bit(cm["classmark3_capability"])},
        {"spare": 0}, {"LCSVACap": _bit(cm["lcs_value_added_capability"])},
        {"UCS2": _bit(cm["ucs2_treatment"])}, {"SoLSACap": _bit(cm["solsa_capability"])},
        {"CMServPrompt": _bit(cm["cm_service_prompt"])}, {"A53": _bit(cm["a5_3_available"])},
        {"A52": _bit(cm["a5_2_available"])},
    ]
    id_tree = [{"Digit1": identity["first_digit"]}, {"Odd": _bit(identity["odd_number_of_digits"])}, {"Type": identity["identity_type"]}]
    if "digits" in identity:
        id_tree.append({"Digits": _bcd_tail(identity["digits"])})
    else:
        id_tree.append({"TMSI": identity["tmsi"]})
    tree: list[Any] = [
        _rr_header("RRHeaderUL", first, message_type), {"spare": 0},
        {"CKSN": [{"V": key & 15}]}, {"MSCm2": [{"L": 3}, {"MSCm2": cm_tree}]},
        {"ID": [{"L": identity_len}, {"ID": id_tree}]},
    ]
    if additional is not None:
        tree.append({"AddUpdateParams": [{"T": 12}, {"AddUpdateParams": [
            {"spare": 0}, {"CSMO": _bit(additional["cs_mobile_originated"])},
            {"CSMT": _bit(additional["cs_mobile_terminated"])},
        ]}]})
    result = {
        "status": "decoded", "message": "PAGING_RESPONSE", "decoder_class": "RRPagingResponse",
        "protocol_discriminator": RR_PD, "message_type": message_type,
        "ciphering_key_sequence": key & 15, "no_ciphering_key_available": (key & 15) == 7,
        "classmark2": cm, "identity": identity_public,
        "decoded_fields": {"RRPagingResponse": tree},
    }
    if additional is not None:
        result["additional_update_parameters"] = additional
    return result


def decode_5b2f(body: bytes) -> dict[str, Any]:
    selection = probe_record(0x5B2F, body)
    if not selection.selected:
        raise ValueError(selection.reason)
    radio_id, channel_direction, diagnostic_type, declared = body[:4]
    if radio_id != 2:
        raise ValueError(f"0x5B2F fixed-device route requires radio ID 2; got {radio_id}")
    if len(body) != 4 + declared:
        raise ValueError(f"0x5B2F declares {declared} L3 bytes; got {len(body) - 4}")
    channel, downlink = channel_direction & 0x7F, bool(channel_direction & 0x80)
    pseudo = 1 if channel in {1, 3} else 0
    wrapped = body[4:]
    if len(wrapped) < pseudo + 2:
        raise ValueError("0x5B2F L3 payload is too short for an RR header")
    l3 = wrapped[pseudo:]
    protocol, message_type = l3[0] & 15, l3[1]
    if protocol != RR_PD:
        raise ValueError("0x5B2F embedded protocol discriminator must be RR (6)")
    if diagnostic_type != message_type:
        raise ValueError("0x5B2F wrapper message type does not match embedded RR type")
    names = {0x21: "PAGING_REQUEST_TYPE_1", 0x22: "PAGING_REQUEST_TYPE_2", 0x24: "PAGING_REQUEST_TYPE_3", 0x27: "PAGING_RESPONSE", 0x32: "CIPHERING_MODE_COMPLETE", 0x35: "CIPHERING_MODE_COMMAND", 0x3F: "IMMEDIATE_ASSIGNMENT"}
    result: dict[str, Any] = {
        "source": "qualcomm-diag", "log_id": "0x5B2F",
        "schema_selection": selection.as_dict(),
        "qualcomm_transport": {
            "radio_id": radio_id, "direction": "DOWNLINK" if downlink else "UPLINK",
            "channel_code": channel,
            "channel_name": {0: "DCCH", 1: "BCCH", 2: "RACH", 3: "CCCH", 4: "SACCH", 5: "SDCCH", 6: "FACCH/F", 7: "FACCH/H"}.get(channel, "unknown"),
            "diagnostic_message_type": diagnostic_type, "l3_length": declared,
            "pseudo_length_bytes": pseudo, "packet_version_present": False,
        },
        "rr_payload_hex": l3.hex(),
    }
    semantic = message_type in {PAGING_RESPONSE, CIPHERING_MODE_COMMAND, CIPHERING_MODE_COMPLETE}
    if not semantic:
        result["rr"] = {"status": "preserved-unsupported", "message": names.get(message_type, f"RR_MESSAGE_{message_type}"), "message_type": message_type, "protocol_discriminator": protocol, "payload_length": len(l3)}
        return result
    if channel != 0 or pseudo:
        raise ValueError(f"{names[message_type]} requires the DCCH 0x5B2F channel")
    if message_type == PAGING_RESPONSE:
        if downlink:
            raise ValueError("Paging Response requires uplink direction")
        result["rr"] = _decode_paging_response(l3)
    else:
        if (message_type == CIPHERING_MODE_COMMAND) != downlink:
            raise ValueError("Ciphering Mode direction does not match message type")
        result["rr"] = _decode_ciphering(l3)
    return result
