"""Dependency-free TS 36.331 Release-14 UPER decoder for observed LTE RRC messages."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any


TRANSPORTS = {
    1: ("BCCH-BCH", "DOWNLINK", "BCCH_BCH_Message"),
    2: ("BCCH-DL-SCH", "DOWNLINK", "BCCH_DL_SCH_Message"),
    4: ("MCCH", "DOWNLINK", None),
    5: ("PCCH", "DOWNLINK", "PCCH_Message"),
    6: ("DL-CCCH", "DOWNLINK", "DL_CCCH_Message"),
    7: ("DL-DCCH", "DOWNLINK", "DL_DCCH_Message"),
    8: ("UL-CCCH", "UPLINK", "UL_CCCH_Message"),
    9: ("UL-DCCH", "UPLINK", "UL_DCCH_Message"),
}
DL_CCCH = ["RRC_CONNECTION_REESTABLISHMENT", "RRC_CONNECTION_REESTABLISHMENT_REJECT", "RRC_CONNECTION_REJECT", "RRC_CONNECTION_SETUP"]
DL_DCCH = ["CSFB_PARAMETERS_RESPONSE_CDMA2000", "DL_INFORMATION_TRANSFER", "HANDOVER_FROM_EUTRA_PREPARATION_REQUEST", "MOBILITY_FROM_EUTRA_COMMAND", "RRC_CONNECTION_RECONFIGURATION", "RRC_CONNECTION_RELEASE", "SECURITY_MODE_COMMAND", "UE_CAPABILITY_ENQUIRY", "COUNTER_CHECK", "UE_INFORMATION_REQUEST_R9", "LOGGED_MEASUREMENT_CONFIGURATION_R10", "RN_RECONFIGURATION_R10", "RRC_CONNECTION_RESUME_R13"]
UL_DCCH = ["CSFB_PARAMETERS_REQUEST_CDMA2000", "MEASUREMENT_REPORT", "RRC_CONNECTION_RECONFIGURATION_COMPLETE", "RRC_CONNECTION_REESTABLISHMENT_COMPLETE", "RRC_CONNECTION_SETUP_COMPLETE", "SECURITY_MODE_COMPLETE", "SECURITY_MODE_FAILURE", "UE_CAPABILITY_INFORMATION", "UL_HANDOVER_PREPARATION_TRANSFER", "UL_INFORMATION_TRANSFER", "COUNTER_CHECK_RESPONSE", "UE_INFORMATION_RESPONSE_R9", "PROXIMITY_INDICATION_R9", "RN_RECONFIGURATION_COMPLETE_R10", "MBMS_COUNTING_RESPONSE_R10", "INTER_FREQ_RSTD_MEASUREMENT_INDICATION_R10"]
FULL_TREE_MESSAGES = {"SYSTEM_INFORMATION_BLOCK_TYPE1", "SYSTEM_INFORMATION", "PAGING", "RRC_CONNECTION_SETUP", "RRC_CONNECTION_REQUEST", "RRC_CONNECTION_RECONFIGURATION", "RRC_CONNECTION_RELEASE", "SECURITY_MODE_COMMAND", "UE_CAPABILITY_ENQUIRY", "MEASUREMENT_REPORT", "RRC_CONNECTION_RECONFIGURATION_COMPLETE", "RRC_CONNECTION_SETUP_COMPLETE", "SECURITY_MODE_COMPLETE", "UE_CAPABILITY_INFORMATION"}


class _Bits:
    def __init__(self, value: bytes):
        self.value, self.position = bytes(value), 0

    @property
    def remaining(self) -> int:
        return len(self.value) * 8 - self.position

    def bit(self) -> int:
        if self.position >= len(self.value) * 8: raise ValueError("truncated UPER value")
        result = (self.value[self.position >> 3] >> (7 - (self.position & 7))) & 1
        self.position += 1
        return result

    def bits(self, count: int) -> int:
        if count < 0: raise ValueError("invalid bit count")
        result = 0
        for _ in range(count): result = (result << 1) | self.bit()
        return result

    def octets(self, count: int) -> bytes:
        if count < 0 or count > self.remaining // 8: raise ValueError("truncated UPER octets")
        return bytes(self.bits(8) for _ in range(count))


@lru_cache(maxsize=1)
def _schema() -> dict[str, Any]:
    path = Path(__file__).with_name("lte_rrc_release14_schema.json")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as failure:
        raise ValueError(f"unable to load vendored LTE RRC schema: {failure}") from failure


def _range_bits(count: int) -> int:
    return 0 if count <= 1 else (count - 1).bit_length()


class _SchemaDecoder:
    def __init__(self):
        self.schema = _schema()

    def decode(self, root: str, payload: bytes) -> Any:
        node = self.schema["roots"].get(root)
        if node is None: raise ValueError(f"missing RRC schema root {root}")
        bits = _Bits(payload)
        result = self._node(node, bits)
        while bits.remaining:
            if bits.bit(): raise ValueError(f"non-zero trailing bits after {root}")
        return result

    def _node(self, index: int, bits: _Bits) -> Any:
        node = self.schema["nodes"][index]
        try:
            kind = node["type"]
            if kind == "SEQUENCE": return self._sequence(node, bits)
            if kind == "CHOICE": return self._choice(node, bits)
            if kind == "SEQUENCE OF": return [self._node(node["item"], bits) for _ in range(self._length(node.get("sizeConstraint"), bits))]
            if kind == "INTEGER": return self._integer(node, bits)
            if kind == "ENUMERATED": return self._enumerated(node, bits)
            if kind == "BIT STRING":
                length = self._length(node.get("sizeConstraint"), bits); return [bits.bits(length), length]
            if kind == "OCTET STRING": return bits.octets(self._length(node.get("sizeConstraint"), bits)).hex()
            if kind == "BOOLEAN": return bool(bits.bit())
            if kind == "NULL": return 0
            raise ValueError(f"unsupported ASN.1 type {kind}")
        except (KeyError, TypeError, ValueError) as failure:
            raise ValueError(f"{node.get('name')}({node.get('type')}): {failure} at bit {bits.position}") from failure

    def _child(self, node: dict[str, Any], name: str) -> int:
        try: return node["children"][name]
        except KeyError as failure: raise ValueError(f"missing schema child {name}") from failure

    def _sequence(self, node: dict[str, Any], bits: _Bits) -> dict[str, Any]:
        value: dict[str, Any] = {}
        extended = bool(node.get("extensible") and bits.bit())
        optional = node.get("rootOptional", [])
        bitmap = bits.bits(len(optional)) if optional else 0
        mandatory = set(node.get("rootMandatory", []))
        for name in node.get("root", []):
            present = name in mandatory
            if name in optional: present = bool(bitmap & (1 << (len(optional) - 1 - optional.index(name))))
            child = self._child(node, name); child_node = self.schema["nodes"][child]
            if present: value[name] = self._node(child, bits)
            elif child_node.get("default") is not None: value[name] = child_node["default"]
        if extended: self._extensions(node, bits, value)
        return value

    def _extensions(self, node: dict[str, Any], bits: _Bits, value: dict[str, Any]) -> None:
        count = self._normally_small(bits) + 1
        present = [bool(bits.bit()) for _ in range(count)]
        nesting = node.get("extensionNesting", [])
        for index, enabled in enumerate(present):
            if not enabled: continue
            opened = self._open(bits)
            if index >= len(nesting): value[f"_unknownExtension{index}"] = opened.hex(); continue
            item = nesting[index]; nested = _Bits(opened)
            if isinstance(item, str): value[item] = self._node(self._child(node, item), nested)
            elif isinstance(item, list) and item:
                groups = node.get("extensionGroups", {})
                group_node = groups.get(str(index), groups.get(str(item[0])))
                if group_node is None: value[f"_extensionGroup{index}"] = opened.hex()
                else:
                    decoded = self._node(group_node, nested)
                    if isinstance(decoded, dict): value.update(decoded)

    def _choice(self, node: dict[str, Any], bits: _Bits) -> list[Any]:
        extension = bool(node.get("extensible") and bits.bit())
        if extension:
            index, opened = self._normally_small(bits), self._open(bits)
            extensions = node.get("extensions", [])
            if index >= len(extensions): return [f"_unknownExtension{index}", opened.hex()]
            name = extensions[index]; return [name, self._node(self._child(node, name), _Bits(opened))]
        root = node.get("root", []); index = self._index(bits, len(root)); name = root[index]
        return [name, self._node(self._child(node, name), bits)]

    def _integer(self, node: dict[str, Any], bits: _Bits) -> int:
        constraint = node.get("valueConstraint")
        if constraint and constraint.get("extensible") and bits.bit(): return self._unconstrained_integer(bits)
        if constraint and constraint.get("lb") is not None and constraint.get("ub") is not None:
            low, high = constraint["lb"], constraint["ub"]
            return low if low == high else low + bits.bits(_range_bits(high - low + 1))
        if constraint and constraint.get("lb") is not None: return constraint["lb"] + self._unsigned(bits)
        return self._unconstrained_integer(bits)

    def _enumerated(self, node: dict[str, Any], bits: _Bits) -> str:
        if node.get("extensible") and bits.bit():
            index = self._normally_small(bits); extensions = node.get("extensions", [])
            return extensions[index] if index < len(extensions) else f"_unknownExtension{index}"
        root = node.get("root", []); return root[self._index(bits, len(root))]

    def _length(self, constraint: dict[str, Any] | None, bits: _Bits) -> int:
        if constraint and constraint.get("extensible") and bits.bit(): return self._unconstrained_length(bits)
        if constraint and constraint.get("lb") is not None and constraint.get("ub") is not None and constraint["ub"] < 65_536:
            low, high = constraint["lb"], constraint["ub"]
            return low if low == high else low + bits.bits(_range_bits(high - low + 1))
        return self._unconstrained_length(bits)

    @staticmethod
    def _unconstrained_length(bits: _Bits) -> int:
        first = bits.bits(8)
        if not first & 0x80: return first
        if not first & 0x40: return ((first & 0x3F) << 8) | bits.bits(8)
        raise ValueError("fragmented UPER length is outside captured scope")

    def _normally_small(self, bits: _Bits) -> int:
        return bits.bits(6) if not bits.bit() else self._unsigned(bits)

    def _unsigned(self, bits: _Bits) -> int:
        return bits.bits(self._unconstrained_length(bits) * 8)

    def _unconstrained_integer(self, bits: _Bits) -> int:
        raw = bits.octets(self._unconstrained_length(bits))
        return int.from_bytes(raw, "big", signed=True) if raw else 0

    def _open(self, bits: _Bits) -> bytes:
        return bits.octets(self._unconstrained_length(bits))

    @staticmethod
    def _index(bits: _Bits, count: int) -> int:
        if count < 1: raise ValueError("empty constrained set")
        index = 0 if count == 1 else bits.bits(_range_bits(count))
        if index >= count: raise ValueError(f"invalid constrained index {index}")
        return index


def _status(status: str, transport: tuple[str, str, str | None], message: str, detail: str, fields: dict[str, Any] | None = None, transaction: int | None = None) -> dict[str, Any]:
    label, direction, _ = transport
    value: dict[str, Any] = {"status": status, "message": message, "transport": label, "direction": direction}
    if transaction is not None: value["transaction_id"] = transaction
    if fields: value.update(fields)
    value["detail"] = detail
    return value


def decode_rrc(pdu_number: int, payload: bytes) -> dict[str, Any]:
    transport = TRANSPORTS.get(pdu_number)
    if transport is None: return {"status": "UNSUPPORTED", "message": "UNSUPPORTED_RRC_TRANSPORT", "detail": f"unsupported LTE RRC transport {pdu_number}"}
    if not payload: return _status("MALFORMED", transport, "MALFORMED_RRC", "empty UPER payload")
    bits, message, transaction = _Bits(payload), "", None
    fields: dict[str, Any] = {}
    try:
        if pdu_number == 1: message = "MASTER_INFORMATION_BLOCK"; fields["semantic_depth"] = "message-and-core-fields"
        elif pdu_number == 4: return _status("UNSUPPORTED", transport, "UNSUPPORTED_RRC_BRANCH", "MCCH Release-14 branch is not in the proven corpus")
        elif pdu_number == 2:
            if bits.bit(): return _status("UNSUPPORTED", transport, "UNSUPPORTED_RRC_BRANCH", "messageClassExtension")
            choice = bits.bit(); message = "SYSTEM_INFORMATION" if choice == 0 else "SYSTEM_INFORMATION_BLOCK_TYPE1"
            fields.update(semantic_depth="message-classified", asn1_payload="SystemInformation" if choice == 0 else "SystemInformationBlockType1")
        elif pdu_number == 5:
            if bits.bit(): return _status("UNSUPPORTED", transport, "UNSUPPORTED_RRC_BRANCH", "messageClassExtension")
            message = "PAGING"; fields["semantic_depth"] = "message-classified"
        elif pdu_number == 8:
            if bits.bit(): return _status("UNSUPPORTED", transport, "UNSUPPORTED_RRC_BRANCH", "messageClassExtension")
            message = "RRC_CONNECTION_REESTABLISHMENT_REQUEST" if bits.bit() == 0 else "RRC_CONNECTION_REQUEST"; fields["semantic_depth"] = "message-classified"
        else:
            if bits.bit(): return _status("UNSUPPORTED", transport, "UNSUPPORTED_RRC_BRANCH", "messageClassExtension")
            names, width = (DL_CCCH, 2) if pdu_number == 6 else ((DL_DCCH, 4) if pdu_number == 7 else (UL_DCCH, 4))
            choice = bits.bits(width)
            if choice >= len(names): return _status("UNSUPPORTED", transport, "UNSUPPORTED_RRC_BRANCH", f"unsupported c1 choice {choice}")
            message = names[choice]; transaction = bits.bits(2) if bits.remaining >= 2 else None
            fields.update(c1_choice=choice, semantic_depth="message-and-transaction-id")
        fields.update(direction=transport[1], remaining_uper_bits=bits.remaining)
    except ValueError as failure:
        return _status("MALFORMED", transport, "MALFORMED_RRC", str(failure))
    if message in FULL_TREE_MESSAGES:
        try:
            fields["asn1_tree"] = _SchemaDecoder().decode(transport[2], payload)
            fields["semantic_depth"] = "full-observed-message-tree"
            detail = "TS 36.331 Release-14 full observed message tree decoded"
        except ValueError as failure:
            fields["semantic_depth"] = "message-family-fallback"; fields["field_tree_error"] = str(failure)
            detail = "Message family decoded; full field tree rejected safely"
    else: detail = "TS 36.331 Release-14 top-level UPER decoded"
    return _status("DECODED", transport, message, detail, fields, transaction)
