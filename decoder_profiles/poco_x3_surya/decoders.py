"""Poco adapters, reusing the bundled shared protocol modules."""
from __future__ import annotations
from typing import Any, Iterator
from decoder_modules import nsg_decode_random_access, nsg_geran, nsg_gmm, nsg_lte_records, nsg_nas, nsg_parse_lte, nsg_schema_registry
from decoder_core.capture import json_safe, UnsupportedPacket

RA_IDS = {0xB061, 0xB062, 0xB167, 0xB168, 0xB169, 0xB16A}
RA_SCHEMAS = {
    0xB061: "lte-mac-rach-trigger-b061-v1-sub05-v2",
    0xB062: "lte-mac-rach-attempt-b062-v1-sub06-v3",
    0xB167: "lte-ml1-prach-msg1-b167-v25",
    0xB168: "lte-ml1-rar-msg2-b168-v24",
    0xB169: "lte-ml1-msg3-b169-v24",
    0xB16A: "lte-ml1-contention-msg4-b16a-v1",
}
SPECIAL_SIGNAL_NAMES = {
    0x5B2F: "GERAN RR DSDS signaling",
    0x5C30: "GPRS DSDS SM/GMM signaling",
}


class ReferenceDecoders:
    """Dispatches through the tool's vendored Python decoder package."""

    def __init__(self, schemas=None):
        self.registry = nsg_schema_registry
        self.lte_records = nsg_lte_records
        self.nas = nsg_nas
        self.diag = nsg_parse_lte
        self.random_access = nsg_decode_random_access
        self.geran = nsg_geran
        self.gmm = nsg_gmm

    def frames(self, payload: bytes) -> Iterator[tuple[bytes, int, bool]]:
        for frame, log_id in self.diag.log_frames(payload, strict=False):
            yield frame, log_id, self.diag.valid_diag_log_frame(frame)

    def signal_name(self, log_id: int) -> str:
        """Return the existing decoder label for a Qualcomm signal ID."""
        return (
            self.diag.PROTOCOL_NAMES.get(log_id)
            or self.diag.LOG_NAMES.get(log_id)
            or SPECIAL_SIGNAL_NAMES.get(log_id)
            or "Unclassified signal"
        )

    def decode(self, frame: bytes, log_id: int) -> tuple[str, dict[str, Any]]:
        body = frame[24:-2]
        if log_id == 0x5B2F:
            return "geran-rr-dsds-signaling-5b2f-unversioned", self.geran.decode_5b2f(body)
        if log_id == 0x5C30:
            return "gprs-dsds-sm-gmm-signaling-5c30-unversioned", self.gmm.decode_5c30(body)
        if log_id in RA_IDS:
            return RA_SCHEMAS[log_id], self._decode_random_access(log_id, body)

        selection = self.registry.probe_record(log_id, body)
        if not selection.selected:
            if selection.status == "invalid-length":
                raise ValueError(selection.reason)
            raise UnsupportedPacket(f"{selection.status}: {selection.reason}")

        decoder_name = selection.decoder
        if decoder_name == "decode_b0c0_rrc_v20":
            value = self.diag.decode_b0c0_rrc(frame)
        elif decoder_name == "decode_b17f_v5":
            value = self.diag.decode_b17f(frame)
        elif decoder_name == "decode_b193_sub19_v39":
            value = self.diag.decode_b193_v39(frame)
        elif decoder_name == "decode_lte_nas_ota_v1":
            value = self.nas.extract_qualcomm_nas(
                {
                    "log_id": f"0x{log_id:04X}",
                    "body_hex": body.hex(),
                }
            )
        else:
            value = self.lte_records.decode_record(log_id, body)
        if value is None:
            raise ValueError(f"{decoder_name} rejected the selected packet layout")
        return selection.schema_id, json_safe(value)

    def _decode_random_access(self, log_id: int, body: bytes) -> dict[str, Any]:
        decoder = self.random_access
        if log_id == 0xB061:
            return json_safe(decoder.decode_b061(body))
        if log_id == 0xB062:
            return json_safe(decoder.decode_b062(body, 100, None))
        if log_id == 0xB167:
            return json_safe(decoder.decode_b167(body))
        if log_id == 0xB168:
            return json_safe(decoder.decode_b168(body))
        if log_id == 0xB169:
            return json_safe(decoder.decode_b169(body, 100))
        return json_safe(decoder.decode_b16a(body))
