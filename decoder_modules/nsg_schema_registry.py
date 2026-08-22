#!/usr/bin/env python3
"""Central, version-aware Qualcomm DIAG schema selection for the target Poco X3."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable


TARGET_PROFILE_ID = "poco-x3-surya-v14.0.2.0"
TARGET_MODEL = "M2007J20CG"
TARGET_DEVICE = "surya"
TARGET_FIRMWARE = "V14.0.2.0.SJGMIXM"
TARGET_BASEBAND = "SS.AT.4.4.c6-00071-RENNELL_GEN_PACK-3.30805.6"


@dataclass(frozen=True)
class DeviceIdentity:
    model: str
    device: str
    firmware: str
    baseband: str


TARGET_IDENTITY = DeviceIdentity(
    model=TARGET_MODEL,
    device=TARGET_DEVICE,
    firmware=TARGET_FIRMWARE,
    baseband=TARGET_BASEBAND,
)


@dataclass(frozen=True)
class SchemaSpec:
    schema_id: str
    log_id: int
    decoder: str
    packet_version: int
    min_length: int
    max_length: int | None = None
    subpacket_id: int | None = None
    subpacket_version: int | None = None
    declared_length_prefix: int | None = None
    profile_id: str = TARGET_PROFILE_ID


@dataclass(frozen=True)
class SchemaSelection:
    status: str
    log_id: str
    packet_version: int | None
    body_length: int
    schema_id: str | None = None
    decoder: str | None = None
    subpacket_id: int | None = None
    subpacket_version: int | None = None
    profile_id: str | None = None
    reason: str | None = None

    @property
    def selected(self) -> bool:
        return self.status == "selected"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def identity_matches(identity: DeviceIdentity) -> bool:
    """Require this project's exact device and firmware/baseband family."""
    basebands = {part.strip() for part in identity.baseband.split(",") if part.strip()}
    return (
        identity.model == TARGET_MODEL
        and identity.device == TARGET_DEVICE
        and identity.firmware == TARGET_FIRMWARE
        and TARGET_BASEBAND in basebands
    )


NAS_IDS = (0xB0E0, 0xB0E1, 0xB0E2, 0xB0E3, 0xB0EA, 0xB0EB, 0xB0EC, 0xB0ED)


SCHEMAS: tuple[SchemaSpec, ...] = (
    SchemaSpec("lte-rrc-ota-b0c0-v20", 0xB0C0, "decode_b0c0_rrc_v20", 20, 19),
    SchemaSpec("lte-ml1-serving-b17f-v5", 0xB17F, "decode_b17f_v5", 5, 36),
    SchemaSpec(
        "lte-ml1-serving-b193-sub19-v39",
        0xB193,
        "decode_b193_sub19_v39",
        1,
        20,
        subpacket_id=0x19,
        subpacket_version=39,
        declared_length_prefix=4,
    ),
    *tuple(
        SchemaSpec(
            f"lte-nas-ota-{log_id:04x}-v1",
            log_id,
            "decode_lte_nas_ota_v1",
            1,
            4,
        )
        for log_id in NAS_IDS
    ),
    SchemaSpec(
        "lte-mac-rach-trigger-b061-v1-sub05-v2",
        0xB061,
        "decode_b061_sub05_v2",
        1,
        17,
        subpacket_id=0x05,
        subpacket_version=2,
    ),
    SchemaSpec(
        "lte-mac-rach-attempt-b062-v1-sub06-v3",
        0xB062,
        "decode_b062_sub06_v3",
        1,
        6,
        subpacket_id=0x06,
        subpacket_version=3,
    ),
    SchemaSpec("lte-ml1-prach-msg1-b167-v25", 0xB167, "decode_b167_v25", 25, 32),
    SchemaSpec("lte-ml1-rar-msg2-b168-v24", 0xB168, "decode_b168_v24", 24, 12),
    SchemaSpec("lte-ml1-msg3-b169-v24", 0xB169, "decode_b169_v24", 24, 12),
    SchemaSpec("lte-ml1-contention-msg4-b16a-v1", 0xB16A, "decode_b16a_v1", 1, 8),
    SchemaSpec("lte-rrc-mib-b0c1-v2", 0xB0C1, "decode_b0c1_v2", 2, 11, 11),
    SchemaSpec(
        "lte-rrc-serving-cell-b0c2-v3",
        0xB0C2,
        "decode_b0c2_v3",
        3,
        29,
        29,
    ),
    SchemaSpec(
        "lte-nas-esm-state-b0e5-v1",
        0xB0E5,
        "decode_b0e5_v1",
        1,
        20,
        20,
    ),
    SchemaSpec(
        "lte-nas-emm-state-b0ee-v2",
        0xB0EE,
        "decode_b0ee_v2",
        2,
        19,
        19,
    ),
    SchemaSpec(
        "lte-mac-ul-tx-stats-b067-v1-sub0b-v2",
        0xB067,
        "decode_b067_v1_sub0b_v2",
        1,
        24,
        24,
        subpacket_id=0x0B,
        subpacket_version=2,
    ),
    SchemaSpec(
        "lte-rlc-dl-am-all-pdu-b082-v1-sub41-v3",
        0xB082,
        "decode_b082_v1_sub41_v3",
        1,
        24,
        subpacket_id=0x41,
        subpacket_version=3,
        declared_length_prefix=4,
    ),
    SchemaSpec(
        "lte-rlc-ul-am-all-pdu-b092-v1-sub46-v3",
        0xB092,
        "decode_b092_v1_sub46_v3",
        1,
        28,
        subpacket_id=0x46,
        subpacket_version=3,
        declared_length_prefix=4,
    ),
    SchemaSpec(
        "lte-pdcp-dl-cipher-pdu-b0a3-v1-subc3-v24",
        0xB0A3,
        "decode_b0a3_v1_subc3_v24",
        1,
        44,
        subpacket_id=0xC3,
        subpacket_version=24,
        declared_length_prefix=4,
    ),
    SchemaSpec(
        "lte-pdcp-ul-cipher-pdu-b0b3-v1-subc3-v26",
        0xB0B3,
        "decode_b0b3_v1_subc3_v26",
        1,
        44,
        subpacket_id=0xC3,
        subpacket_version=26,
        declared_length_prefix=4,
    ),
    SchemaSpec(
        "lte-phy-pusch-tx-report-b139-v124",
        0xB139,
        "decode_b139_v124",
        124,
        8,
    ),
    SchemaSpec(
        "lte-phy-pucch-csf-b14d-v103",
        0xB14D,
        "decode_b14d_v103",
        103,
        12,
        12,
    ),
    SchemaSpec(
        "lte-phy-pusch-csf-b14e-v103",
        0xB14E,
        "decode_b14e_v103",
        103,
        36,
        36,
    ),
    SchemaSpec(
        "lte-phy-pdcch-decoding-b130-v123",
        0xB130,
        "decode_b130_v123",
        123,
        12,
    ),
    SchemaSpec(
        "lte-phy-connected-intra-frequency-b179-v4",
        0xB179,
        "decode_b179_v4",
        4,
        28,
    ),
    SchemaSpec(
        "lte-phy-idle-neighbor-measurement-b192-v1",
        0xB192,
        "decode_b192_v1",
        1,
        28,
    ),
    SchemaSpec(
        "lte-phy-connected-neighbor-measurement-b195-v1",
        0xB195,
        "decode_b195_v1",
        1,
        100,
    ),
    SchemaSpec(
        "lte-mac-dl-transport-block-b063-v1-sub07-v4",
        0xB063,
        "decode_b063_v1_sub07_v4",
        1,
        8,
        subpacket_id=0x07,
        subpacket_version=4,
        declared_length_prefix=4,
    ),
    SchemaSpec(
        "lte-mac-ul-transport-block-b064-v1-sub08-v2",
        0xB064,
        "decode_b064_v1_sub08_v2",
        1,
        8,
        subpacket_id=0x08,
        subpacket_version=2,
        declared_length_prefix=4,
    ),
    SchemaSpec(
        "geran-rr-dsds-signaling-5b2f-unversioned",
        0x5B2F,
        "decode_5b2f_dsds_rr",
        0,
        6,
        259,
    ),
    SchemaSpec(
        "gprs-dsds-sm-gmm-signaling-5c30-unversioned",
        0x5C30,
        "decode_5c30_dsds_sm_gmm",
        0,
        257,
        65_790,
    ),
)


def schemas_for(log_id: int) -> tuple[SchemaSpec, ...]:
    return tuple(schema for schema in SCHEMAS if schema.log_id == log_id)


def select_schema(
    *,
    log_id: int,
    packet_version: int | None,
    body_length: int,
    subpacket_id: int | None = None,
    subpacket_version: int | None = None,
    declared_length: int | None = None,
    identity: DeviceIdentity = TARGET_IDENTITY,
) -> SchemaSelection:
    """Choose one exact schema, otherwise return a lossless-fallback reason."""
    common = {
        "log_id": f"0x{log_id:04X}",
        "packet_version": packet_version,
        "body_length": body_length,
        "subpacket_id": subpacket_id,
        "subpacket_version": subpacket_version,
    }
    candidates = schemas_for(log_id)
    if not candidates:
        return SchemaSelection(
            status="unsupported-log-id",
            reason="no registered schema for this Qualcomm log ID",
            **common,
        )
    if not identity_matches(identity):
        return SchemaSelection(
            status="unsupported-device-profile",
            reason=(
                "device/firmware/baseband does not match the validated "
                f"{TARGET_PROFILE_ID} profile"
            ),
            **common,
        )
    version_matches = [
        schema
        for schema in candidates
        if schema.packet_version == packet_version
        and schema.subpacket_id == subpacket_id
        and schema.subpacket_version == subpacket_version
    ]
    if not version_matches:
        expected = ", ".join(
            f"packet={schema.packet_version}"
            + (
                f",sub={schema.subpacket_id:#04x}/v{schema.subpacket_version}"
                if schema.subpacket_id is not None
                else ""
            )
            for schema in candidates
        )
        return SchemaSelection(
            status="unsupported-version",
            reason=f"observed version tuple is not registered; expected {expected}",
            profile_id=TARGET_PROFILE_ID,
            **common,
        )
    length_matches: list[SchemaSpec] = []
    length_reasons = []
    for schema in version_matches:
        if body_length < schema.min_length:
            length_reasons.append(
                f"{schema.schema_id} requires at least {schema.min_length} bytes"
            )
            continue
        if schema.max_length is not None and body_length > schema.max_length:
            length_reasons.append(
                f"{schema.schema_id} permits at most {schema.max_length} bytes"
            )
            continue
        if declared_length is not None and schema.declared_length_prefix is not None:
            declared_end = schema.declared_length_prefix + declared_length
            if declared_end > body_length:
                length_reasons.append(
                    f"{schema.schema_id} declares end {declared_end} beyond "
                    f"{body_length} available bytes"
                )
                continue
        length_matches.append(schema)
    if not length_matches:
        return SchemaSelection(
            status="invalid-length",
            reason="; ".join(length_reasons),
            profile_id=TARGET_PROFILE_ID,
            **common,
        )
    if len(length_matches) != 1:
        return SchemaSelection(
            status="ambiguous-schema",
            reason="more than one registered schema matched",
            profile_id=TARGET_PROFILE_ID,
            **common,
        )
    schema = length_matches[0]
    return SchemaSelection(
        status="selected",
        schema_id=schema.schema_id,
        decoder=schema.decoder,
        profile_id=schema.profile_id,
        **common,
    )


def probe_record(
    log_id: int,
    body: bytes,
    *,
    identity: DeviceIdentity = TARGET_IDENTITY,
) -> SchemaSelection:
    """Extract this profile's routing tuple from a complete log body."""
    packet_version = 0 if log_id in {0x5B2F, 0x5C30} else (body[0] if body else None)
    if log_id == 0xB193 and len(body) >= 8:
        return select_schema(
            log_id=log_id,
            packet_version=packet_version,
            body_length=len(body),
            subpacket_id=body[4],
            subpacket_version=body[5],
            declared_length=int.from_bytes(body[6:8], "little"),
            identity=identity,
        )
    if log_id in {
        0xB063,
        0xB064,
        0xB067,
        0xB082,
        0xB092,
        0xB0A3,
        0xB0B3,
    } and len(body) >= 8:
        return select_schema(
            log_id=log_id,
            packet_version=packet_version,
            body_length=len(body),
            subpacket_id=body[4],
            subpacket_version=body[5],
            declared_length=int.from_bytes(body[6:8], "little"),
            identity=identity,
        )
    return select_schema(
        log_id=log_id,
        packet_version=packet_version,
        body_length=len(body),
        identity=identity,
    )


def registry_manifest() -> list[dict[str, Any]]:
    return [asdict(schema) for schema in SCHEMAS]


def supported_log_ids() -> Iterable[int]:
    return sorted({schema.log_id for schema in SCHEMAS})
