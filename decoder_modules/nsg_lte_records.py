#!/usr/bin/env python3
"""Pure decoders for additional LTE Qualcomm DIAG records on Poco X3.

The functions in this module have no capture, UI, service, or global project
state.  Each accepts one complete Qualcomm log body and returns plain Python
data, making the layouts directly portable to a JNI/C++ decoder library.

Layout source:
  MobileInsight mobileinsight-core, Apache-2.0, revision
  4330fa9c2df0b090128652546440f63f151af55f.

Only packet versions and lengths observed on the validated Poco X3 target are
accepted.  Unknown layouts raise DecodeError instead of being guessed.
"""

from __future__ import annotations

from typing import Any, Callable


class DecodeError(ValueError):
    """The body does not match the exact registered Qualcomm layout."""


def _require(body: bytes, *, version: int, minimum: int, exact: int | None = None) -> None:
    if not body:
        raise DecodeError("empty Qualcomm log body")
    if body[0] != version:
        raise DecodeError(f"unsupported packet version {body[0]}; expected {version}")
    if len(body) < minimum:
        raise DecodeError(f"truncated body: {len(body)} bytes; need at least {minimum}")
    if exact is not None and len(body) != exact:
        raise DecodeError(f"invalid body length {len(body)}; expected exactly {exact}")


def _u16(body: bytes, offset: int) -> int:
    return int.from_bytes(body[offset : offset + 2], "little")


def _u32(body: bytes, offset: int) -> int:
    return int.from_bytes(body[offset : offset + 4], "little")


def _u64(body: bytes, offset: int) -> int:
    return int.from_bytes(body[offset : offset + 8], "little")


def _i16(body: bytes, offset: int) -> int:
    return int.from_bytes(body[offset : offset + 2], "little", signed=True)


def _sfn_sf(value: int) -> dict[str, int]:
    return {
        "raw": value,
        "subframe": value & 0xF,
        "system_frame_number": (value >> 4) & 0x3FF,
    }


def _plmn_mk2(raw: bytes) -> str:
    if len(raw) != 3:
        raise DecodeError("PLMN must contain three bytes")
    last_digit = (raw[1] >> 4) & 0xF
    mcc = f"{raw[0] & 0xF}{(raw[0] >> 4) & 0xF}{raw[1] & 0xF}"
    mnc = f"{raw[2] & 0xF}{(raw[2] >> 4) & 0xF}"
    if last_digit < 10:
        mnc += str(last_digit)
    return f"{mcc}-{mnc}"


def _bandwidth(raw: int) -> dict[str, int | float]:
    return {"code": raw, "mhz": raw / 5.0}


def decode_b0c1_v2(body: bytes) -> dict[str, Any]:
    """Decode LTE RRC MIB Message Log Packet 0xB0C1 version 2."""
    _require(body, version=2, minimum=11, exact=11)
    return {
        "log_id": "0xB0C1",
        "packet_version": 2,
        "physical_cell_id": _u16(body, 1),
        "dl_earfcn": _u32(body, 3),
        "system_frame_number": _u16(body, 7),
        "number_of_antennas": body[9],
        "downlink_bandwidth": _bandwidth(body[10]),
    }


def decode_b0c2_v3(body: bytes) -> dict[str, Any]:
    """Decode LTE RRC Serving Cell Info Log Packet 0xB0C2 version 3."""
    _require(body, version=3, minimum=29, exact=29)
    return {
        "log_id": "0xB0C2",
        "packet_version": 3,
        "physical_cell_id": _u16(body, 1),
        "downlink_earfcn": _u32(body, 3),
        "uplink_earfcn": _u32(body, 7),
        "downlink_bandwidth": _bandwidth(body[11]),
        "uplink_bandwidth": _bandwidth(body[12]),
        "e_utran_cell_identity": _u32(body, 13),
        "tracking_area_code": _u16(body, 17),
        "lte_band": _u32(body, 19),
        "mcc": _u16(body, 23),
        "mnc_digits": body[25],
        "mnc": _u16(body, 26),
        "allowed_access_raw": body[28],
    }


EMM_STATE_NAMES = {
    0: "EMM_NULL",
    1: "EMM_DEREGISTERED",
    2: "EMM_REGISTERED_INITIATED",
    3: "EMM_REGISTERED",
    4: "EMM_TRACKING_AREA_UPDATING_INITIATED",
    5: "EMM_SERVICE_REQUEST_INITIATED",
    6: "EMM_DEREGISTERED_INITIATED",
}

EMM_SUBSTATE_NAMES = {
    1: {
        0: "EMM_DEREGISTERED_NO_IMSI",
        1: "EMM_DEREGISTERED_PLMN_SEARCH",
        2: "EMM_DEREGISTERED_ATTACH_NEEDED",
        3: "EMM_DEREGISTERED_NO_CELL_AVAILABLE",
        4: "EMM_DEREGISTERED_ATTEMPTING_TO_ATTACH",
        5: "EMM_DEREGISTERED_NORMAL_SERVICE",
        6: "EMM_DEREGISTERED_LIMITED_SERVICE",
    },
    2: {
        0: "EMM_WAITING_FOR_NW_RESPONSE",
        1: "EMM_WAITING_FOR_ESM_RESPONSE",
    },
    3: {
        0: "EMM_REGISTERED_NORMAL_SERVICE",
        1: "EMM_REGISTERED_UPDATE_NEEDED",
        2: "EMM_REGISTERED_ATTEMPTING_TO_UPDATE",
        3: "EMM_REGISTERED_NO_CELL_AVAILABLE",
        4: "EMM_REGISTERED_PLMN_SEARCH",
        5: "EMM_REGISTERED_LIMITED_SERVICE",
    },
}


def decode_b0ee_v2(body: bytes) -> dict[str, Any]:
    """Decode LTE NAS EMM State 0xB0EE version 2."""
    _require(body, version=2, minimum=19, exact=19)
    state = body[1]
    substate = _u16(body, 2)
    substate_table = EMM_SUBSTATE_NAMES.get(3 if state in {4, 5} else state, {})
    return {
        "log_id": "0xB0EE",
        "packet_version": 2,
        "emm_state": state,
        "emm_state_name": EMM_STATE_NAMES.get(state, "UNKNOWN"),
        "emm_substate": substate,
        "emm_substate_name": substate_table.get(substate, "UNDEFINED"),
        "plmn": _plmn_mk2(body[4:7]),
        "guti_valid": body[7],
        "guti_ue_id": body[8],
        "guti_plmn": _plmn_mk2(body[9:12]),
        "guti_mme_group_id_hex": body[12:14].hex(),
        "guti_mme_code_hex": body[14:15].hex(),
        "guti_m_tmsi_hex": body[15:19].hex(),
    }


def decode_b0e5_v1(body: bytes) -> dict[str, Any]:
    """Decode LTE NAS ESM bearer state 0xB0E5 version 1."""
    _require(body, version=1, minimum=20, exact=20)
    return {
        "log_id": "0xB0E5",
        "packet_version": 1,
        "eps_bearer_type": body[1],
        "eps_bearer_id": body[2],
        "eps_bearer_state": body[3],
        "qos_length": body[10],
        "qci": body[11],
        "ul_mbr": body[12],
        "dl_mbr": body[13],
        "ul_gbr": body[14],
        "dl_gbr": body[15],
        "ul_mbr_ext": body[16],
        "dl_mbr_ext": body[17],
        "ul_gbr_ext": body[18],
        "dl_gbr_ext": body[19],
    }


def decode_b067_v1_sub0b_v2(body: bytes) -> dict[str, Any]:
    """Decode LTE MAC UL Tx Statistics 0xB067 v1, subpacket 0x0B v2."""
    _require(body, version=1, minimum=24, exact=24)
    if body[1] != 1:
        raise DecodeError(f"expected one subpacket, observed {body[1]}")
    subpacket_id = body[4]
    subpacket_version = body[5]
    subpacket_size = _u16(body, 6)
    if (subpacket_id, subpacket_version, subpacket_size) != (0x0B, 2, 20):
        raise DecodeError(
            "unsupported B067 subpacket "
            f"id=0x{subpacket_id:02X} v{subpacket_version} size={subpacket_size}"
        )
    return {
        "log_id": "0xB067",
        "packet_version": 1,
        "subpacket_id": subpacket_id,
        "subpacket_version": subpacket_version,
        "sub_id": body[8],
        "number_of_samples": body[9],
        "padding_bsr_count": body[10],
        "regular_bsr_count": body[11],
        "periodic_bsr_count": body[12],
        "cancel_bsr_count": body[13],
        "grant_received_bytes": _u32(body, 14),
        "grant_utilized_bytes": _u32(body, 18),
    }


CSF_TX_MODE_NAMES = {
    0: "TM_INVALID",
    1: "TM_SINGLE_ANT_PORT_0",
    2: "TM_TD_RANK_1",
    3: "TM_OL_SM",
    4: "TM_CL_SM",
    5: "TM_MU_MIMO",
    6: "TM_CL_RANK_1_PC",
    7: "TM_SINGLE_ANT_PORT_5",
}

PUSCH_REPORTING_MODE_NAMES = {
    0: "MODE_APERIODIC_RM12",
    1: "MODE_APERIODIC_RM20",
    2: "MODE_APERIODIC_RM22",
    3: "MODE_APERIODIC_RM30",
    4: "MODE_APERIODIC_RM31",
}


def decode_b14d_v103(body: bytes) -> dict[str, Any]:
    """Decode LTE PHY PUCCH Channel State Feedback 0xB14D version 103."""
    _require(body, version=103, minimum=12, exact=12)
    time_word = _u16(body, 1)
    report_byte = body[3]
    detail = _u32(body, 4)
    csi_rank = body[9]
    report_mode = ((report_byte & 1) << 2) | ((time_word >> 14) & 3)
    report_type = (report_byte >> 1) & 0xF
    tx_mode = (detail >> 26) & 0xF
    return {
        "log_id": "0xB14D",
        "packet_version": 103,
        "time": _sfn_sf(time_word),
        "pucch_reporting_mode": report_mode,
        "pucch_report_type": report_type,
        "number_of_subbands": detail & 0xF,
        "alternate_cqi_table": (detail >> 7) & 1,
        "cqi_codeword_0": (detail >> 10) & 0xF,
        "cqi_codeword_1": (detail >> 14) & 0xF,
        "wideband_pmi": (detail >> 18) & 0xF,
        "carrier_index": (detail >> 22) & 0xF,
        "csf_tx_mode": tx_mode,
        "csf_tx_mode_name": CSF_TX_MODE_NAMES.get(tx_mode, "UNKNOWN"),
        "num_csi_rs_ports": body[8] & 0xF,
        "csi_measurement_set_index": (csi_rank >> 1) & 1,
        "rank_index": (csi_rank >> 2) & 3,
        "rank": ((csi_rank >> 2) & 3) + 1,
        "forced_max_ri": ((body[10] & 0xF) << 4) | ((csi_rank >> 4) & 0xF),
    }


def decode_b14e_v103(body: bytes) -> dict[str, Any]:
    """Decode LTE PHY PUSCH Channel State Feedback 0xB14E version 103."""
    _require(body, version=103, minimum=36, exact=36)
    first = _u32(body, 1)
    second = _u16(body, 5)
    third = body[7]
    carrier = body[35]
    cqi0 = ((first >> 29) & 0x7) | ((second & 1) << 3)
    report_mode = (first >> 14) & 0x7
    tx_mode = (third >> 4) & 0xF
    return {
        "log_id": "0xB14E",
        "packet_version": 103,
        "time": _sfn_sf(first),
        "pusch_reporting_mode": report_mode,
        "pusch_reporting_mode_name": PUSCH_REPORTING_MODE_NAMES.get(
            report_mode, "UNKNOWN"
        ),
        "csi_measurement_set_index": (first >> 17) & 1,
        "rank_index": (first >> 18) & 3,
        "rank": ((first >> 18) & 3) + 1,
        "wideband_pmi_1": (first >> 20) & 0xF,
        "number_of_subbands": (first >> 24) & 0x1F,
        "wideband_cqi_codeword_0": cqi0,
        "wideband_cqi_codeword_1": (second >> 1) & 0xF,
        "subband_size_k": (second >> 5) & 0xF,
        "size_m": (second >> 9) & 0x7,
        "single_wideband_pmi": (second >> 12) & 0xF,
        "single_multiband_pmi": third & 0xF,
        "csf_tx_mode": tx_mode,
        "csf_tx_mode_name": CSF_TX_MODE_NAMES.get(tx_mode, "UNKNOWN"),
        "forced_max_ri": body[22],
        "alternate_cqi_table": (body[28] >> 1) & 1,
        "carrier_index": carrier & 0xF,
        "num_csi_rs_ports": (carrier >> 4) & 0xF,
    }


MODULATION_NAMES = {0: "BPSK", 1: "QPSK", 2: "16-QAM", 3: "64-QAM"}


def _decode_b139_record(record: bytes) -> dict[str, Any]:
    if len(record) != 84:
        raise DecodeError(f"B139/v124 record must be 84 bytes, got {len(record)}")
    carrier = _u16(record, 2)
    resource = _u32(record, 4)
    ack = _u32(record, 12)
    ack_payload = _u32(record, 16)
    modulation = _u32(record, 20)
    tx = _u32(record, 24)
    dl = _u32(record, 28)
    dmrs = _u32(record, 80)
    mod_order = modulation & 3
    tx_power_code = tx & 0x7F
    return {
        "time": _sfn_sf(_u16(record, 0)),
        "ul_carrier_index": carrier & 3,
        "ack_present": (carrier >> 2) & 1,
        "cqi_present": (carrier >> 3) & 1,
        "ri_present": (carrier >> 4) & 1,
        "frequency_hopping": (carrier >> 5) & 3,
        "retransmission_index": (carrier >> 7) & 0x1F,
        "redundancy_version": (carrier >> 12) & 3,
        "mirror_hopping": (carrier >> 14) & 3,
        "resource_allocation_type": resource & 1,
        "start_rb_slot_0": (resource >> 1) & 0x7F,
        "start_rb_slot_1": (resource >> 8) & 0x7F,
        "number_of_resource_blocks": (resource >> 15) & 0x7F,
        "dl_carrier_index": (resource >> 25) & 3,
        "pusch_transport_block_size": _u16(record, 8),
        "coding_rate_raw": _u16(record, 10),
        "coding_rate": _u16(record, 10) / 1024.0,
        "rate_matched_ack_bits": ack & 0x3FFF,
        "ri_payload": (ack >> 14) & 0xF,
        "rate_matched_ri_bits": (ack >> 19) & 0x7FF,
        "ue_srs": (ack >> 29) & 1,
        "srs_occasion": (ack >> 30) & 1,
        "ack_payload": ack_payload & 0xFFFFF,
        "ack_nak_input_length_0": (ack_payload >> 20) & 0xF,
        "ack_nak_input_length_1": (ack_payload >> 24) & 0xF,
        "number_of_ri_bits": (ack_payload >> 28) & 0x7,
        "modulation_order": mod_order,
        "modulation": MODULATION_NAMES.get(mod_order, "UNKNOWN"),
        "pusch_digital_gain_code": (modulation >> 2) & 0xFF,
        "start_rb_cluster_1": (modulation >> 10) & 0xFF,
        "number_of_rb_cluster_1": (modulation >> 18) & 0x3F,
        # MobileInsight labels this seven-bit code as dBm and documents x-128,
        # but its v124 implementation does not apply the offset. Preserve both.
        "pusch_tx_power_code": tx_power_code,
        "pusch_tx_power_dbm_documented": tx_power_code - 128,
        "number_of_cqi_bits": (tx >> 7) & 0xFF,
        "rate_matched_cqi_bits": (tx >> 18) & 0x3FFF,
        "number_of_dl_carriers": dl & 3,
        "ack_nack_index": (dl >> 2) & 0xFFF,
        "ack_nack_late": (dl >> 14) & 1,
        "csf_late": (dl >> 15) & 1,
        "drop_pusch": (dl >> 16) & 1,
        "cqi_payload_hex": record[32:76].hex(),
        "tx_resampler": _u32(record, 76),
        "dmrs_cyclic_shift_slot_0": dmrs & 0xF,
        "dmrs_cyclic_shift_slot_1": (dmrs >> 4) & 0xF,
        "dmrs_root_slot_0": (dmrs >> 8) & 0x7FF,
        "dmrs_root_slot_1": (dmrs >> 19) & 0x7FF,
    }


def decode_b139_v124(body: bytes) -> dict[str, Any]:
    """Decode LTE PHY PUSCH Tx Report 0xB139 version 124."""
    _require(body, version=124, minimum=8)
    header = _u16(body, 1)
    number_of_records = (header >> 9) & 0x1F
    expected = 8 + number_of_records * 84
    if len(body) != expected:
        raise DecodeError(
            f"B139/v124 declares {number_of_records} records ({expected} bytes), "
            f"but body has {len(body)}"
        )
    return {
        "log_id": "0xB139",
        "packet_version": 124,
        "serving_cell_id": header & 0x1FF,
        "number_of_records": number_of_records,
        "dispatch_time": _sfn_sf(_u16(body, 4)),
        "records": [
            _decode_b139_record(body[offset : offset + 84])
            for offset in range(8, len(body), 84)
        ],
    }


def _rsrp(raw: int) -> float:
    return raw * 0.0625 - 180.0


def _rsrq(raw: int) -> float:
    return raw * 0.0625 - 30.0


def decode_b179_v4(body: bytes) -> dict[str, Any]:
    """Decode LTE connected-mode intra-frequency measurements B179/v4."""
    _require(body, version=4, minimum=28)
    number_of_neighbors = body[24]
    number_of_detected = body[25]
    payload_end = 28 + number_of_neighbors * 12 + number_of_detected * 16
    trailing = body[payload_end:]
    # This firmware sometimes reserves one additional zeroed 12-byte neighbor
    # slot. MobileInsight stops at the advertised count. Accept only the
    # observed, unambiguous zero padding form.
    if trailing not in {b"", bytes(12)}:
        raise DecodeError(
            "B179/v4 count/length mismatch: "
            f"neighbors={number_of_neighbors}, detected={number_of_detected}, "
            f"payload_end={payload_end}, observed={len(body)}, "
            f"trailing={trailing.hex()}"
        )
    offset = 28
    neighbors = []
    for _ in range(number_of_neighbors):
        neighbors.append(
            {
                "physical_cell_id": _u16(body, offset),
                "rsrp_dbm": _rsrp(_i16(body, offset + 2)),
                "rsrq_db": _rsrq(_i16(body, offset + 6)),
            }
        )
        offset += 12
    detected = []
    for _ in range(number_of_detected):
        detected.append(
            {
                "physical_cell_id": _u16(body, offset),
                "sss_correlation": _u32(body, offset + 4),
                "reference_time": _u64(body, offset + 8),
            }
        )
        offset += 16
    return {
        "log_id": "0xB179",
        "packet_version": 4,
        "serving_cell_index": body[4] & 0x7,
        "earfcn": _u32(body, 8),
        "serving_physical_cell_id": _u16(body, 12),
        "time": _sfn_sf(_u16(body, 14)),
        "serving_rsrp_dbm": _rsrp(_i16(body, 16)),
        "serving_rsrq_db": _rsrq(_i16(body, 20)),
        "number_of_neighbor_cells": number_of_neighbors,
        "number_of_detected_cells": number_of_detected,
        "neighbor_cells": neighbors,
        "detected_cells": detected,
        "reserved_zero_neighbor_slot": len(trailing) == 12,
    }


DCI_FORMAT_NAMES = {
    0: "Format 0",
    1: "Format 1",
    2: "Format 1A",
    3: "Format 1B",
    4: "Format 1C",
    5: "Format 1D",
    6: "Format 2",
    7: "Format 2A",
    8: "Format 3",
    9: "Format 3A",
    12: "Format 60A",
    13: "Format 61A",
    14: "Format 62",
    15: "Reserved",
}

RNTI_TYPE_NAMES = {
    0: "C-RNTI",
    1: "SPS-RNTI",
    2: "P-RNTI",
    3: "RA-RNTI",
    4: "Temporary-C-RNTI",
    5: "SI-RNTI",
    6: "TPC-PUSCH-RNTI",
    7: "TPC-PUCCH-RNTI",
    8: "MBMS-RNTI",
}


def _decode_b130_hypothesis(record: bytes) -> dict[str, Any]:
    if len(record) != 28:
        raise DecodeError(f"B130/v123 hypothesis must be 28 bytes, got {len(record)}")
    meta = _u32(record, 8)
    cce = _u32(record, 12)
    prune = _u32(record, 16)
    dci_format = (meta >> 6) & 0xF
    decode_state = (meta >> 10) & 0xF
    return {
        "payload_hex": record[:8].hex(),
        "aggregation_level_code": meta & 3,
        "aggregation_level": 1 << (meta & 3),
        "candidate": (meta >> 2) & 7,
        "search_space": "UE-specific" if ((meta >> 5) & 1) else "Common",
        "dci_format": dci_format,
        "dci_format_name": DCI_FORMAT_NAMES.get(dci_format, "UNKNOWN"),
        "decode_state": decode_state,
        "rnti_type_name": RNTI_TYPE_NAMES.get(decode_state, "UNKNOWN"),
        "payload_size_bits": (meta >> 14) & 0xFF,
        "tail_match": (meta >> 22) & 1,
        "nonzero_symbol_mismatch_count": (meta >> 23) & 0x1FF,
        "alternate_tbs_enabled": cce & 1,
        "start_cce": (cce >> 1) & 0x7F,
        "nonzero_llr_count": (cce >> 8) & 0x1FF,
        "normal_metric": (cce >> 17) & 0x7FFF,
        "prune_status": prune & 0x7FF,
        "energy_metric": (prune >> 11) & 0x1FFFFF,
        "normalized_energy_metric": _u32(record, 20) / 65535.0,
        "symbol_error_rate": _u32(record, 24) / 2147483648.0,
    }


def decode_b130_v123(body: bytes) -> dict[str, Any]:
    """Decode LTE PHY PDCCH Decoding Result 0xB130 version 123."""
    _require(body, version=123, minimum=12)
    config = _u32(body, 1)
    number_of_hypotheses = body[7]
    expected = 12 + number_of_hypotheses * 28
    if len(body) != expected:
        raise DecodeError(
            "B130/v123 count/length mismatch: "
            f"hypotheses={number_of_hypotheses}, expected={expected}, "
            f"observed={len(body)}"
        )
    mode = body[6]
    return {
        "log_id": "0xB130",
        "packet_version": 123,
        "time": _sfn_sf(config),
        "bandwidth_mhz": (((config >> 14) & 7) - 1) * 5,
        "cif_configured": (config >> 17) & 1,
        "two_bit_csi_configured": (config >> 18) & 1,
        "aperiodic_srs_configured": (config >> 19) & 1,
        "frame_structure": (config >> 20) & 3,
        "number_of_enb_antennas_code": (config >> 22) & 3,
        "downlink_cyclic_prefix": (config >> 24) & 3,
        "ssc": (config >> 26) & 3,
        "ca_fdd_tdd": (config >> 28) & 3,
        "demback_mode_select": mode & 0xF,
        "carrier_index": (mode >> 4) & 0xF,
        "number_of_hypotheses": number_of_hypotheses,
        "hypotheses": [
            _decode_b130_hypothesis(body[offset : offset + 28])
            for offset in range(8, len(body) - 4, 28)
        ],
        "trailing_reserved_hex": body[-4:].hex(),
    }


def _decode_ml1_measurement_cell(record: bytes) -> dict[str, Any]:
    if len(record) != 52:
        raise DecodeError(f"ML1 measurement cell must be 52 bytes, got {len(record)}")
    identity = _u32(record, 0)
    rsrq_word = _u32(record, 20)
    rssi_word = _u32(record, 28)
    return {
        "physical_cell_id": identity & 0x3FF,
        "ftl_cumulative_frequency_offset": (identity >> 10) & 0xFFFF,
        "instant_rsrp_dbm": (( _u16(record, 12) & 0xFFF) * 0.0625) - 180.0,
        "instant_rsrq_db": (((rsrq_word >> 10) & 0x3FF) * 0.0625) - 30.0,
        "instant_rssi_dbm": (((rssi_word >> 11) & 0x7FF) * 0.0625) - 110.0,
    }


def decode_b192_v1(body: bytes) -> dict[str, Any]:
    """Decode idle neighbor measurement request/response B192/v1."""
    _require(body, version=1, minimum=28)
    if body[1] != 2:
        raise DecodeError(f"B192/v1 expected two subpackets, observed {body[1]}")
    request_start = 4
    request_id, request_version = body[request_start], body[request_start + 1]
    request_size = _u16(body, request_start + 2)
    response_start = request_start + request_size
    if response_start + 12 > len(body):
        raise DecodeError("truncated B192 response subpacket")
    response_id, response_version = body[response_start], body[response_start + 1]
    response_size = _u16(body, response_start + 2)
    if (request_id, request_version) != (26, 2):
        raise DecodeError(
            f"unsupported B192 request subpacket {request_id}/v{request_version}"
        )
    if (response_id, response_version) != (27, 4):
        raise DecodeError(
            f"unsupported B192 response subpacket {response_id}/v{response_version}"
        )
    if response_start + response_size != len(body):
        raise DecodeError("B192 subpacket sizes do not cover the complete body")

    request_config = body[request_start + 8]
    request_cells_count = request_config & 0xF
    expected_request = 12 + request_cells_count * 16
    if request_size != expected_request:
        raise DecodeError(
            f"B192 request count/size mismatch: {request_cells_count}/{request_size}"
        )
    request_cells = []
    pos = request_start + 12
    for _ in range(request_cells_count):
        cell = body[pos : pos + 16]
        config = _u16(cell, 0)
        request_cells.append(
            {
                "physical_cell_id": config & 0x3FF,
                "cyclic_prefix_type": (config >> 10) & 1,
                "enabled_tx_antennas_code": (config >> 11) & 3,
                "ttl_enabled": (config >> 13) & 1,
                "ftl_enabled": (config >> 14) & 1,
                "remaining_raw_hex": cell[2:].hex(),
            }
        )
        pos += 16

    response_config = _u16(body, response_start + 8)
    response_cells_count = response_config & 0x3F
    expected_response = 12 + response_cells_count * 52
    if response_size != expected_response:
        raise DecodeError(
            f"B192 response count/size mismatch: {response_cells_count}/{response_size}"
        )
    response_cells = []
    pos = response_start + 12
    for _ in range(response_cells_count):
        response_cells.append(_decode_ml1_measurement_cell(body[pos : pos + 52]))
        pos += 52
    return {
        "log_id": "0xB192",
        "packet_version": 1,
        "request": {
            "earfcn": _u32(body, request_start + 4),
            "number_of_cells": request_cells_count,
            "number_of_rx_antennas_code": (request_config >> 4) & 3,
            "duplexing_mode": (request_config >> 6) & 3,
            "cells": request_cells,
        },
        "response": {
            "earfcn": _u32(body, response_start + 4),
            "number_of_cells": response_cells_count,
            "duplexing_mode": (response_config >> 7) & 3,
            "serving_cell_index": (response_config >> 9) & 0xF,
            "cells": response_cells,
        },
    }


def decode_b195_v1(body: bytes) -> dict[str, Any]:
    """Decode connected neighbor response B195/v1; preserve request losslessly."""
    _require(body, version=1, minimum=100)
    if body[1] != 2:
        raise DecodeError(f"B195/v1 expected two subpackets, observed {body[1]}")
    request_start = 4
    request_id, request_version = body[request_start], body[request_start + 1]
    request_size = _u16(body, request_start + 2)
    response_start = request_start + request_size
    if response_start + 12 > len(body):
        raise DecodeError("truncated B195 response subpacket")
    response_id, response_version = body[response_start], body[response_start + 1]
    response_size = _u16(body, response_start + 2)
    if (request_id, request_version) != (30, 32):
        raise DecodeError(
            f"unsupported B195 request subpacket {request_id}/v{request_version}"
        )
    if (response_id, response_version) != (31, 4):
        raise DecodeError(
            f"unsupported B195 response subpacket {response_id}/v{response_version}"
        )
    if response_start + response_size != len(body):
        raise DecodeError("B195 subpacket sizes do not cover the complete body")
    config = _u16(body, response_start + 8)
    count = config & 0x3F
    if response_size != 12 + count * 52:
        raise DecodeError(f"B195 response count/size mismatch: {count}/{response_size}")
    cells = []
    pos = response_start + 12
    for _ in range(count):
        cells.append(_decode_ml1_measurement_cell(body[pos : pos + 52]))
        pos += 52
    return {
        "log_id": "0xB195",
        "packet_version": 1,
        "request": {
            "subpacket_id": request_id,
            "subpacket_version": request_version,
            "raw_payload_hex": body[request_start + 4 : response_start].hex(),
        },
        "response": {
            "earfcn": _u32(body, response_start + 4),
            "number_of_cells": count,
            "duplexing_mode": (config >> 7) & 3,
            "serving_cell_index": (config >> 9) & 0xF,
            "cells": cells,
        },
    }


def _single_subpacket(
    body: bytes, *, log_id: int, packet_version: int, subpacket_id: int, subpacket_version: int
) -> bytes:
    _require(body, version=packet_version, minimum=8)
    if body[1] != 1:
        raise DecodeError(f"0x{log_id:04X} expected one subpacket, observed {body[1]}")
    observed = (body[4], body[5])
    expected = (subpacket_id, subpacket_version)
    if observed != expected:
        raise DecodeError(
            f"0x{log_id:04X} subpacket {observed[0]:02X}/v{observed[1]} "
            f"does not match {expected[0]:02X}/v{expected[1]}"
        )
    size = _u16(body, 6)
    if size < 4 or 4 + size != len(body):
        raise DecodeError(
            f"0x{log_id:04X} invalid subpacket size {size} for body {len(body)}"
        )
    return body[8 : 4 + size]


def _alignment_tail(payload: bytes, pos: int, *, label: str) -> str:
    """Preserve the target firmware's at-most-three alignment bytes."""
    trailing = payload[pos:]
    if len(trailing) > 3:
        raise DecodeError(
            f"{label} has invalid trailing bytes at offset {pos}: {trailing.hex()}"
        )
    return trailing.hex()


def _decode_rlc_am_pdu(
    payload: bytes,
    pos: int,
    *,
    direction: str,
    rb_config_index: int,
) -> tuple[dict[str, Any], int]:
    """Normalize one v3 RLC AM PDU metadata/header envelope."""
    if pos + 9 > len(payload):
        raise DecodeError(f"truncated RLC {direction} AM PDU header")
    packed_time = _u16(payload, pos)
    pdu_bytes = _u16(payload, pos + 2)
    logged_bytes = _u16(payload, pos + 4)
    reserved = payload[pos + 6]
    lookahead = payload[pos + 7]
    sn_low = payload[pos + 8]
    if logged_bytes < 2:
        raise DecodeError(
            f"RLC {direction} PDU logged_bytes={logged_bytes}; expected at least 2"
        )
    extension_length = logged_bytes - 2
    end = pos + 9 + extension_length
    if end > len(payload):
        raise DecodeError(
            f"truncated RLC {direction} logged header: "
            f"need {extension_length} extension bytes"
        )

    common: dict[str, Any] = {
        "rb_config_index": rb_config_index,
        "time": _sfn_sf(packed_time),
        "pdu_size_bytes": pdu_bytes,
        "logged_header_bytes": logged_bytes,
        "reserved": reserved,
        "dc_lookahead_raw": lookahead,
        "logged_header_hex": payload[pos + 7 : end].hex(),
        "logged_extension_hex": payload[pos + 9 : end].hex(),
    }
    if lookahead < 16:
        common.update(
            {
                "pdu_type": "control",
                "control_pdu_type": "STATUS",
                "ack_sequence_number": lookahead * 64 + sn_low // 4,
                "control_extension_status": (
                    "preserved-raw; optional NACK semantics not normalized"
                    if extension_length
                    else "none"
                ),
            }
        )
    else:
        common.update(
            {
                "pdu_type": "data",
                "sequence_number": (
                    sn_low
                    + (((lookahead >> 1) & 1) * 512)
                    + ((lookahead & 1) * 256)
                ),
                "resegmentation_flag": (lookahead >> 6) & 1,
                "polling_bit": (lookahead >> 5) & 1,
                "framing_info": (lookahead >> 3) & 3,
                "extension_bit": (lookahead >> 2) & 1,
                "data_extension_status": (
                    "preserved-raw; optional LSF/SO/LI semantics not normalized"
                    if extension_length
                    else "none"
                ),
            }
        )
    return common, end


def _decode_rlc_am_all_pdu_v1_sub_v3(
    body: bytes,
    *,
    log_id: int,
    subpacket_id: int,
    direction: str,
) -> dict[str, Any]:
    payload = _single_subpacket(
        body,
        log_id=log_id,
        packet_version=1,
        subpacket_id=subpacket_id,
        subpacket_version=3,
    )
    fixed_length = 16 if direction == "downlink" else 20
    if len(payload) < fixed_length:
        raise DecodeError(
            f"0x{log_id:04X} v3 payload is {len(payload)} bytes; "
            f"need at least {fixed_length}"
        )

    rb_config_index = payload[0]
    result: dict[str, Any] = {
        "log_id": f"0x{log_id:04X}",
        "packet_version": 1,
        "subpacket_id": subpacket_id,
        "subpacket_version": 3,
        "direction": direction,
        "rlc_mode": "AM" if payload[1] == 1 else "unknown",
        "rlc_mode_raw": payload[1],
        "sequence_number_length_bits": payload[2],
        "rb_config_index": rb_config_index,
        "enabled_pdu_log_packets_mask": _u16(payload, 4),
    }
    if direction == "downlink":
        result.update(
            {
                "vr_r": _u16(payload, 6),
                "vr_x": _u16(payload, 8),
                "vr_ms": _u16(payload, 10),
                "vr_h": _u16(payload, 12),
            }
        )
        number_of_pdus = _u16(payload, 14)
    else:
        result.update(
            {
                "vt_a": _u16(payload, 6),
                "vt_s": _u16(payload, 8),
                "pdu_without_poll": _u16(payload, 10),
                "bytes_without_poll": _u32(payload, 12),
                "poll_sequence_number": _u16(payload, 16),
            }
        )
        number_of_pdus = _u16(payload, 18)

    pos = fixed_length
    pdus = []
    for _ in range(number_of_pdus):
        pdu, pos = _decode_rlc_am_pdu(
            payload,
            pos,
            direction=direction,
            rb_config_index=rb_config_index,
        )
        pdus.append(pdu)
    result.update(
        {
            "number_of_pdus": number_of_pdus,
            "pdus": pdus,
            "trailing_alignment_hex": _alignment_tail(
                payload, pos, label=f"0x{log_id:04X}/v3"
            ),
            "decode_scope": (
                "exact Qualcomm RLC AM envelope and logged-header preservation; "
                "SDU reassembly is outside this decoder"
            ),
        }
    )
    return result


def decode_b082_v1_sub41_v3(body: bytes) -> dict[str, Any]:
    """Decode LTE RLC DL AM All PDU B082/v1, subpacket 41/v3."""
    return _decode_rlc_am_all_pdu_v1_sub_v3(
        body,
        log_id=0xB082,
        subpacket_id=0x41,
        direction="downlink",
    )


def decode_b092_v1_sub46_v3(body: bytes) -> dict[str, Any]:
    """Decode LTE RLC UL AM All PDU B092/v1, subpacket 46/v3."""
    return _decode_rlc_am_all_pdu_v1_sub_v3(
        body,
        log_id=0xB092,
        subpacket_id=0x46,
        direction="uplink",
    )


CIPHER_ALGORITHM_NAMES = {
    2: "LTE SNOW-3G",
    3: "LTE AES",
    7: "None",
}

PDCP_SN_LENGTH_BITS = {
    0: 5,
    1: 7,
    2: 12,
    3: 15,
}


def _decode_pdcp_cipher_data_v1_subc3(
    body: bytes,
    *,
    log_id: int,
    subpacket_version: int,
    direction: str,
) -> dict[str, Any]:
    payload = _single_subpacket(
        body,
        log_id=log_id,
        packet_version=1,
        subpacket_id=0xC3,
        subpacket_version=subpacket_version,
    )
    if len(payload) < 36:
        raise DecodeError(
            f"0x{log_id:04X} C3/v{subpacket_version} payload is "
            f"{len(payload)} bytes; need at least 36"
        )

    # Public Qualcomm decoders disagree on whether the first 32 bytes are
    # reserved or live SRB/DRB cipher material. Do not expose them through the
    # structured result. The outer capture artifact remains lossless.
    srb_algorithm = payload[32]
    drb_algorithm = payload[33]
    number_of_pdus = _u16(payload, 34)
    pos = 36
    pdus = []
    for _ in range(number_of_pdus):
        if pos + 13 > len(payload):
            raise DecodeError(
                f"truncated 0x{log_id:04X} C3/v{subpacket_version} PDU header"
            )
        config = _u16(payload, pos)
        pdu_size = _u16(payload, pos + 2)
        logged_bytes = _u16(payload, pos + 4)
        packed_time = _u16(payload, pos + 6)
        sequence_number_raw = _u32(payload, pos + 8)
        compression = payload[pos + 12]
        end = pos + 13 + logged_bytes
        if end > len(payload):
            raise DecodeError(
                f"truncated 0x{log_id:04X} ciphered PDU: "
                f"logged={logged_bytes}, available={len(payload) - pos - 13}"
            )
        sn_length_code = (config >> 7) & 3
        bearer_id = (config >> 9) & 0x1F
        pdus.append(
            {
                "config_index": config & 0x3F,
                "rlc_mode": "UM" if ((config >> 6) & 1) else "AM",
                "sequence_number_length_code": sn_length_code,
                "sequence_number_length_bits": PDCP_SN_LENGTH_BITS.get(
                    sn_length_code
                ),
                "bearer_id": bearer_id,
                "plane": "signaling" if bearer_id in {0, 1} else "user",
                "valid_pdu": (config >> 14) & 1,
                "reserved_config_bit": (config >> 15) & 1,
                "pdu_size_bytes": pdu_size,
                "logged_bytes": logged_bytes,
                "time": _sfn_sf(packed_time),
                "sequence_number_raw": sequence_number_raw,
                "sequence_number_12bit": sequence_number_raw & 0xFFF,
                "compression_pdu_type_raw": compression,
                "ciphered_pdu_hex": payload[pos + 13 : end].hex(),
                "payload_status": (
                    "ciphered-or-opaque; no plaintext interpretation attempted"
                ),
            }
        )
        pos = end

    return {
        "log_id": f"0x{log_id:04X}",
        "packet_version": 1,
        "subpacket_id": 0xC3,
        "subpacket_version": subpacket_version,
        "direction": direction,
        "opaque_security_material": {
            "length_bytes": 32,
            "redacted_from_structured_output": True,
            "reason": (
                "public decoders disagree whether these bytes are reserved or "
                "live SRB/DRB cipher material"
            ),
        },
        "srb_cipher_algorithm": srb_algorithm,
        "srb_cipher_algorithm_name": CIPHER_ALGORITHM_NAMES.get(
            srb_algorithm, "Unknown"
        ),
        "drb_cipher_algorithm": drb_algorithm,
        "drb_cipher_algorithm_name": CIPHER_ALGORITHM_NAMES.get(
            drb_algorithm, "Unknown"
        ),
        "number_of_pdus": number_of_pdus,
        "pdus": pdus,
        "trailing_alignment_hex": _alignment_tail(
            payload, pos, label=f"0x{log_id:04X}/C3/v{subpacket_version}"
        ),
        "decode_scope": (
            "exact Qualcomm PDCP cipher-PDU envelope; possible key material "
            "redacted and ciphered payload preserved without decryption"
        ),
    }


def decode_b0a3_v1_subc3_v24(body: bytes) -> dict[str, Any]:
    """Decode LTE PDCP DL Cipher Data PDU B0A3/v1, C3/v24."""
    return _decode_pdcp_cipher_data_v1_subc3(
        body,
        log_id=0xB0A3,
        subpacket_version=24,
        direction="downlink",
    )


def decode_b0b3_v1_subc3_v26(body: bytes) -> dict[str, Any]:
    """Decode LTE PDCP UL Cipher Data PDU B0B3/v1, C3/v26."""
    return _decode_pdcp_cipher_data_v1_subc3(
        body,
        log_id=0xB0B3,
        subpacket_version=26,
        direction="uplink",
    )


def decode_b063_v1_sub07_v4(body: bytes) -> dict[str, Any]:
    """Decode LTE MAC downlink transport-block metadata and MAC bytes."""
    payload = _single_subpacket(
        body,
        log_id=0xB063,
        packet_version=1,
        subpacket_id=0x07,
        subpacket_version=4,
    )
    if not payload:
        raise DecodeError("B063 subpacket has no sample count")
    count = payload[0]
    pos = 1
    samples = []
    for _ in range(count):
        if pos + 14 > len(payload):
            raise DecodeError("truncated B063/v4 sample header")
        header_length = payload[pos + 13]
        end = pos + 14 + header_length
        if end > len(payload):
            raise DecodeError("truncated B063/v4 MAC header bytes")
        samples.append(
            {
                "sub_id": payload[pos],
                "cell_id": payload[pos + 1],
                "time": _sfn_sf(_u16(payload, pos + 2)),
                "rnti_type": payload[pos + 4],
                "harq_id": payload[pos + 5],
                "pmch_id": _u16(payload, pos + 6),
                "downlink_transport_block_size": _u16(payload, pos + 8),
                "number_of_rlc_pdus": payload[pos + 10],
                "padding_bytes": _u16(payload, pos + 11),
                "mac_header_hex": payload[pos + 14 : end].hex(),
            }
        )
        pos = end
    trailing = payload[pos:]
    if len(trailing) > 3:
        raise DecodeError(f"B063/v4 has {len(trailing)} non-alignment bytes")
    return {
        "log_id": "0xB063",
        "packet_version": 1,
        "subpacket_id": 0x07,
        "subpacket_version": 4,
        "number_of_samples": count,
        "direction": "downlink",
        "samples": samples,
        "trailing_alignment_hex": trailing.hex(),
    }


def decode_b064_v1_sub08_v2(body: bytes) -> dict[str, Any]:
    """Decode LTE MAC uplink transport-block metadata and MAC bytes."""
    payload = _single_subpacket(
        body,
        log_id=0xB064,
        packet_version=1,
        subpacket_id=0x08,
        subpacket_version=2,
    )
    if not payload:
        raise DecodeError("B064 subpacket has no sample count")
    count = payload[0]
    pos = 1
    samples = []
    for _ in range(count):
        if pos + 14 > len(payload):
            raise DecodeError("truncated B064/v2 sample header")
        header_length = payload[pos + 13]
        end = pos + 14 + header_length
        if end > len(payload):
            raise DecodeError("truncated B064/v2 MAC header bytes")
        samples.append(
            {
                "sub_id": payload[pos],
                "cell_id": payload[pos + 1],
                "harq_id": payload[pos + 2],
                "rnti_type": payload[pos + 3],
                "time": _sfn_sf(_u16(payload, pos + 4)),
                "grant_bytes": _u16(payload, pos + 6),
                "number_of_rlc_pdus": payload[pos + 8],
                "padding_bytes": _u16(payload, pos + 9),
                "bsr_event": payload[pos + 11],
                "bsr_trigger": payload[pos + 12],
                "mac_header_hex": payload[pos + 14 : end].hex(),
            }
        )
        pos = end
    trailing = payload[pos:]
    if len(trailing) > 3:
        raise DecodeError(f"B064/v2 has {len(trailing)} non-alignment bytes")
    return {
        "log_id": "0xB064",
        "packet_version": 1,
        "subpacket_id": 0x08,
        "subpacket_version": 2,
        "number_of_samples": count,
        "direction": "uplink",
        "samples": samples,
        "trailing_alignment_hex": trailing.hex(),
    }


DECODERS: dict[int, Callable[[bytes], dict[str, Any]]] = {
    0xB082: decode_b082_v1_sub41_v3,
    0xB092: decode_b092_v1_sub46_v3,
    0xB0A3: decode_b0a3_v1_subc3_v24,
    0xB0B3: decode_b0b3_v1_subc3_v26,
    0xB0C1: decode_b0c1_v2,
    0xB0C2: decode_b0c2_v3,
    0xB0E5: decode_b0e5_v1,
    0xB0EE: decode_b0ee_v2,
    0xB063: decode_b063_v1_sub07_v4,
    0xB064: decode_b064_v1_sub08_v2,
    0xB067: decode_b067_v1_sub0b_v2,
    0xB130: decode_b130_v123,
    0xB139: decode_b139_v124,
    0xB14D: decode_b14d_v103,
    0xB14E: decode_b14e_v103,
    0xB179: decode_b179_v4,
    0xB192: decode_b192_v1,
    0xB195: decode_b195_v1,
}


def decode_record(log_id: int, body: bytes) -> dict[str, Any]:
    """Dispatch one complete body using only an explicit registered log ID."""
    decoder = DECODERS.get(log_id)
    if decoder is None:
        raise DecodeError(f"no decoder registered for log ID 0x{log_id:04X}")
    return decoder(body)
