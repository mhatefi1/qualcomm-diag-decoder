"""Conservative correlation of Qualcomm protected and modem-plaintext NAS views."""

from __future__ import annotations

from typing import Any, Iterable


ROUTES = {
    "0xB0E0": {"0xB0E2"},
    "0xB0E1": {"0xB0E3"},
    "0xB0EA": {"0xB0EC", "0xB0E2"},
    "0xB0EB": {"0xB0ED", "0xB0E3"},
}
VERIFICATION = (
    "same direction, validated log route, six-byte security-header length "
    "delta, bounded frame/time proximity"
)


def _distance(left: int, right: int) -> int:
    return abs(left - right)


def _eligible(protected: dict[str, Any], plain: dict[str, Any], max_frames: int, max_nanos: int) -> bool:
    protected_fields, plain_fields = protected.get("fields", {}), plain.get("fields", {})
    if protected_fields.get("direction") != plain_fields.get("direction"): return False
    if plain.get("log_id") not in ROUTES.get(protected.get("log_id"), set()): return False
    if _distance(protected["index"], plain["index"]) > max_frames: return False
    if _distance(protected["timestamp_nanos"], plain["timestamp_nanos"]) > max_nanos: return False
    protected_nas, plain_nas = protected_fields.get("nas", {}), plain_fields.get("nas", {})
    if protected_nas.get("payload_length") != plain_nas.get("payload_length", -7) + 6: return False
    security = protected_nas.get("security_header_type")
    if security in {1, 3}:
        return protected_nas.get("protected_payload_hex") == plain_nas.get("payload_hex")
    return security in {2, 4}


def correlate(observations: Iterable[dict[str, Any]], maximum_frame_distance: int, maximum_time_distance_nanos: int) -> list[dict[str, Any]]:
    """Pair each protected NAS packet with at most one unambiguous plaintext view."""
    if maximum_frame_distance < 0 or maximum_time_distance_nanos < 0:
        raise ValueError("correlation bounds must be non-negative")
    records = list(observations)
    for record in records:
        if record.get("index", -1) < 0 or record.get("timestamp_nanos", -1) < 0:
            raise ValueError("frame index and timestamp must be non-negative")
    protected = [r for r in records if r.get("fields", {}).get("form") == "security-protected"]
    plaintext = [r for r in records if r.get("fields", {}).get("form") == "plain"]
    used: set[int] = set(); result: list[dict[str, Any]] = []
    for protected_record in protected:
        candidates = [p for p in plaintext if id(p) not in used and _eligible(protected_record, p, maximum_frame_distance, maximum_time_distance_nanos)]
        candidates.sort(key=lambda p: (_distance(protected_record["index"], p["index"]), _distance(protected_record["timestamp_nanos"], p["timestamp_nanos"])))
        if not candidates: continue
        selected = candidates[0]
        score = (_distance(protected_record["index"], selected["index"]), _distance(protected_record["timestamp_nanos"], selected["timestamp_nanos"]))
        if len(candidates) > 1 and score == (_distance(protected_record["index"], candidates[1]["index"]), _distance(protected_record["timestamp_nanos"], candidates[1]["timestamp_nanos"])): continue
        used.add(id(selected))
        result.append({
            "protected_index": protected_record["index"], "plaintext_index": selected["index"],
            "frame_distance": score[0], "time_distance_nanos": score[1],
            "direction": selected.get("fields", {}).get("direction", ""),
            "plaintext_message": selected.get("fields", {}).get("nas", {}).get("message", ""),
            "verification": VERIFICATION,
        })
    return result
