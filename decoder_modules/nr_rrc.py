"""Release-15-compatible direct NR roots; shares the existing UPER engine."""
import json
from functools import lru_cache
from pathlib import Path
from .nsg_rrc import _SchemaDecoder
from decoder_core.diag import supported

ROOTS = {9: ("RRCReconfiguration", "rrc_reconfiguration"),
         10: ("RRCReconfigurationComplete", "rrc_reconfiguration_complete"),
         25: ("RadioBearerConfig", "radio_bearer_configuration")}


@lru_cache(maxsize=1)
def schema():
    return json.loads(Path(__file__).with_name("nr_rrc_release15_schema.json").read_text(encoding="utf-8"))


def decode(pdu, payload):
    supported(pdu in ROOTS, "unsupported-b821-v12-pdu-number")
    if not payload:
        raise ValueError("empty NR RRC UPER payload")
    root, _ = ROOTS[pdu]
    tree = _SchemaDecoder(schema()).decode(root, payload)
    def visit(value):
        if isinstance(value, dict):
            return any(visit(key) or visit(child) for key,child in value.items())
        if isinstance(value, (list,tuple)):
            return any(visit(child) for child in value)
        return isinstance(value,str) and any(token in value.lower() for token in (
            "_unknownextension", "-r16", "-r17", "-r18", "-v16", "-v17", "-v18"))
    supported(not visit(tree), "NR RRC schema branch is outside Release 15")
    return dict(semantic_depth="full-observed-message-tree",asn1_root=root,asn1_tree=tree)
