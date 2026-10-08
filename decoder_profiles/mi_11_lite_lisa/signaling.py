"""Lisa Qualcomm adapters around reusable standard RRC and EPS NAS decoders."""
from decoder_core.diag import uint as u, require, supported
from decoder_modules import nsg_rrc
from decoder_modules.eps_nas import decode as eps_decode
from .decoders import common
from .privacy import sanitize


def decode_rrc(schema, body):
    supported(body[1:4]==bytes((16,16,15)),"unsupported-rrc-v27-runtime-tuple")
    transport={3:2,7:5,8:6,9:7,10:8,11:9}.get(body[14])
    supported(transport is not None,"unsupported-rrc-v27-transport")
    supported(body[16:19]==bytes(3),"unsupported-rrc-v27-reserved")
    require(u(body,19,2)==len(body)-21,"rrc-v27-length-mismatch")
    rrc=nsg_rrc.decode_rrc(transport,body[21:])
    require(rrc["status"]!="MALFORMED",rrc["detail"])
    supported(rrc["status"]!="UNSUPPORTED",rrc["detail"])
    fields=dict(**common(schema),header_profile="qualcomm-log-lte-rrc-ota-v27",
        rrc_release_major_raw=body[1],rrc_release_version_raw=body[2],radio_bearer_id_raw=body[3],
        cell_context_raw=u(body,4,2),frequency_raw=u(body,6,2),timing_metadata_low_raw=u(body,8,2),
        timing_metadata_high_raw=u(body,10,4),pdu_number=body[14],sib_mask=body[15],
        message_length=len(body)-21,rrc=sanitize(rrc))
    return fields,[]


def decode_nas(schema, body):
    supported(body[:4]==bytes((1,9,5,0)),"unsupported-qualcomm-nas-header: expected 1/9/5/0")
    direction="MT" if schema.log_id in (0xb0e2,0xb0ea,0xb0ec) else "MO"
    nas=eps_decode(body[4:],direction)
    return dict(**common(schema),direction=direction,plane="ESM" if schema.log_id<=0xb0e3 else "EMM",
        form="security-protected" if schema.log_id in (0xb0e1,0xb0ea,0xb0eb) else "plain",
        qualcomm_header=dict(packet_version=1,rrc_release_number=9,major_version=5,minor_version=0),
        nas=sanitize(nas,"nas")),[]
