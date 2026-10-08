"""Proven compatible prefixes and explicitly partial Lisa-only measurements."""
from decoder_core.diag import uint as u, require, supported
from decoder_modules import nsg_decode_random_access as ra, nsg_parse_lte as lte
from .decoders import common
from .privacy import sanitize


def decode(schema, body):
    supported(schema.log_id in (0xb168,0xb16a,0xb17f,0xb193), "unsupported-unproven-lisa-layout")
    warnings=[]
    if schema.log_id == 0xb193:
        fields,warnings=b193(body)
    elif schema.log_id == 0xb17f:
        # Existing semantic parser requires the Poco 36-byte prefix; Lisa suffix is opaque.
        fields=lte.decode_b17f(bytes(24)+body[:36]+bytes(2))
        require(fields is not None, "malformed-measurement-record")
    else:
        fields=(ra.decode_b168(body) if schema.log_id == 0xb168 else ra.decode_b16a(body))
    fields=dict(fields)
    fields.pop("schema_selection",None)
    if schema.log_id != 0xb193:
        fields["semantic_source"]="accepted-exact-version-poco-core"
    fields=sanitize(fields)
    if schema.log_id==0xb17f:
        fields.update(semantic_scope="accepted-v5-prefix-through-offset-35",uninterpreted_suffix_bytes=len(body)-36)
    return dict(**common(schema),record_version=schema.version,family=schema.family,
                measurement=fields),warnings


def b193(body):
    require(len(body)==180,"invalid-b193-v50-body-length")
    supported(body[1]==1,"unsupported-b193-subpacket-count")
    supported(body[4]==0x19,"unsupported-b193-subpacket-id")
    supported(body[5]==50,"unsupported-b193-subpacket-version")
    require(u(body,6,2)==176,"invalid-b193-v50-subpacket-size")
    require(u(body,12,2)==1,"invalid-b193-v50-cell-count")
    def bits(offset,n):
        return (int.from_bytes(body,"little") >> offset) & ((1<<n)-1)
    cell=dict(index=0,offset_bytes=24,length_bytes=156,physical_cell_id=u(body,24,2)&511,
        serving_rsrp_dbm=-140+bits(24*8+268,12)*0.0625,
        filtered_rsrp_dbm=-180+bits(24*8+300,12)*0.0625,rsrp_quantization_db=0.0625,
        interpreted_bits=33,uninterpreted_bits=156*8-33)
    fields=dict(packet_version=1,subpacket_count=1,outer_uninterpreted_offset_bytes=2,
        outer_uninterpreted_length_bytes=2,subpacket_id=25,subpacket_version=50,subpacket_size_bytes=176,
        earfcn=u(body,8,4),num_cells=1,valid_rx_bits=u(body,14,2),logical_to_physical_rx_map=u(body,16,4),
        v50_header_extension_offset_bytes=20,v50_header_extension_length_bytes=4,cell_size_bytes=156,
        cells=[cell],semantic_scope="partial-lisa-0xb193-v1-subpacket-0x19-v50",
        uninterpreted_fields="outer word, v50 header extension, and all cell bits except PCI and two RSRP fields")
    return fields,[dict(code="partial-b193-v50-layout",message="only private-corpus-proven Lisa v50 fields are interpreted")]


def call_manager(schema, body):
    event,state,kind=(u(body,n,4) for n in (1,13,17))
    fields=dict(event_code=event,call_client_id=u(body,5,4),call_id=u(body,9,4),state_code=state,
        type_code=kind,decoded_prefix_bytes=21,uninterpreted_tail_bytes=len(body)-21,
        sensitive_call_fields_redacted=True)
    events="originate answer end_request end supplementary_services incoming connect service_option privacy privacy_preference caller_id abbreviated_alert abbreviated_reorder abbreviated_intercept signal display called_party connected_number information extended_display ndss_start ndss_connect".split()
    states="idle origination incoming conversation originating_waiting_for_call_control".split()
    types="voice circuit_switched_data packet_switched_data sms position_determination test otapa standard_otasp nonstandard_otasp emergency supplementary_services videotelephony videotelephony_loopback".split()
    for code,key,names in ((event,"event_name",events),(state,"state_name",states),(kind,"type_name",types)):
        if code<len(names): fields[key]=names[code]
    if event==27: fields["event_name"]="setup_indicator"
    return dict(**common(schema),record_version=3,family=schema.family,call_manager=fields),[
        dict(code="partial-12c1-v3-fixed-prefix",message="only the exact fixed scalar prefix is interpreted; the remaining call fields are redacted")]
