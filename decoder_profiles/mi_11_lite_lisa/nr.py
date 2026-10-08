"""Exact partial NR envelopes. Observation is never a current NSA/SA claim."""
from decoder_core.diag import uint as u, require, supported
from decoder_modules import nr_rrc
from .decoders import common
from .privacy import sanitize


def decode(schema, body):
    fields=dict(**common(schema),mode_scope="nsa-corpus-only",sa_compatibility_inferred=False,
                record_version=schema.version,family=schema.family)
    if schema.log_id==0xb821:
        supported(u(body,0,4)==12,"unsupported-b821-body-version")
        supported(body[4:6]==bytes((15,160)),"unsupported-b821-v12-runtime-release-tuple")
        require(u(body,21,2)==len(body)-23,"b821-v12-message-length-mismatch")
        pci,arfcn,pdu=u(body,7,2),u(body,9,4),body[16]
        require(pci==0xffff or pci<=1007,"b821-v12-invalid-physical-cell-id")
        require(arfcn==0xffffffff or arfcn<=3279165,"b821-v12-invalid-nr-arfcn")
        rrc=nr_rrc.decode(pdu,body[23:])
        fields.update(schema_evidence="exact-nsg-v12-schema-plus-scat-exact-v12-plus-ts38331-plus-lisa-private-replay",
            decoder_scope="exact-envelope-and-observed-direct-rrc-roots",rrc_release_major_raw=15,
            rrc_release_version_raw=160,rrc_release_number=15,rrc_release_major=10,rrc_release_minor=0,
            rrc_release_version="15.10.0",
            rrc_release_version_encoding="u16le:number=bits[7:0],major=bits[15:12],minor=bits[11:8]",
            rrc_release_reserved_bit_count=0,rrc_release_version_semantics_proven=True,
            radio_bearer_id=body[6],physical_cell_id_present=pci!=0xffff,
            nr_arfcn_present=arfcn!=0xffffffff,all_ones_radio_context_form_observed=pci==0xffff and arfcn==0xffffffff,
            timing_field_octets=3,timing_sfn_subframe_slot_semantics_proven=False,timing_field_redacted=True,
            pdu_number=pdu,message_kind=nr_rrc.ROOTS[pdu][1],
            embedded_direction="uplink" if pdu==10 else "internal_control",sib_mask=u(body,17,4),
            message_length=len(body)-23,rrc=sanitize(rrc),rrc_raw_bytes_in_projection=False)
        if pci!=0xffff: fields["physical_cell_id"]=pci
        if arfcn!=0xffffffff: fields["nr_arfcn"]=arfcn
        return fields,[dict(code="b821-v12-timing-encoding-unproven",
            message="three-byte timing boundary is exact; SFN/subframe/slot packing remains opaque")]
    supported(u(body,0,2)==1 and u(body,2,2)==2,"unsupported-b889-composite-version")
    supported(body[15]==1,"unsupported-b889-record-count")
    reason={0:"connection_request",1:"radio_link_failure",2:"handover",3:"uplink_data_arrival",6:"beam_failure"}.get(body[18])
    contention={0:"contention_free",1:"downlink_mac_control_element",2:"uplink_grant",3:"pdcch_c_rnti"}.get(body[21])
    supported(reason is not None,"unsupported-b889-rach-reason")
    supported(contention is not None,"unsupported-b889-contention-type")
    require(body[23]<=6,"invalid-b889-msg3-size")
    fields.update(schema_evidence="mobileinsight-4330fa9-exact-v2.1-plus-lisa-private-replay",
        decoder_scope="exact-v2.1-core-with-opaque-lisa-suffix",composite_version="2.1",public_core_bytes=30,
        record_count=1,procedure="random_access_trigger",direction="uplink",sleep=body[4],
        downlink_dynamic_config_change=body[7],downlink_config=body[8],ml1_state_change=body[9]>>4,
        uplink_config=body[9]&15,log_fields_change_bitmap=u(body,12,2),reason_code=body[18],reason=reason,
        carrier_id=body[19],first_active_uplink_bwp=body[20],contention_code=body[21],contention=contention,
        msg3_size=body[23],msg3_field_bytes=6,msg3_unused_bytes=6-body[23],subscription_redacted=True,
        c_rnti_redacted=True,random_access_identifier_redacted=True,msg3_redacted=True,
        lisa_suffix_bytes=2,lisa_suffix_semantics_proven=False,lisa_suffix_redacted=True)
    return fields,[dict(code="b889-v1-lisa-suffix-opaque",
        message="the exact v2.1 core is decoded; the two-byte Lisa suffix remains uninterpreted")]
