"""Exact/partial Lisa MAC/RLC/PDCP projections (Mi11LteLowerLayerDecoder)."""
from decoder_core.diag import uint as u, require as check, require_range as bounded, supported


def container(body, count):
    bounded(body, 0, 4)
    supported(body[1] == count, "unsupported-subpacket-count")
    cursor, packets = 4, []
    for _ in range(count):
        bounded(body, cursor, 4)
        size = u(body, cursor + 2, 2)
        check(size >= 4, "invalid-subpacket-size")
        bounded(body, cursor, size)
        packets.append((body[cursor], body[cursor + 1], size, body[cursor + 4:cursor + size]))
        cursor += size
    check(cursor == len(body), "invalid-container-trailing-bytes")
    return packets


def packet(body, sid, version, size=None):
    item = container(body, 1)[0]
    supported(item[:3] == (sid, version, size or len(body) - 4),
              "unsupported-subpacket-layout")
    return item[3]


def partial(fields, code, message):
    return fields, [{"code": code, "message": message}]


def decode(log_id, body):
    return DECODERS[log_id](body)


def b061(body):
    config, reason = container(body, 2)
    supported(config[:3] == (3, 8, 32) and reason[:3] == (5, 2, 24),
              "unsupported-b061-subpacket-layout")
    p = reason[3]
    check(len(p) == 20, "invalid-b061-reason-length")
    reason_code = p[2]
    def sub(item, role, status):
        return dict(id=item[0], version=item[1], size_bytes=item[2], role=role,
                    status=status, content_redacted=True)
    return partial(dict(layer="mac", procedure="random_access_trigger", packet_version=1,
        subpacket_count=2, subpackets=[sub(config, "configuration", "opaque-uninterpreted"),
                                     sub(reason, "trigger_reason", "partial")],
        reason_code=reason_code, reason={0:"connection_request",1:"radio_link_failure",
            2:"uplink_data",3:"downlink_data",4:"handover"}.get(reason_code,"unknown"),
        message3_size_bytes=p[12], group_chosen=p[13], temporary_radio_identifiers_redacted=True,
        matching_identifier_redacted=True, configuration_payload_bytes=len(config[3]),
        uninterpreted_reason_suffix_bytes=3), "partial-b061-v1-layout",
        "configuration subpacket and three-byte reason suffix remain uninterpreted")


def b062(body):
    p = packet(body, 6, 49, 52)
    check(len(p) == 48, "invalid-b062-attempt-length")
    supported(p[5] == 7, "unsupported-b062-message-mask")
    return partial(dict(layer="mac", procedure="random_access_attempt", packet_version=1,
        subpacket_id=6, subpacket_version=49, subpacket_size_bytes=52, result_code=p[3],
        result={0:"success",1:"failure_at_message2",4:"aborted"}.get(p[3],"unknown"),
        contention_based=p[4] != 0, message_mask=7, message1_present=True,
        message2_present=True,message3_present=True,message1_bytes=4,message2_bytes=7,
        message3_bytes=17,v49_extension_bytes=14,temporary_radio_identifiers_redacted=True,
        uplink_grant_redacted=True,message3_content_redacted=True), "partial-b062-v49-layout",
        "the exact v49 extension boundary is known but its contents remain uninterpreted")


def b063(body):
    check(len(body) >= 24, "invalid-b063-v50-length")
    blocks = u(body,4,2)
    check(0 < blocks <= (len(body)-8)//16, "invalid-b063-v50-block-count")
    return partial(dict(layer="mac",procedure="downlink_transport_block",packet_version=50,
        transport_block_count=blocks,logical_channel_count=body[6],reason_code=body[7],
        common_header_bytes_per_block=16,opaque_transport_region_bytes=len(body)-8,
        mac_sdu_content_redacted=True),"partial-b063-v50-envelope",
        "v50 block count is bounded but dynamic SDU/group contents remain opaque")


def b064(body):
    p = packet(body,8,2)
    bounded(p,0,1)
    count, cursor, samples = p[0],1,[]
    for index in range(count):
        bounded(p,cursor,14)
        n = p[cursor+13]
        bounded(p,cursor+14,n)
        t = u(p,cursor+4,2)
        samples.append(dict(index=index,subscription_id=p[cursor],cell_index=p[cursor+1],
            harq_id=p[cursor+2],rnti_type_code=p[cursor+3],system_frame_number=t>>4,
            subframe=t&15,grant_bytes=u(p,cursor+6,2),rlc_pdu_count=p[cursor+8],
            padding_bytes=u(p,cursor+9,2),bsr_event_code=p[cursor+11],
            bsr_trigger_code=p[cursor+12],mac_header_bytes=n,mac_header_redacted=True))
        cursor += 14+n
    check(0 <= len(p)-cursor <= 3,"invalid-b064-alignment")
    return dict(layer="mac",procedure="uplink_transport_block",packet_version=1,
        subpacket_id=8,subpacket_version=2,sample_count=count,samples=samples,
        alignment_bytes=len(p)-cursor), []


def b083(body):
    check(len(body)>=18,"invalid-b083-v48-length")
    check(body[1]==0 and u(body,2,2)==0 and body[5]==0 and u(body,6,2)==0,
          "invalid-b083-v48-header")
    count=body[4]
    check(count>0 and len(body)==8+count*10,"invalid-b083-v48-entry-count")
    return partial(dict(layer="rlc",procedure="downlink_control_or_configuration",
        packet_version=48,entry_count=count,entry_size_bytes=10,opaque_entry_bytes=count*10,
        entry_content_redacted=True),"partial-b083-v48-layout",
        "the exact v48 entry boundary is known but entry fields remain uninterpreted")


def b082(body):
    check(len(body)>=68,"invalid-b082-v48-length")
    check(body[1]==0 and u(body,2,2)==0,"invalid-b082-v48-header")
    nm,ns=u(body,4,2),u(body,6,2)
    check(nm>0 and ns>0 and len(body)==8+ns*20+nm*40,"invalid-b082-v48-count")
    cursor,states,metadata=8,[],[]
    for index in range(ns):
        states.append(dict(index=index,rb_config_index=body[cursor],
            configuration_code=body[cursor+1],configuration_extension_code=u(body,cursor+2,2),
            rx_next=u(body,cursor+4,4),rx_next_status_trigger=u(body,cursor+8,4),
            rx_high_status=u(body,cursor+12,4),rx_next_high=u(body,cursor+16,4),
            mode_and_sn_length_uninterpreted=True))
        cursor+=20
    statuses=("pdu_data","pdu_control","pdu_invalid","pdu_outside_receive_window",
              "pdu_dropped_flow_control","um_pdu_discarded")
    for index in range(nm):
        subframe,sfn,status,flags=u(body,cursor,2),u(body,cursor+2,2),body[cursor+5],u(body,cursor+24,4)
        check(subframe<=9 and sfn<=1023,"invalid-b082-system-time")
        check(u(body,cursor+6,2)==0 and flags & ~31==0,"invalid-b082-metadata-flags")
        check(status<=5,"invalid-b082-status")
        metadata.append(dict(index=index,system_frame_number=sfn,subframe=subframe,
            rb_config_index=body[cursor+4],status_code=status,status=statuses[status],
            start_sequence_number=u(body,cursor+8,4),end_sequence_number=u(body,cursor+12,4),
            segment_offset_start=u(body,cursor+16,4),segment_offset_end=u(body,cursor+20,4),
            polling_bit=bool(flags&1),last_segment_flag=bool(flags&2),tail_segment=bool(flags&4),
            head_segment=bool(flags&8),inner_segment=bool(flags&16),
            payload_length_bytes=u(body,cursor+28,4),pdcp_sequence_metadata_redacted=True,
            rlc_pdcp_content_opaque=True))
        cursor+=40
    check(cursor==len(body),"invalid-b082-v48-consumption")
    return partial(dict(layer="rlc",procedure="downlink_am_pdu_metadata",packet_version=48,
        rlc_state_count=ns,metadata_count=nm,rlc_state_record_bytes=20,metadata_record_bytes=40,
        rlc_states=states,pdu_metadata=metadata,raw_rlc_pdu_present=False,
        pdcp_content_policy="opaque-sensitive-local-only"),"partial-b082-v48-configuration",
        "mode/SN configuration codes remain uninterpreted and PDCP metadata is redacted")


def b092(body):
    p=packet(body,0x46,4)
    bounded(p,0,20)
    count,cursor,pdus=u(p,18,2),20,[]
    for index in range(count):
        bounded(p,cursor,9)
        t,n=u(p,cursor,2),u(p,cursor+4,2)
        check(n>=2,"invalid-b092-logged-length")
        bounded(p,cursor+9,n-2)
        look,low=p[cursor+7],p[cursor+8]
        item=dict(index=index,rb_config_index=p[0],system_frame_number=t>>4,subframe=t&15,
            pdu_size_bytes=u(p,cursor+2,2),logged_header_bytes=n,logged_extension_bytes=n-2,
            logged_content_redacted=True)
        if look<16:
            item.update(pdu_type="control",ack_sequence_number=look*64+low//4)
        else:
            item.update(pdu_type="data",sequence_number=low+((look>>1)&1)*512+(look&1)*256,
                resegmentation_flag=(look>>6)&1,polling_bit=(look>>5)&1,
                framing_info=(look>>3)&3,extension_bit=(look>>2)&1)
        pdus.append(item)
        cursor+=9+n-2
    check(0<=len(p)-cursor<=3,"invalid-b092-alignment")
    return dict(layer="rlc",procedure="uplink_am_pdu",packet_version=1,subpacket_id=0x46,
        subpacket_version=4,rb_config_index=p[0],rlc_mode_code=p[1],sequence_number_length_bits=p[2],
        enabled_pdu_log_mask=u(p,4,2),pdu_count=count,pdus=pdus,alignment_bytes=len(p)-cursor),[]


def b0b3(body):
    p=packet(body,0xc3,40)
    bounded(p,0,36)
    count,cursor,pdus=u(p,34,2),36,[]
    for index in range(count):
        bounded(p,cursor,13)
        config,n,t=u(p,cursor,2),u(p,cursor+4,2),u(p,cursor+6,2)
        bounded(p,cursor+13,n)
        sn=(config>>7)&7
        pdus.append(dict(index=index,config_index=config&63,rlc_mode="UM" if (config>>6)&1 else "AM",
            sequence_number_length_code=sn,sequence_number_length_bits={0:5,1:7,2:12,3:15,4:18}.get(sn,"unknown"),
            bearer_id=(config>>10)&31,valid_pdu=bool(config>>15),pdu_size_bytes=u(p,cursor+2,2),
            logged_bytes=n,system_frame_number=t>>4,subframe=t&15,sequence_number=u(p,cursor+8,4),
            compression_type_code=p[cursor+12],cipher_data_redacted=True))
        cursor+=13+n
    check(0<=len(p)-cursor<=3,"invalid-b0b3-alignment")
    return dict(layer="pdcp",procedure="uplink_cipher_data",packet_version=1,subpacket_id=0xc3,
        subpacket_version=40,security_prefix_bytes=32,security_prefix_redacted=True,
        srb_cipher_algorithm_code=p[32],drb_cipher_algorithm_code=p[33],pdu_count=count,pdus=pdus,
        alignment_bytes=len(p)-cursor,cipher_data_policy="opaque-sensitive-local-only"),[]


DECODERS={0xb061:b061,0xb062:b062,0xb063:b063,0xb064:b064,0xb082:b082,
          0xb083:b083,0xb092:b092,0xb0b3:b0b3}
