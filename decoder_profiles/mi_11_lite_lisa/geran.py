"""Versioned Lisa RR/GMM/SM wrappers and Android's privacy-safe projections."""
from decoder_core.diag import require as check, uint as u
from decoder_modules import nsg_geran, nsg_gmm
from .decoders import common

RR_NAMES={0:"SYSTEM_INFORMATION_TYPE_13",3:"SYSTEM_INFORMATION_TYPE_2TER",6:"SYSTEM_INFORMATION_TYPE_5TER",
    7:"SYSTEM_INFORMATION_TYPE_2QUATER",13:"CHANNEL_RELEASE",21:"MEASUREMENT_REPORT",22:"CLASSMARK_CHANGE",
    25:"SYSTEM_INFORMATION_TYPE_1",26:"SYSTEM_INFORMATION_TYPE_2",27:"SYSTEM_INFORMATION_TYPE_3",
    28:"SYSTEM_INFORMATION_TYPE_4",29:"SYSTEM_INFORMATION_TYPE_5",30:"SYSTEM_INFORMATION_TYPE_6",
    33:"PAGING_REQUEST_TYPE_1",34:"PAGING_REQUEST_TYPE_2",36:"PAGING_REQUEST_TYPE_3",39:"PAGING_RESPONSE",
    50:"CIPHERING_MODE_COMPLETE",53:"CIPHERING_MODE_COMMAND",63:"IMMEDIATE_ASSIGNMENT"}
GMM_NAMES={1:"ATTACH_REQUEST",2:"ATTACH_ACCEPT",3:"ATTACH_COMPLETE",4:"ATTACH_REJECT",5:"DETACH_REQUEST",
    6:"DETACH_ACCEPT",8:"ROUTING_AREA_UPDATE_REQUEST",9:"ROUTING_AREA_UPDATE_ACCEPT",
    10:"ROUTING_AREA_UPDATE_COMPLETE",11:"ROUTING_AREA_UPDATE_REJECT",18:"AUTHENTICATION_AND_CIPHERING_REQUEST",
    19:"AUTHENTICATION_AND_CIPHERING_RESPONSE",20:"AUTHENTICATION_AND_CIPHERING_REJECT",
    21:"IDENTITY_REQUEST",22:"IDENTITY_RESPONSE"}
PAGE_MODES=("Normal paging","Extended paging","Paging reorganization","Same as before")
CHANNEL_NEEDED=("Any channel","SDCCH","TCH/F","TCH/H or TCH/F")
IDENTITIES={0:"No identity",1:"IMSI",2:"IMEI",3:"IMEISV",4:"TMSI/P-TMSI"}


def shape(condition):
    check(condition,"unobserved-lisa-message-shape")


def decode(schema,body):
    transport,key,message,warning=(rr(body) if schema.log_id==0x5b2f else gprs(body))
    fields=dict(**common(schema),record_version=1,router_peripheral=1,outer_radio_id=1,
        family=schema.family,qualcomm_transport=transport)
    fields[key]=message
    warnings=[] if warning is None else [dict(code=warning,message=(
        "proven message structure decoded; sensitive or unproven information elements remain redacted"
        if warning=="partial-standards-decode" else
        "message is bounded and privacy-redacted but has no semantic decoder"))]
    return fields,warnings


def rr(body):
    check(len(body)>=6,"truncated-5b2f-wrapper")
    channel,downlink=body[1]&127,bool(body[1]&128)
    direction="DOWNLINK" if downlink else "UPLINK"
    declared=body[3]
    check(len(body)==4+declared,"invalid-5b2f-length")
    pseudo_bytes=int(channel in (1,3))
    check(declared>=pseudo_bytes+2,"truncated-5b2f-l3")
    pseudo=-1
    if pseudo_bytes:
        check(body[4]&3==1,"invalid-5b2f-pseudo-length")
        pseudo=body[4]>>2
        check(pseudo<=declared-1,"invalid-5b2f-pseudo-length")
    p=body[4+pseudo_bytes:];pd,kind=p[0]&15,p[1]
    transport=dict(direction=direction,channel_code=channel,
        channel_name={0:"DCCH",1:"BCCH",2:"RACH",3:"CCCH",4:"SACCH",5:"SDCCH",6:"FACCH/F",7:"FACCH/H"}.get(channel,"unknown"),
        diagnostic_message_type=body[2],declared_l3_span_bytes=declared,pseudo_length_bytes=pseudo_bytes,
        bounded_l3_bytes=len(p),packet_version_present=True)
    if pseudo_bytes:transport.update(l2_pseudo_length_value=pseudo,fixed_control_block_bytes=len(p))
    if pd!=6 or body[2]!=kind:
        return transport,"rr",dict(status="preserved-unsupported",message="NON_RR_OR_OPAQUE_SACCH",
            apparent_protocol_discriminator=pd,apparent_high_nibble=p[0]>>4,apparent_inner_type=kind,
            diagnostic_message_type_matches_l3=body[2]==kind,wrapper_boundary_exact=True,
            standard_l3_header_confirmed=False,semantic_name_assigned=False,bounded_inner_bytes=len(p),
            content_redacted=True),"bounded-unsupported-5b2f-message"
    check(p[0]>>4==0,"invalid-rr-skip-indicator")
    fields=dict(status="decoded",message=RR_NAMES.get(kind,f"RR_MESSAGE_{kind}"),protocol_discriminator=6,message_type=kind)
    warning=None
    if kind in (0x27,0x35,0x32):
        shape(channel==0 and pseudo_bytes==0)
        check(downlink==(kind==0x35),"invalid-rr-semantic-direction")
        result=nsg_geran._decode_paging_response(p) if kind==0x27 else nsg_geran._decode_ciphering(p)
        if kind==0x27:
            cm=result["classmark2"]
            fields.update(ciphering_key_sequence=result["ciphering_key_sequence"],
                no_ciphering_key_available=result["no_ciphering_key_available"],
                revision_level=cm["revision_level"],packet_switched_capability=cm["packet_switched_capability"],
                a5_1_available=cm["a5_1_available"],a5_2_available=cm["a5_2_available"],a5_3_available=cm["a5_3_available"],
                identity_type=result["identity"]["identity_type_name"],subscriber_or_temporary_identity_redacted=True,
                additional_update_parameters_present="additional_update_parameters" in result)
        elif kind==0x35:
            fields.update({k:result[k] for k in ("terminal_identity_requested","algorithm_identifier","algorithm_name","start_ciphering")})
        else:
            fields.update(terminal_identity_present=result["terminal_identity_present"],terminal_identity_redacted=result["terminal_identity_present"])
    elif kind==13:
        shape(channel==0 and downlink and declared==3)
        fields.update(rr_cause=p[2],rr_cause_name=RR_CAUSES.get(p[2],f"RR cause {p[2]}"))
    elif kind==22:
        shape(channel==0 and not downlink and declared==20)
        check(p[2]==3 and p[6]==0x20 and 8+p[7]==len(p),"invalid-classmark-change")
        fields.update(classmark2_bytes=3,classmark3_present=True,classmark3_bytes=p[7],
            information_element_boundary_exact=True,radio_capabilities_redacted=True)
    elif kind==21:
        shape(channel==4 and not downlink and declared==18)
        fields.update(measurement(p))
    elif kind in (0,3,6,7,25,26,27,28,29,30):
        if kind in (6,29,30):shape(channel==4 and downlink and declared==18)
        else:shape(channel==1 and downlink and declared==23 and len(p)==22)
        fields.update(system_information(kind,p,pseudo));warning="partial-standards-decode"
    elif kind in (33,34,36,63):
        shape(channel==3 and downlink and declared==23 and len(p)==22)
        fields.update(paging_assignment(kind,p,pseudo));warning="partial-standards-decode"
    else:
        fields.update(status="preserved-unsupported",payload_length=len(p),content_redacted=True)
        warning="bounded-unsupported-rr-message"
    return transport,"rr",fields,warning


def measurement(p):
    check(len(p)==18,"invalid-measurement-report-boundary")
    def bits(start,n):return (int.from_bytes(p,"big")>>(len(p)*8-start-n))&((1<<n)-1)
    neighbors=bits(39,3);neighbors=0 if neighbors==7 else neighbors
    used=42+neighbors*17
    check(used<=len(p)*8,"invalid-measurement-report-boundary")
    check(all(bits(i,1)==0 for i in range(used,len(p)*8)),"invalid-measurement-report-padding")
    return dict(measurement_results_bytes=16,ba_used=bits(16,1),dtx_used=bits(17,1)==1,
        rxlev_full_serving_cell=bits(18,6),three_g_ba_used=bits(24,1),measurements_valid=bits(25,1)==0,
        rxlev_sub_serving_cell=bits(26,6),si23_ba_used=bits(32,1),rxqual_full_serving_cell=bits(33,3),
        rxqual_sub_serving_cell=bits(36,3),neighbor_measurement_count=neighbors,
        neighbor_measurements_redacted=neighbors>0,padding_validated=True)


def system_information(kind,p,pseudo):
    expected={0:0,3:18,7:1,25:21,26:22,27:18,28:12}
    if kind in (6,29,30):check(len(p)==18 and pseudo==-1,"invalid-system-information-boundary")
    else:check(len(p)==22 and pseudo==expected[kind],"invalid-system-information-pseudo-length")
    layouts={
        6:(["NEIGHBOR_CELL_DESCRIPTION_2_16"],16,0),29:(["NEIGHBOR_CELL_DESCRIPTION_16"],16,0),
        30:(["CELL_IDENTITY_2","LOCATION_AREA_IDENTITY_5","CELL_OPTIONS_SACCH_1","NCC_PERMITTED_1","SI6_REST_OCTETS_7"],9,7),
        0:(["SI13_REST_OCTETS_20"],0,20),3:(["NEIGHBOR_CELL_DESCRIPTION_2_16","SI2TER_REST_OCTETS_4"],16,4),
        7:(["SI2QUATER_REST_OCTETS_20"],0,20),25:(["CELL_CHANNEL_DESCRIPTION_16","RACH_CONTROL_PARAMETERS_3","SI1_REST_OCTETS_1"],19,1),
        26:(["NEIGHBOR_CELL_DESCRIPTION_16","NCC_PERMITTED_1","RACH_CONTROL_PARAMETERS_3"],20,0),
        27:(["CELL_IDENTITY_2","LOCATION_AREA_IDENTITY_5","CONTROL_CHANNEL_DESCRIPTION_3","CELL_OPTIONS_BCCH_1","CELL_SELECTION_PARAMETERS_2","RACH_CONTROL_PARAMETERS_3","SI3_REST_OCTETS_4"],16,4),
        28:(["LOCATION_AREA_IDENTITY_5","CELL_SELECTION_PARAMETERS_2","RACH_CONTROL_PARAMETERS_3","SI4_OPTIONAL_AND_REST_OCTETS_10"],10,10)}
    elements,mandatory,rest=layouts[kind]
    return dict(status="decoded-partial",l2_pseudo_length_value=pseudo,information_element_layout=elements,
        mandatory_information_bytes=mandatory,bounded_rest_or_optional_bytes=rest,
        frequency_lists_redacted=kind in (25,26,3,29,6),network_identifiers_redacted=kind in (27,28,30),
        unparsed_rest_octets_redacted=rest>0)


def paging_assignment(kind,p,pseudo):
    combined=p[2]
    check(combined&12==0,"invalid-paging-or-assignment-boundary")
    fields=dict(status="decoded-partial",l2_pseudo_length_value=pseudo,page_mode=combined&3,
                page_mode_name=PAGE_MODES[combined&3])
    if kind!=63:
        fields.update(channel_needed_identity_1=(combined>>4)&3,channel_needed_identity_1_name=CHANNEL_NEEDED[(combined>>4)&3])
    if kind==33:
        check(pseudo in (5,9) and p[3]>0 and 4+p[3]==pseudo,"invalid-paging-request-boundary")
        fields.update(channel_needed_identity_2=(combined>>6)&3,channel_needed_identity_2_name=CHANNEL_NEEDED[(combined>>6)&3],
            mobile_identity_element_count=1,mobile_identity_type=p[4]&7,mobile_identity_type_name=IDENTITIES.get(p[4]&7,"other"),
            mobile_identity_bytes=p[3],rest_octets_bytes=len(p)-pseudo,subscriber_or_temporary_identity_redacted=True)
    elif kind==34:
        check(combined&0xcc==0 and pseudo in (11,18),"invalid-paging-request-boundary")
        optional=pseudo>11
        if optional:check(p[11]==0x17 and p[12]>0 and 13+p[12]==pseudo,"invalid-paging-request-boundary")
        fields.update(fixed_temporary_identity_count=2,optional_mobile_identity_present=optional,
            temporary_identity_count=2+int(optional),rest_octets_bytes=len(p)-pseudo,
            subscriber_or_temporary_identities_redacted=True)
    elif kind==36:
        check(combined&0xcc==0 and pseudo==19,"invalid-paging-request-boundary")
        fields.update(temporary_identity_count=4,temporary_identity_bytes=16,rest_octets_bytes=len(p)-pseudo,
            subscriber_or_temporary_identities_redacted=True,unparsed_rest_octets_redacted=True)
    else:
        shape(pseudo==11)
        check(11+p[10]==pseudo and combined>>4<=7 and p[9]&0xc0==0,"invalid-immediate-assignment-boundary")
        mode=combined>>4
        fields.update(dedicated_mode_or_tbf=mode,dedicated_mode_or_tbf_name={0:"Dedicated mode resource",
            1:"Uplink TBF or second two-message assignment",2:"Not used",3:"Downlink TBF",4:"Not used",
            5:"First of two uplink-TBF assignment messages",6:"Not used",7:"First of two downlink-TBF assignment messages"}[mode],
            channel_description_present=True,channel_or_frequency_assignment_redacted=True,request_reference_present=True,
            request_reference_redacted=True,timing_advance_present=True,timing_advance=p[9],mobile_allocation_bytes=p[10],
            rest_octets_bytes=len(p)-pseudo,unparsed_rest_octets_redacted=True)
    return fields


def gprs(body):
    check(len(body)>=257,"truncated-5c30-wrapper")
    direction=body[1]
    check(direction in (0,1),"invalid-5c30-direction")
    n=u(body,3,2)
    check(n>=2 and len(body)==5+n+250,"invalid-5c30-length")
    p=body[5:5+n];pd,kind=p[0]&15,p[1]
    check(kind==body[2],"invalid-5c30-message-type")
    transport=dict(direction="UPLINK" if direction==0 else "DOWNLINK",direction_code=direction,
        diagnostic_message_type=kind,l3_length=n,opaque_trailing_bytes=250,opaque_tail_redacted=True,
        packet_version_present=True)
    if pd not in (8,10):
        return transport,"gprs_l3",dict(status="preserved-unsupported",family=f"PROTOCOL_{pd}",
            protocol_discriminator=pd,message_type=kind,payload_length=len(p),content_redacted=True),"bounded-unsupported-gprs-protocol"
    if pd==8:
        check(p[0]>>4==0,"invalid-gmm-skip-indicator")
        if kind in (8,11,18,19,20):
            fields=gmm_shared(p,direction,kind)
        elif kind in (1,2,3):
            fields=gmm_attach(p,direction,kind)
        else:
            return transport,"gmm",dict(status="preserved-unsupported",message=GMM_NAMES.get(kind,f"GMM_MESSAGE_{kind}"),
                protocol_discriminator=8,message_type=kind,payload_length=len(p),content_redacted=True),"bounded-unsupported-gmm-message"
        return transport,"gmm",fields,None
    if kind in (0x41,0x42):
        return transport,"gprs_l3",sm(p,direction,kind),None
    return transport,"gprs_l3",dict(status="preserved-unsupported",family="GPRS_SESSION_MANAGEMENT",
        protocol_discriminator=10,message_type=kind,message=f"SM_MESSAGE_{kind}",payload_length=len(p),
        content_redacted=True),"bounded-unsupported-sm-message"


def gmm_shared(p,direction,kind):
    check(direction==(0 if kind in (8,19) else 1),"invalid-gmm-message-direction")
    result=nsg_gmm._rau(p) if kind in (8,11) else nsg_gmm._auth(p)
    fields={k:result[k] for k in ("status","message","protocol_discriminator","message_type")}
    if kind==8:
        for k in ("ciphering_key_sequence","no_ciphering_key_available","follow_on_request","update_type","update_type_name"):fields[k]=result[k]
        fields.update(radio_access_capability_bytes=result["ms_radio_access_capability"]["length"],optional_element_count=len(result["optional_elements"]),network_and_mobile_identities_redacted=True)
    elif kind==11:
        for k in ("gmm_cause","gmm_cause_name","force_to_standby"):fields[k]=result[k]
        fields.update(optional_element_count=len(result["optional_elements"]),network_and_mobile_identities_redacted=True)
    elif kind==18:
        for k in ("terminal_identity_requested","ciphering_algorithm","ciphering_algorithm_name","authentication_ciphering_reference","force_to_standby"):fields[k]=result[k]
        fields.update(rand_present="rand_hex" in result,autn_present="autn_hex" in result,mac_present="mac_hex" in result,security_material_redacted=True)
    elif kind==19:
        fields.update(authentication_ciphering_reference=result["authentication_ciphering_reference"],
            sres_present="sres_hex" in result,terminal_identity_present="imeisv" in result,
            response_extension_present="authentication_response_extension_hex" in result,mac_present="mac_hex" in result,
            security_and_identity_material_redacted=True)
    return fields


def optional(p,start,family):
    names=[];pos=start
    while pos<len(p):
        tag=p[pos];item=OPTIONAL[family].get(tag) or OPTIONAL_HALF[family].get(tag&0xf0)
        check(item is not None,"unrecognized optional IE at an observed message boundary")
        name,size=item
        check(name not in names,"duplicate optional IE")
        if size==0:
            check(pos+2<=len(p),"optional TLV length is truncated");size=2+p[pos+1]
        elif size==-1:
            check(pos+3<=len(p),"optional extended TLV length is truncated");size=3+int.from_bytes(p[pos+1:pos+3],"big")
        check(size>0 and pos+size<=len(p),"optional IE crosses the exact Layer-3 boundary")
        names.append(name);pos+=size
    return dict(optional_bytes=len(p)-start,optional_ie_count=len(names),optional_ie_names=names,optional_ie_boundaries_exact=True)


def gmm_attach(p,direction,kind):
    fields=dict(status="decoded",message=GMM_NAMES[kind],protocol_discriminator=8,message_type=kind)
    if kind==3:
        shape(direction==0 and len(p)==2);return fields
    if kind==1:
        shape(direction==0 and len(p)==63)
        check(p[2]==4,"invalid-attach-request-boundary")
        combined=p[7];cksn=combined>>4;attach=combined&7
        check(cksn<=7 and 1<=attach<=4 and p[10]==5,"invalid-attach-request-boundary")
        pos=11+p[10]+6
        check(pos<len(p) and p[pos]==32,"invalid-attach-request-boundary")
        end=pos+1+p[pos]
        check(len(p)-end==8,"invalid-attach-request-boundary")
        fields.update(attach_type=attach,attach_type_name={1:"GPRS attach",2:"not used",3:"combined GPRS/IMSI attach",4:"emergency attach"}[attach],
            follow_on_request=bool(combined&8),ciphering_key_sequence=cksn,no_ciphering_key_available=cksn==7,
            network_capability_bytes=4,mobile_identity_type=p[11]&7,mobile_identity_type_name=IDENTITIES.get(p[11]&7,"other"),
            mobile_identity_bytes=5,radio_access_capability_bytes=32,network_identity_and_capabilities_redacted=True,
            **optional(p,end,"ATTACH_REQUEST"))
    else:
        shape(direction==1 and len(p)==25)
        combined,priorities=p[2],p[4]
        check(combined>>4<=1 and 1<=combined&15<=3 and priorities&0x88==0,"invalid-attach-accept-boundary")
        fields.update(attach_result=combined&15,force_to_standby=combined>>4==1,
            periodic_rau_timer_unit=p[3]>>5,periodic_rau_timer_value=p[3]&31,sms_radio_priority=priorities&7,
            tom8_radio_priority=(priorities>>4)&7,routing_area_identity_present=True,routing_area_identity_redacted=True,
            network_identity_and_optional_content_redacted=True,**optional(p,11,"ATTACH_ACCEPT"))
    return fields


def sm(p,direction,kind):
    fields=dict(status="decoded",family="GPRS_SESSION_MANAGEMENT",message="ACTIVATE_PDP_CONTEXT_REQUEST" if kind==65 else "ACTIVATE_PDP_CONTEXT_ACCEPT",
        protocol_discriminator=10,message_type=kind,transaction_identifier=(p[0]>>4)&7,transaction_identifier_flag=p[0]>>7)
    if kind==65:
        shape(direction==0 and len(p)==74)
        check(p[2]&0xf0==0 and p[3]&0xf0==0 and p[4]==14 and p[19]==2 and p[20]&0xf0==0,"invalid-sm-request-boundary")
        org,typ=p[20]&15,p[21]
        name=({0:"legacy reserved",1:"PPP",2:"non-IP"}.get(typ,"ETSI reserved") if org==0 else
              {33:"IPv4",87:"IPv6",141:"IPv4v6"}.get(typ,"IETF unknown") if org==1 else "Empty" if org==15 and typ==0 else "Not specified")
        opts=optional(p,22,"ACTIVATE_PDP_REQUEST");names=opts["optional_ie_names"]
        fields.update(nsapi=p[2]&15,llc_sapi=p[3]&15,requested_qos_bytes=14,requested_qos_redacted=True,
            pdp_address_bytes=2,pdp_type_organization=org,pdp_type_number=typ,pdp_type_name=name,
            dynamic_address_requested=True,pdp_address_redacted=True,apn_present="ACCESS_POINT_NAME" in names,
            apn_redacted="ACCESS_POINT_NAME" in names,protocol_configuration_options_present="PROTOCOL_CONFIGURATION_OPTIONS" in names,
            optional_content_redacted=True,**opts)
    else:
        shape(direction==1 and len(p)==58)
        check(p[2]&0xf0==0 and p[3]==12 and p[16]&0xf8==0,"invalid-sm-accept-boundary")
        opts=optional(p,17,"ACTIVATE_PDP_ACCEPT");names=opts["optional_ie_names"]
        fields.update(llc_sapi=p[2]&15,negotiated_qos_bytes=12,negotiated_qos_redacted=True,
            radio_priority=p[16]&7,pdp_address_present="PDP_ADDRESS" in names,pdp_address_redacted="PDP_ADDRESS" in names,
            protocol_configuration_options_present="PROTOCOL_CONFIGURATION_OPTIONS" in names,optional_content_redacted=True,**opts)
    return fields


OPTIONAL = {
    "ATTACH_REQUEST": {0x19: ("OLD_P_TMSI_SIGNATURE", 4), 0x17: ("READY_TIMER", 2), 0x33: ("PS_LCS_CAPABILITY", 0), 0x11: ("MS_CLASSMARK_2", 0), 0x20: ("MS_CLASSMARK_3", 0), 0x40: ("SUPPORTED_CODEC_LIST", 0), 0x58: ("UE_NETWORK_CAPABILITY", 0), 0x1a: ("ADDITIONAL_MOBILE_IDENTITY", 0), 0x1b: ("ADDITIONAL_OLD_ROUTING_AREA_IDENTITY", 0), 0x5d: ("VOICE_DOMAIN_PREFERENCE", 0), 0x14: ("OLD_LOCATION_AREA_IDENTITY", 0), 0x10: ("TMSI_BASED_NRI_CONTAINER", 0), 0x6a: ("T3324_VALUE", 0), 0x39: ("T3312_EXTENDED_VALUE", 0), 0x6e: ("EXTENDED_DRX_PARAMETERS", 0)},
    "ATTACH_ACCEPT": {0x19: ("P_TMSI_SIGNATURE", 4), 0x17: ("NEGOTIATED_READY_TIMER", 2), 0x18: ("ALLOCATED_P_TMSI", 0), 0x23: ("MOBILE_IDENTITY", 0), 0x25: ("GMM_CAUSE", 2), 0x2a: ("T3302_VALUE", 0), 0x4a: ("EQUIVALENT_PLMN_LIST", 0), 0x34: ("EMERGENCY_NUMBER_LIST", 0), 0x37: ("T3319_VALUE", 0), 0x38: ("T3323_VALUE", 0), 0x39: ("T3312_EXTENDED_VALUE", 0), 0x66: ("ADDITIONAL_NETWORK_FEATURE_SUPPORT", 0), 0x6a: ("T3324_VALUE", 0), 0x6e: ("EXTENDED_DRX_PARAMETERS", 0), 0x8c: ("CELL_NOTIFICATION", 1)},
    "ACTIVATE_PDP_REQUEST": {0x28: ("ACCESS_POINT_NAME", 0), 0x27: ("PROTOCOL_CONFIGURATION_OPTIONS", 0), 0x33: ("NBIFOM_CONTAINER", 0), 0x7b: ("EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS", -1), 0x5c: ("EXTENDED_QOS", 0)},
    "ACTIVATE_PDP_ACCEPT": {0x2b: ("PDP_ADDRESS", 0), 0x27: ("PROTOCOL_CONFIGURATION_OPTIONS", 0), 0x34: ("PACKET_FLOW_IDENTIFIER", 0), 0x39: ("SM_CAUSE", 0), 0x33: ("NBIFOM_CONTAINER", 0), 0x7b: ("EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS", -1), 0x5c: ("EXTENDED_QOS", 0)},
}

OPTIONAL_HALF = {
    "ATTACH_REQUEST": {0x90: ("TMSI_STATUS", 1), 0xd0: ("DEVICE_PROPERTIES", 1), 0xe0: ("P_TMSI_TYPE", 1), 0xc0: ("MS_NETWORK_FEATURE_SUPPORT", 1), 0xf0: ("ADDITIONAL_UPDATE_TYPE", 1)},
    "ATTACH_ACCEPT": {0xb0: ("NETWORK_FEATURE_SUPPORT", 1), 0xa0: ("REQUESTED_MS_INFORMATION", 1), 0xc0: ("UPLINK_DATA_STATUS_INTEGRITY", 1)},
    "ACTIVATE_PDP_REQUEST": {0xa0: ("REQUEST_TYPE", 1), 0xc0: ("DEVICE_PROPERTIES", 1)},
    "ACTIVATE_PDP_ACCEPT": {0xb0: ("CONNECTIVITY_TYPE", 1), 0xc0: ("WLAN_OFFLOAD_INDICATION", 1)},
}

RR_CAUSES={0:"Normal event",1:"Abnormal release, unspecified",2:"Abnormal release, channel unacceptable",
    3:"Abnormal release, timer expired",4:"Abnormal release, no activity",5:"Preemptive release",
    8:"Handover impossible, timing advance out of range",9:"Channel mode unacceptable",10:"Frequency not implemented",
    65:"Call already cleared",95:"Semantically incorrect message",96:"Invalid mandatory information",
    97:"Message type not implemented",98:"Message incompatible with protocol state",100:"Conditional IE error",
    101:"No cell allocation available",111:"Protocol error, unspecified"}
