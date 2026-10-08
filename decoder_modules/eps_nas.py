"""Strict EPS NAS semantic boundary shared independently of capture/phone layout.

Reuses the existing standard NAS parser for accepted core families; supplemental
projections follow Mi11ObservedNasSemantics, without Poco's proprietary-tail retry.
"""
from decoder_core.diag import require, require_range as bounded, supported
from .nsg_nas import decode_lte_nas, _security_metadata

CORE_EMM={0x41,0x44,0x52,0x53,0x55,0x56,0x5d,0x5e,0x45,0x62,0x63}


def direction_check(actual, expected):
    require(actual==expected,f"NAS message requires {expected} direction")


def lv(p, offset):
    bounded(p,offset,1)
    end=offset+1+p[offset]
    bounded(p,offset+1,p[offset])
    return end


def decode(p, direction, _inner=False):
    require(bool(p),"empty NAS PDU")
    if not any(p) and not _inner:
        return dict(status="placeholder",message="QUALCOMM_NAS_PLACEHOLDER",direction=direction,
            payload_length=len(p),decode_scope="all-zero placeholder; no over-air PDU")
    pd=p[0]&15
    security=p[0]>>4 if pd==7 else 0
    base=dict(payload_hex=p.hex(),payload_length=len(p),direction=direction,
        protocol_discriminator=pd,security_header_type=security,
        security_header_name=_security_metadata(p).get("security_header_name","plain NAS message"))
    if pd==7 and security in (1,2,3,4):
        bounded(p,0,6)
        base.update(mac_hex=p[1:5].hex(),sequence_number=p[5],protected_payload_hex=p[6:].hex(),
            integrity_validation="not-validated: K_NASint, integrity algorithm, bearer direction, and full NAS COUNT are unavailable",
            ciphering="ciphertext preserved; K_NASenc, ciphering algorithm, and full NAS COUNT are required to decrypt" if security in (2,4) else "not ciphered; inner NAS can be decoded",
            status="decoded",message="SECURITY_PROTECTED_NAS_MESSAGE",decoder_class="EMMSecProtNASMessage",
            decoded_fields={"EMMSecProtNASMessage":[{"EMMHeaderSec":[{"SecHdr":security},{"ProtDisc":7}]},
                {"MAC":p[1:5].hex()},{"Seqn":p[5]},{"NASMessage":p[6:].hex()}]},
            decode_scope="security envelope only; inner NAS is ciphered" if security in (2,4) else "security envelope and clear-text inner NAS")
        if security in (1,3):
            # The shared core preserves unknown inner messages, without promoting them.
            base["inner_nas"]=decode(p[6:],direction,_inner=True)
            base["inner_nas_status"]="decoded-from-integrity-only-envelope"
        if not _inner: base["semantic_source"]="accepted-poco-eps-nas-core"
        return base
    if _inner and pd not in (2,7):
        return raw_inner(base,p)
    supported(pd in (2,7),"unsupported-nas-message")
    bounded(p,0,3 if pd==2 else 2)
    msg=p[2] if pd==2 else p[1]
    if security==12 or (pd==7 and msg in CORE_EMM) or (pd==2 and msg in (0xd9,0xda)):
        if pd==7 and security==0 and msg in (0x41,0x44,0x5d,0x5e):
            direction_check(direction,"MT" if msg in (0x44,0x5d) else "MO")
            result={**base,**{0x41:attach_request,0x44:attach_reject,0x5d:security_command,0x5e:security_complete}[msg](p),
                    "decode_scope":"complete unencrypted NAS PDU"}
        else:
            result=decode_lte_nas(p,direction,allow_proprietary_tail=False)
        if result["status"]=="decoder-unavailable":
            raise ImportError("LTE NAS decoding needs pycrate; install requirements.txt")
        require(result["status"]=="decoded",result.get("error","malformed NAS PDU"))
        for key in ("nested_messages","nested_decode_warning"):
            result.pop(key,None)
        strict_core(p,direction,result)
        if not _inner: result["semantic_source"]="accepted-poco-eps-nas-core"
        return result
    if _inner:
        return raw_inner(base,p)
    fields=supplemental(p,direction,pd,msg)
    fields.update(payload_length=len(p),direction=direction,protocol_discriminator=pd,
        security_header_type=0,security_header_name="plain NAS message",
        decode_scope="complete unencrypted NAS PDU",semantic_source="mi11-ts24.301-observed-branch")
    return fields


def raw_inner(base,p):
    return dict(**base,status="preserved-unsupported",message="UNKNOWN_NAS_MESSAGE",decoder_class="RawNasMessage",
        decoded_fields={"RawNasMessage":[{"V":"0x"+p.hex()}]},decode_scope="complete unencrypted NAS PDU")


def supplemental(p,direction,pd,msg):
    fields=dict(status="decoded")
    if pd==2:
        supported(msg in (0xc1,0xc2,0xd0),"unsupported-nas-message")
        fields.update(eps_bearer_identity=p[0]>>4,procedure_transaction_identity=p[1])
        if msg==0xc1:
            direction_check(direction,"MT")
            bounded(p,0,4)
            a=lv(p,3); b=lv(p,a); end=lv(p,b)
            fields.update(message="ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST",eps_qos_length=p[3],
                access_point_name_present=p[a]>0,access_point_name_length=p[a],pdn_address_present=p[b]>0,
                pdn_address_length=p[b],optional_bytes=len(p)-end)
        elif msg==0xc2:
            direction_check(direction,"MO")
            fields.update(message="ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT",optional_bytes=len(p)-3)
        else:
            direction_check(direction,"MO")
            bounded(p,0,4)
            require(p[3]&128==0,"PDN Connectivity Request spare bit is nonzero")
            request,pdn=p[3]&7,(p[3]>>4)&7
            fields.update(message="PDN_CONNECTIVITY_REQUEST",request_type=request,
                request_type_name={1:"initial-request",2:"handover",3:"unused-emergency-bearer-services",4:"initial-emergency-request"}.get(request,"reserved-or-unknown"),
                pdn_type=pdn,pdn_type_name={1:"IPv4",2:"IPv6",3:"IPv4v6",5:"non-IP"}.get(pdn,"reserved-or-unknown"),optional_bytes=len(p)-4)
        return fields
    supported(p[0]>>4==0 and msg in (0x42,0x43,0x61),"unsupported-nas-message")
    if msg==0x42:
        direction_check(direction,"MT")
        bounded(p,0,7)
        require(p[2]>>4==0,"Attach Accept result spare half-octet is nonzero")
        bounded(p,5,p[4]); pos=5+p[4]
        bounded(p,pos,2); n=int.from_bytes(p[pos:pos+2],"big")
        bounded(p,pos+2,n)
        fields.update(message="ATTACH_ACCEPT",eps_attach_result=p[2]&15,
            eps_attach_result_name={1:"EPS-only",2:"combined-EPS-IMSI"}.get(p[2]&15,"reserved-or-unknown"),
            t3412_unit=p[3]>>5,t3412_value=p[3]&31,tai_list_length=p[4],esm_container_length=n,
            optional_bytes=len(p)-(pos+2+n))
    elif msg==0x43:
        direction_check(direction,"MO")
        bounded(p,0,4);n=int.from_bytes(p[2:4],"big")
        require(len(p)==4+n,"Attach Complete has invalid ESM container boundary")
        fields.update(message="ATTACH_COMPLETE",esm_container_length=n)
    else:
        direction_check(direction,"MT")
        pos,names=2,[]
        tags={0x43:"full-network-name",0x45:"short-network-name",0x46:"local-time-zone",
              0x47:"universal-time-and-local-time-zone",0x49:"network-daylight-saving-time"}
        while pos<len(p):
            tag=p[pos]
            require(tag in tags,"unsupported EMM Information IE")
            if tag in (0x43,0x45,0x49):
                bounded(p,pos,2);size=2+p[pos+1]
            else: size=2 if tag==0x46 else 8
            bounded(p,pos,size);names.append(tags[tag]);pos+=size
        fields.update(message="EMM_INFORMATION",information_elements=names,information_element_count=len(names))
    return fields


def strict_core(p, direction, result):
    """Direction/exact-boundary checks from the accepted EPS NAS core."""
    security=p[0]>>4 if p[0]&15==7 else 0
    if security==12:
        require(len(p)==4,"EMM Service Request must be exactly 4 bytes")
        result.update(ksi=p[1]>>5,short_sequence_number=p[1]&31,short_mac_hex=p[2:4].hex(),
            integrity_validation="not-validated: EPS security context and full NAS COUNT are unavailable")
        return
    if p[0]&15!=7:
        return
    msg=p[1]
    names={0x41:"ATTACH_REQUEST",0x44:"ATTACH_REJECT",0x52:"AUTHENTICATION_REQUEST",0x53:"AUTHENTICATION_RESPONSE",
           0x55:"IDENTITY_REQUEST",0x56:"IDENTITY_RESPONSE",0x5d:"SECURITY_MODE_COMMAND",0x5e:"SECURITY_MODE_COMPLETE",
           0x45:"DETACH_REQUEST",0x62:"DOWNLINK_NAS_TRANSPORT",0x63:"UPLINK_NAS_TRANSPORT"}
    if msg in names:result["message"]=names[msg]
    expected={0x41:"MO",0x44:"MT",0x53:"MO",0x55:"MT",0x56:"MO",0x5d:"MT",0x5e:"MO",0x62:"MT",0x63:"MO",0x45:"MO"}.get(msg)
    if expected: direction_check(direction,expected)
    if msg==0x55:
        require(len(p)==3 and p[2]>>4==0,"invalid Identity Request boundary or spare bits")
        result.update(requested_identity_type=p[2]&15,requested_identity_type_name={0:"no identity",1:"IMSI",2:"IMEI",3:"IMEISV",4:"TMSI",5:"TMGI",6:"reserved for future use"}.get(p[2]&15,"reserved"))
    if msg in (0x53,0x56,0x62,0x63):
        bounded(p,0,3);n=p[2]
        require(n>0 and len(p)==3+n,"NAS LV length does not consume the exact PDU")
        if msg==0x53:
            require(4<=n<=16,"RES length must be 4..16 bytes")
            result.update(res_length=n,res_offset=3,res_end_offset=3+n,res_hex=p[3:].hex())
        elif msg in (0x62,0x63):
            result.update(nas_container_length=n,nas_container_offset=3,nas_container_end_offset=3+n,
                nas_container_hex="0x"+p[3:].hex(),contained_protocol_discriminator=p[3]&15)
        else:
            identity=p[3:];kind=identity[0]&7
            result.update(identity_length=n,identity_offset=3,identity_end_offset=3+n,
                identity_hex="0x"+identity.hex(),identity_type=kind,
                identity_type_name={0:"no identity",1:"IMSI",2:"IMEI",3:"IMEISV",4:"TMSI"}.get(kind,"reserved"),identity_present=kind!=0)
            if kind in (1,2,3):
                digits=mobile_identity_digits(identity)
                result["identity_digit_count"]=len(digits)
                result[{1:"imsi_digits",2:"imei_digits",3:"imeisv_digits"}[kind]]=digits
    if msg==0x45:
        result["message"]="DETACH_REQUEST"


def emm_header(p):
    return [{"SecHdr":p[0]>>4},{"ProtDisc":p[0]&15},{"Type":p[1]}]


def esm_header(p):
    bounded(p,0,3)
    return [{"EPSBearerId":p[0]>>4},{"ProtDisc":p[0]&15},{"PTI":p[1]},{"Type":p[2]}]


def ksi(value):
    return [{"NAS_KSI":[{"TSC":(value>>3)&1},{"Value":value&7}]}]


def identity_tree(p):
    bounded(p,0,1)
    tree=[{"Digit1":p[0]>>4},{"Odd":(p[0]>>3)&1},{"Type":p[0]&7}]
    if p[0]&7==6:
        require(len(p)==11,"GUTI EPS identity must be exactly 11 bytes")
        tree += [{"PLMN":p[1:4].hex()},{"MMEGroupID":int.from_bytes(p[4:6],"big")},
                 {"MMECode":p[6]},{"MTMSI":int.from_bytes(p[7:11],"big")}]
    else:tree.append({"Value":"0x"+p.hex()})
    return tree


def capability_tree(cap, security=False):
    names=["EEA0 EEA1_128 EEA2_128 EEA3_128 EEA4 EEA5 EEA6 EEA7",
           "EIA0 EIA1_128 EIA2_128 EIA3_128 EIA4 EIA5 EIA6 EIA7",
           "UEA0 UEA1 UEA2 UEA3 UEA4 UEA5 UEA6 UEA7",
           "spare UIA1 UIA2 UIA3 UIA4 UIA5 UIA6 UIA7" if security else "UCS2 UIA1 UIA2 UIA3 UIA4 UIA5 UIA6 UIA7",
           "spare GEA1 GEA2 GEA3 GEA4 GEA5 GEA6 GEA7" if security else "ProSe_dd ProSe H245_ASH ACC_CSFB LPP LCS X1_SRVCC NF"]
    tree=[{name:(cap[i]>>(7-bit))&1} for i in range(min(len(cap),5)) for bit,name in enumerate(names[i].split())]
    if not security and len(cap)>5:tree.append({"Extension":cap[5:].hex()})
    return tree


ATTACH_HALF={9:"TMSIStatus",15:"AddUpdateType",13:"DeviceProp",14:"OldGUTIType",12:"MSNetFeatSupp",11:"UERadioCapIDAvail"}
ATTACH_TV={0x19:("OldPTMSISign",3),0x52:("OldTAI",5),0x13:("OldLAI",5),0x5c:("DRXParam",2),0x17:("AddInfoReq",1)}
ATTACH_TLV={0x50:"AddGUTI",0x31:"MSNetCap",0x11:"MSCm2",0x20:"MSCm3",0x40:"SuppCodecs",0x5d:"VoiceDomPref",
    0x10:"TMSIBasedNRICont",0x6a:"T3324",0x5e:"T3412Ext",0x6e:"ExtDRXParam",0x6f:"UEAddSecCap",0x6d:"UEStatus",0x32:"N1UENetCap"}


def attach_optionals(p,start):
    tree,normalized,pos=[],[],start
    while pos<len(p):
        tag=p[pos];half=tag>>4
        if half in ATTACH_HALF:
            name=ATTACH_HALF[half]
            tree.append({name:[{"T":half},{"V":tag&15}]})
            normalized.append(dict(name=name,iei=f"0x{half:X}",wire_format="TV-half-octet",offset=pos,length=1,value=tag&15))
            pos+=1;continue
        if tag in ATTACH_TV:
            name,size=ATTACH_TV[tag];start_value=pos+1
            parts=[{"T":tag}];wire="TV"
        elif tag in ATTACH_TLV:
            bounded(p,pos,2);name,size=ATTACH_TLV[tag],p[pos+1];start_value=pos+2
            parts=[{"T":tag},{"L":size}];wire="TLV"
        else:return tree,normalized,p[pos:].hex()
        bounded(p,start_value,size);value=p[start_value:start_value+size].hex()
        tree.append({name:parts+[{"V":value}]})
        normalized.append(dict(name=name,iei=f"0x{tag:02X}",wire_format=wire,offset=pos,length=size,value_hex=value))
        pos=start_value+size
    return tree,normalized,""


def attach_request(p):
    bounded(p,0,4);combined=p[2];n=p[3];require(n>0,"empty EPS identity")
    bounded(p,4,n);identity=p[4:4+n];pos=4+n
    bounded(p,pos,1);cap_n=p[pos];cap_start=pos+1
    require(cap_n>=2,"UE network capability requires at least 2 bytes")
    bounded(p,cap_start,cap_n);cap=p[cap_start:cap_start+cap_n];pos=cap_start+cap_n
    bounded(p,pos,2);esm_n=int.from_bytes(p[pos:pos+2],"big");esm_start=pos+2
    require(esm_n>0,"empty ESM container");bounded(p,esm_start,esm_n);esm=p[esm_start:esm_start+esm_n]
    optional,normalized,tail=attach_optionals(p,esm_start+esm_n)
    caps=capability_tree(cap)
    if len(esm)>=4 and esm[0]&15==2 and esm[2]==0xd0:
        nested=[{"ESMHeader":esm_header(esm)},{"PDNType":[{"V":esm[3]&7}]},{"RequestType":[{"V":(esm[3]>>4)&7}]}]
        if len(esm)>4:nested.append({"OptionalTail":esm[4:].hex()})
        esm_tree={"ESMPDNConnectivityRequest":nested}
    else:esm_tree={"V":"0x"+esm.hex()}
    tree=[{"EMMHeader":emm_header(p)},{"NAS_KSI":ksi(combined>>4)},{"EPSAttachType":[{"V":combined&15}]},
        {"EPSID":[{"L":n},{"EPSID":identity_tree(identity)}]},
        {"UENetCap":[{"L":cap_n},{"UENetCap":caps}]},{"ESMContainer":[{"L":esm_n},esm_tree]}]+optional
    fields=dict(status="decoded",message="ATTACH_REQUEST",decoder_class="EMMAttachRequest",decoded_fields={"EMMAttachRequest":tree},
        nas_ksi_tsc=(combined>>7)&1,nas_ksi=(combined>>4)&7,eps_attach_type=combined&15,
        eps_attach_type_name={1:"EPS attach",2:"combined EPS/IMSI attach",6:"EPS emergency attach"}.get(combined&15,"reserved/unknown"),
        eps_identity_length=n,eps_identity_offset=4,eps_identity_end_offset=4+n,eps_identity_hex="0x"+identity.hex(),
        eps_identity_type=identity[0]&7,eps_identity_type_name={1:"IMSI",3:"IMEI",6:"GUTI"}.get(identity[0]&7,"reserved/unknown"),
        ue_network_capability_length=cap_n,ue_network_capability_offset=cap_start,ue_network_capability_end_offset=cap_start+cap_n,
        ue_network_capability_hex="0x"+cap.hex(),ue_network_capabilities={k:v for item in caps for k,v in item.items()},
        esm_container_length=esm_n,esm_container_offset=esm_start,esm_container_end_offset=esm_start+esm_n,
        esm_container_hex="0x"+esm.hex(),contained_protocol_discriminator=esm[0]&15,
        nested_message="PDN_CONNECTIVITY_REQUEST" if len(esm)>=3 and esm[0]&15==2 and esm[2]==0xd0 else "UNKNOWN_ESM_MESSAGE",
        optional_ies=normalized)
    if tail:fields["unparsed_optional_tail_hex"]=tail
    return fields


def security_command(p):
    bounded(p,0,5);algo,key,n=p[2],p[3],p[4]
    require(algo&0x88==0 and key>>4==0,"Security Mode Command spare bits must be zero")
    require(2<=n<=5,"UE security capability must be 2..5 bytes")
    bounded(p,5,n);cap=p[5:5+n];caps=capability_tree(cap,True)
    cipher,integrity=(algo>>4)&7,algo&7
    tree=[{"EMMHeader":emm_header(p)},{"NASSecAlgo":[{"NASSecAlgo":[{"spare":0},{"CiphAlgo":cipher},{"spare":0},{"IntegAlgo":integrity}]}]},
        {"spare":0},{"NAS_KSI":ksi(key)},{"UESecCap":[{"L":n},{"UESecCap":caps}]}]
    opts,pos,tail=[],5+n,""
    while pos<len(p):
        tag=p[pos]
        if tag>>4==12:
            require((tag>>1)&7==0,"IMEISV request spare bits must be zero")
            tree.append({"IMEISVReq":[{"T":12},{"IMEISVReq":[{"spare":0},{"Value":tag&1}]}]})
            opts.append(dict(name="IMEISVReq",iei="0xC",wire_format="TV-half-octet",offset=pos,length=1,requested=bool(tag&1)))
            pos+=1
        elif tag in (0x55,0x56):
            bounded(p,pos,5);name="NonceUE" if tag==0x55 else "NonceMME";value=p[pos+1:pos+5].hex()
            tree.append({name:[{"T":tag},{"V":value}]})
            opts.append(dict(name=name,iei=f"0x{tag:02X}",wire_format="TV",offset=pos,length=5,value_hex=value));pos+=5
        else:tail=p[pos:].hex();break
    fields=dict(status="decoded",message="SECURITY_MODE_COMMAND",decoder_class="EMMSecurityModeCommand",
        decoded_fields={"EMMSecurityModeCommand":tree},selected_ciphering_algorithm=cipher,selected_ciphering_algorithm_name=f"EEA{cipher}",
        selected_integrity_algorithm=integrity,selected_integrity_algorithm_name=f"EIA{integrity}",nas_ksi_tsc=(key>>3)&1,nas_ksi=key&7,
        ue_security_capability_length=n,ue_security_capability_offset=5,ue_security_capability_end_offset=5+n,
        ue_security_capability_hex="0x"+cap.hex(),ue_security_capabilities={k:v for item in caps for k,v in item.items()},optional_ies=opts)
    if tail:fields["unparsed_optional_tail_hex"]=tail
    return fields


def security_complete(p):
    bounded(p,0,2);tree=[{"EMMHeader":emm_header(p)}];fields=dict(imeisv_present=False);pos=2
    if pos<len(p) and p[pos]==0x23:
        bounded(p,pos,2);n=p[pos+1];require(n==9,"IMEISV must contain exactly 9 bytes")
        bounded(p,pos+2,n);identity=p[pos+2:pos+2+n]
        require(identity[0]&15==3,"identity must be an even-digit IMEISV")
        digits=[identity[0]>>4]+[d for v in identity[1:] for d in (v&15,v>>4)]
        require(digits[-1]==15 and all(d<=9 for d in digits[:-1]),"invalid IMEISV digits")
        tree.append({"IMEISV":[{"T":35},{"L":n},{"ID":[{"Digit1":identity[0]>>4},{"Odd":0},{"Type":3},{"Digits":identity[1:].hex()}]}]})
        fields.update(imeisv_present=True,imeisv_length=n,imeisv_offset=pos+2,imeisv_end_offset=pos+2+n,
            imeisv_hex="0x"+identity.hex(),imeisv_digits="".join(str(d) for d in digits[:-1]))
        pos+=2+n
    if pos<len(p):fields["unparsed_optional_tail_hex"]=p[pos:].hex()
    fields.update(status="decoded",message="SECURITY_MODE_COMPLETE",decoder_class="EMMSecurityModeComplete",decoded_fields={"EMMSecurityModeComplete":tree})
    return fields


def mobile_identity_digits(identity):
    digits=[identity[0]>>4]+[d for value in identity[1:] for d in (value&15,value>>4)]
    if not identity[0]&8:
        require(digits[-1]==15,"even mobile identity requires filler nibble")
        digits=digits[:-1]
    require(all(d<=9 for d in digits),"mobile identity has non-decimal digits")
    return ''.join(str(d) for d in digits)


EMM_CAUSES={2:"IMSI unknown in HSS",3:"illegal UE",6:"illegal ME",7:"EPS services not allowed",
    8:"EPS and non-EPS services not allowed",9:"UE identity cannot be derived by network",10:"implicitly detached",
    11:"PLMN not allowed",12:"tracking area not allowed",13:"roaming not allowed in this tracking area",
    14:"EPS services not allowed in this PLMN",15:"no suitable cells in tracking area",17:"network failure",
    18:"CS domain not available",19:"ESM failure",22:"congestion",25:"not authorized for this CSG",
    35:"requested service option not authorized in this PLMN",39:"CS service temporarily not available",40:"no EPS bearer context activated"}


def attach_reject(p):
    bounded(p,0,3);cause=p[2];pos=3;tree=[{"EMMHeader":emm_header(p)},{"EMMCause":[{"EMMCause":cause}]}];opts=[];tail=""
    while pos<len(p):
        tag=p[pos]
        if tag>>4==10:
            tree.append({"ExtEMMCause":[{"T":10},{"V":tag&15}]})
            opts.append(dict(name="ExtEMMCause",iei="0xA",wire_format="TV-half-octet",offset=pos,length=1,value=tag&15));pos+=1
        elif tag==0x78:
            bounded(p,pos,3);n=int.from_bytes(p[pos+1:pos+3],"big");require(n>0,"empty ESM container")
            bounded(p,pos+3,n);v=p[pos+3:pos+3+n]
            tree.append({"ESMContainer":[{"T":tag},{"L":n},{"V":"0x"+v.hex()}]})
            opts.append(dict(name="ESMContainer",iei="0x78",wire_format="TLVE",offset=pos,length=n,
                value_hex="0x"+v.hex(),contained_protocol_discriminator=v[0]&15));pos+=3+n
        elif tag in (0x5f,0x16):
            bounded(p,pos,3);require(p[pos+1]==1,"Attach Reject timer must contain exactly 1 byte")
            timer=p[pos+2];name="T3346" if tag==0x5f else "T3402"
            tree.append({name:[{"T":tag},{"L":1},{"GPRSTimer":[{"Unit":timer>>5},{"Value":timer&31}]}]})
            opts.append(dict(name=name,iei=f"0x{tag:02X}",wire_format="TLV",offset=pos,length=1,timer_unit=timer>>5,timer_value=timer&31));pos+=3
        else:tail=p[pos:].hex();break
    fields=dict(emm_cause=cause,emm_cause_name=EMM_CAUSES.get(cause,"reserved/unknown"),optional_ies=opts,
        status="decoded",message="ATTACH_REJECT",decoder_class="EMMAttachReject",decoded_fields={"EMMAttachReject":tree})
    if tail:fields["unparsed_optional_tail_hex"]=tail
    return fields
