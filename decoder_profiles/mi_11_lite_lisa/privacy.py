"""Android's privacy projections, applied before Lisa records leave the adapter."""
import re

RRC_TOKENS=("identity","stmsi","mtmsi","randomvalue","rnti","shortmac","dedicatedinfonas",
    "nasmessage","uecapability","cellidentity","plmnidentity","trackingarea","securitykey",
    "keysetidentifier","latecriticalextension","latenoncriticalextension","unknownextension",
    "raw","hex","payload")
NAS_TOKENS=("imsi","imei","imeisv","msisdn","supi","suci","guti","tmsi","mtmsi","stmsi",
    "mobileidentity","subscriberidentity","rand","autn","sqnxak","reshex","authenticationresponse",
    "authkey","securitykey","knas","kasme","kamf","nonce","mac","apn","accesspointname",
    "pdnaddress","ipaddress")


def sanitize(value, mode="rrc", depth=0):
    if value is None:
        return None
    if mode == "rrc" and depth >= 24:
        return "<nested value omitted>"
    if mode == "nas" and depth >= 12:
        return value
    if isinstance(value, dict):
        result={}
        for key,child in value.items():
            name=re.sub("[^a-z0-9]","",str(key).lower())
            sensitive=any(t in name for t in (RRC_TOKENS if mode=="rrc" else NAS_TOKENS))
            if mode=="nas":
                if name.endswith(("length","offset","endoffset","present","count","type","typename")):
                    sensitive=False
                sensitive=sensitive or name in ("digit1","digits")
            binary=mode=="nas" and (name.endswith(("hex","tail")) or name.startswith("raw")
                or any(t in name for t in ("payloadhex","ciphertext","unparsed"))
                or name in ("nasmessageraw","nasmessage","v"))
            result[key]="<redacted>" if sensitive else marker(child) if binary else sanitize(child,mode,depth+1)
        return result
    if isinstance(value,(list,tuple)):
        return [sanitize(child,mode,depth+1) for child in value]
    if isinstance(value,bytes):
        return marker(value)
    if mode=="rrc" and isinstance(value,str) and re.fullmatch("(?:[a-fA-F0-9]{2})+",value):
        return f"<binary {len(value)//2} bytes omitted>"
    return value


def marker(value):
    if isinstance(value, bytes):
        return f"<binary {len(value)} bytes omitted>"
    if isinstance(value,str):
        compact=re.sub("[^0-9A-Fa-f]","",value)
        if value.lstrip().startswith("0x") and compact.startswith("0"):
            compact=compact[1:]
        return f"<binary {(len(compact)+1)//2} bytes omitted>"
    return "<binary content omitted>"
