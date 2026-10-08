"""Lisa schema validation and declarative decoder routing; no automatic detection."""
from dataclasses import replace
from decoder_core.dispatcher import RoutedSchemaDispatcher
from .schemas import SCHEMAS
from . import lower_layer

ANDROID_PROFILE_ID = "mi-11-lite-lisa-v14.0.2.0-tkomixm"


def common(schema):
    return dict(source="qualcomm-routed-diag",device_profile=ANDROID_PROFILE_ID,
                route_id=schema.route_id,log_id=f"0x{schema.log_id:04X}")


class LisaDecoders(RoutedSchemaDispatcher):
    privacy_safe = True

    def __init__(self, schemas=None):
        super().__init__(schemas or bound_schemas())


def lower(schema, body):
    fields,warnings=lower_layer.decode(schema.log_id,body)
    direction="downlink" if schema.log_id in (0xb063,0xb082,0xb083) else (
        "procedure-scoped" if schema.log_id in (0xb061,0xb062) else "uplink")
    return dict(**common(schema),record_version=schema.version,family=schema.family,
                direction=direction,lower_layer=fields),warnings


def measurement(schema, body):
    from .measurement import decode
    return decode(schema,body)


def rrc(schema, body):
    from .signaling import decode_rrc
    return decode_rrc(schema,body)


def nas(schema, body):
    from .signaling import decode_nas
    return decode_nas(schema,body)


def geran(schema, body):
    from .geran import decode
    return decode(schema,body)


def call(schema, body):
    from .measurement import call_manager
    return call_manager(schema,body)


def nr(schema, body):
    from .nr import decode
    return decode(schema,body)


ROUTE_DECODERS={**{i:lower for i in lower_layer.DECODERS},
    **{i:measurement for i in (0xb130,0xb139,0xb14d,0xb14e,0xb167,0xb168,
                               0xb169,0xb16a,0xb17f,0xb193,0xb197)},
    **{i:nas for i in (0xb0e1,0xb0e2,0xb0e3,0xb0ea,0xb0eb,0xb0ec,0xb0ed)},
    0xb0c0:rrc,0x5b2f:geran,0x5c30:geran,0x12c1:call,0xb821:nr,0xb889:nr}


def bound_schemas():
    return tuple(replace(schema, decoder=ROUTE_DECODERS.get(schema.log_id)) for schema in SCHEMAS)
