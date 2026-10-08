"""Exact observed Lisa route declarations; lengths are evidence, not device detection."""
from dataclasses import dataclass
from decoder_profiles.base import Schema as BaseSchema


@dataclass(frozen=True)
class Schema(BaseSchema):

    @property
    def nested_tuples(self):
        return NESTED_TUPLES.get(self.log_id, ())


SCHEMAS = (
    Schema("mi11-12c1-v3-direct", 0x12c1, 3, frozenset((366,)),
           "Call Manager call event", "direct", None, None),
    Schema("mi11-17f7-v4-direct", 0x17f7, 4, frozenset((40, 58, 76, 94, 112, 130, 148, 166,)),
           "WWCoex Power Info", "direct", "unsupported-17f7-v4-exact-parser-has-no-v4-schema", None),
    Schema("mi11-184e-v2-direct", 0x184e, 2, frozenset((1946,)),
           "NR5G MAC CSF Report", "direct", "unsupported-184e-v2-nr-family-deferred", None),
    Schema("mi11-5b2f-v1-radio1", 0x5b2f, 1, frozenset((7, 17, 22, 24, 25, 27,)),
           "GSM DSDS RR signaling", "multi-radio-v1", None, None),
    Schema("mi11-5c30-v1-radio1", 0x5c30, 1, frozenset((257, 280, 295, 313, 318, 329,)),
           "GPRS DSDS SM/GMM OTA signaling", "multi-radio-v1", None, None),
    Schema("mi11-b061-v1-radio1", 0xb061, 1, frozenset((60,)),
           "LTE MAC RACH trigger", "multi-radio-v1", None, None),
    Schema("mi11-b062-v1-radio1", 0xb062, 1, frozenset((56,)),
           "LTE MAC RACH response", "multi-radio-v1", None, None),
    Schema("mi11-b063-v50-radio1", 0xb063, 50, frozenset((36, 48, 52, 60, 64, 76, 80, 104, 112, 116, 120, 132, 136, 144, 168, 212, 300, 572,)),
           "LTE MAC downlink transport block", "multi-radio-v1", None, 24),
    Schema("mi11-b064-v1-radio1", 0xb064, 1, frozenset((28, 32, 36, 48, 52, 64, 72, 76, 108, 368, 396, 404, 408, 424, 432,)),
           "LTE MAC uplink transport block", "multi-radio-v1", None, 28),
    Schema("mi11-b082-v48-radio1", 0xb082, 48, frozenset((108, 128, 208, 248, 288, 368,)),
           "LTE RLC downlink PDU", "multi-radio-v1", None, 68),
    Schema("mi11-b083-v48-radio1", 0xb083, 48, frozenset((18, 28, 38, 48, 58,)),
           "LTE RLC downlink control/configuration", "multi-radio-v1", None, 18),
    Schema("mi11-b092-v1-radio1", 0xb092, 1, frozenset((40, 44, 48, 56, 60, 64, 128, 136, 164, 184, 192,)),
           "LTE RLC uplink PDU", "multi-radio-v1", None, 40),
    Schema("mi11-b0b3-v1-radio1", 0xb0b3, 1, frozenset((60, 64, 76, 80, 96, 116,)),
           "LTE PDCP uplink cipher-data", "multi-radio-v1", None, 60),
    Schema("mi11-b0c0-v27-radio1", 0xb0c0, 27, frozenset((23, 24, 25, 27, 28, 29, 30, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 47, 49, 53, 58, 61, 62, 63, 65, 66, 74, 76, 84, 86, 87, 106, 128, 131, 142, 167, 171, 183, 195, 227, 228, 1735, 1782, 1786,)),
           "LTE RRC OTA", "multi-radio-v1", None, 22, 65556),
    Schema("mi11-b0e1-v1-radio1", 0xb0e1, 1, frozenset((13, 24, 86,)),
           "LTE NAS ESM security-protected outgoing", "multi-radio-v1", None, None),
    Schema("mi11-b0e2-v1-radio1", 0xb0e2, 1, frozenset((7, 122, 141,)),
           "LTE NAS ESM plain incoming", "multi-radio-v1", None, None),
    Schema("mi11-b0e3-v1-radio1", 0xb0e3, 1, frozenset((7, 18, 80,)),
           "LTE NAS ESM plain outgoing", "multi-radio-v1", None, None),
    Schema("mi11-b0ea-v1-radio1", 0xb0ea, 1, frozenset((13, 27, 45, 46, 128, 160,)),
           "LTE NAS EMM security-protected incoming", "multi-radio-v1", None, None),
    Schema("mi11-b0eb-v1-radio1", 0xb0eb, 1, frozenset((12, 17, 21, 23, 25, 157,)),
           "LTE NAS EMM security-protected outgoing", "multi-radio-v1", None, None),
    Schema("mi11-b0ec-v1-radio1", 0xb0ec, 1, frozenset((21, 39, 40, 154,)),
           "LTE NAS EMM plain incoming", "multi-radio-v1", None, None),
    Schema("mi11-b0ed-v1-radio1", 0xb0ed, 1, frozenset((8, 11, 15, 17, 19, 151,)),
           "LTE NAS EMM plain outgoing", "multi-radio-v1", None, None),
    Schema("mi11-b130-v163-radio1", 0xb130, 163, frozenset((36, 68, 100, 132, 164, 196, 228,)),
           "LTE ML1/LL1", "multi-radio-v1", None, None),
    Schema("mi11-b139-v161-radio1", 0xb139, 161, frozenset((108, 208, 308, 408, 508, 608, 708, 808, 908, 1008, 1108,)),
           "LTE ML1/LL1", "multi-radio-v1", None, None),
    Schema("mi11-b14d-v163-radio1", 0xb14d, 163, frozenset((20,)),
           "LTE ML1/LL1", "multi-radio-v1", None, None),
    Schema("mi11-b14e-v163-radio1", 0xb14e, 163, frozenset((44,)),
           "LTE ML1/LL1", "multi-radio-v1", None, None),
    Schema("mi11-b167-v40-radio1", 0xb167, 40, frozenset((32,)),
           "LTE MAC/ML1", "multi-radio-v1", None, None),
    Schema("mi11-b168-v24-radio1", 0xb168, 24, frozenset((12,)),
           "LTE MAC/ML1", "multi-radio-v1", None, None),
    Schema("mi11-b169-v40-radio1", 0xb169, 40, frozenset((12,)),
           "LTE MAC/ML1", "multi-radio-v1", None, None),
    Schema("mi11-b16a-v1-radio1", 0xb16a, 1, frozenset((8,)),
           "LTE MAC/ML1", "multi-radio-v1", None, None),
    Schema("mi11-b17f-v5-radio1", 0xb17f, 5, frozenset((40,)),
           "LTE serving-cell measurement/evaluation", "multi-radio-v1", None, None),
    Schema("mi11-b193-v1-radio1", 0xb193, 1, frozenset((180,)),
           "LTE ML1/LL1", "multi-radio-v1", None, None),
    Schema("mi11-b197-v2-radio1", 0xb197, 2, frozenset((36,)),
           "LTE serving-cell information", "multi-radio-v1", None, None),
    Schema("mi11-nsa-b8a7-v3", 0xb8a7, 3, frozenset((88,)), "NR5G MAC CSF family anchor", unsupported_reason="unsupported-b8a7-v3-exact-v2.3-raw-layout-unproven"),
    Schema("mi11-nsa-b821-v12", 0xb821, 12, frozenset((24, 32, 126, 698)), "NR5G RRC OTA/control"),
    Schema("mi11-nsa-b97f-v8", 0xb97f, 8, frozenset((172, 260, 304)), "NR5G ML1 Searcher Measurement Database Update Ext", unsupported_reason="unsupported-b97f-v8-exact-v2.8-raw-layout-unproven"),
    Schema("mi11-nsa-b883-v17", 0xb883, 17, frozenset((36,48,68,80,100,112,120,132,152)), "NR5G MAC UL Physical Channel Schedule Report", unsupported_reason="unsupported-b883-v17-exact-v2.17-raw-layout-unproven"),
    Schema("mi11-nsa-b889-v1", 0xb889, 1, frozenset((32,)), "NR5G MAC RACH Trigger"),
)

NESTED_TUPLES = {
    0xb061: ((3, 8), (5, 2)), 0xb062: ((6, 49),), 0xb064: ((8, 2),),
    0xb092: ((0x46, 4),), 0xb0b3: ((0xc3, 40),), 0xb193: ((0x19, 50),),
}

ROUTES = {schema.log_id: schema for schema in SCHEMAS}
SIGNAL_NAMES = {schema.log_id: schema.family for schema in SCHEMAS}
SIGNAL_NAMES.update({0xb0e0: "LTE NAS ESM protected incoming (unobserved)",
                     0xb180: "LTE measurement (unobserved)", 0xb975: "NR measurement (unobserved)"})
