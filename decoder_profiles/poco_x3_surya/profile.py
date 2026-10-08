from decoder_profiles.base import DeviceProfile
from decoder_modules.nsg_parse_lte import PROTOCOL_NAMES, LOG_NAMES
from .decoders import ReferenceDecoders, SPECIAL_SIGNAL_NAMES
from .schemas import SCHEMAS

PROFILE = DeviceProfile(
    profile_id="poco-x3-surya", model="Poco X3 (M2007J20CG)", codename="surya",
    aliases=("poco-x3", "surya", "M2007J20CG"), chipset="Qualcomm Snapdragon 732G",
    validated_scope={"firmware": "V14.0.2.0.SJGMIXM",
                     "baseband": "SS.AT.4.4.c6-00071-RENNELL_GEN_PACK-3.30805.6"},
    capture_formats=("PXDG_V1", "QUALCOMM_DIAG_RAW"),
    signal_names={**LOG_NAMES, **PROTOCOL_NAMES, **SPECIAL_SIGNAL_NAMES},
    schemas=tuple(SCHEMAS), adapter_factory=ReferenceDecoders,
    limitations=("Frozen Poco packet versions only; no neighboring-version fallback.",
                 "LTE RRC observed Release-14 branches; unsupported branches remain opaque."),
)
