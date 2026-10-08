from decoder_profiles.base import DeviceProfile
from .schemas import SCHEMAS, SIGNAL_NAMES
from .decoders import LisaDecoders, bound_schemas

PROFILE = DeviceProfile(
    profile_id="mi-11-lite-lisa", model="Mi 11 Lite (2109119DG)", codename="lisa",
    aliases=("mi-11-lite", "lisa", "lisa_global", "2109119DG",
             "mi-11-lite-lisa-v14.0.2.0-tkomixm"),
    chipset="Qualcomm SM7325 / YUPIK",
    validated_scope={
        "vendor_firmware": "V14.0.2.0.TKOMIXM",
        "runtime_build": "SecurePhone_lisa-userdebug 13 TQ3A.230901.001 eng.root.20260819.090649 test-keys",
        "baseband": "4.3CPL2-gl-26.1-15406.330108_2219_856558541b4",
    },
    capture_formats=("PXDG_V1", "QUALCOMM_DIAG_RAW"), signal_names=SIGNAL_NAMES,
    schemas=bound_schemas(), adapter_factory=LisaDecoders,
    limitations=("Only MODEM peripheral 1 and multi-radio wrapper v1/radio 1 are validated.",
        "Seven measurement/control layouts, WWCoex and opaque NR routes remain unsupported.",
        "B193/v50, Call Manager, some GERAN and lower-layer results are explicitly partial.",
        "NR B821/v12 and B889/v1 are partial; records prove neither NSA nor SA mode.",
        "No accepted SA corpus or SA compatibility claim; other Mi 11 Lite variants are not implied.",
        "Firmware/baseband scope is not independently verified against the input capture."),
)
