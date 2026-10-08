"""The only registration point for phone profiles; aliases are case-insensitive."""
from .poco_x3_surya.profile import PROFILE as POCO


def registered_profiles():
    # Lazy loading keeps --help and --list-devices free of optional decoder imports.
    from .mi_11_lite_lisa.profile import PROFILE as LISA
    return (POCO, LISA)


def resolve_profile(value):
    for profile in registered_profiles():
        if value.casefold() in {name.casefold() for name in (profile.profile_id, *profile.aliases)}:
            return profile
    raise ValueError(f"unknown device profile '{value}'; use --list-devices")
