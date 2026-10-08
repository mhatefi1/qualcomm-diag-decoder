# Offline Phone Signal Decoder

Decode Dev/Diag capture files exported by **Android Signaling App Demo**.
Supports Poco X3 (`surya`) and the qualified Mi 11 Lite (`2109119DG` / `lisa`)
profile. Decoded packets go to JSON; the terminal shows only progress and statistics.

This tool works **offline**. It never connects to a phone, discovers devices,
communicates with Android, or retrieves live device information. Android Studio,
Java, Gradle, and the Android source are not needed to run it.

## Install

Use Python 3.10 or newer on Windows, Linux, or macOS. In the project folder:

```text
python -m pip install -r requirements.txt
```

Use plain `pycrate`, not `pycrate[naslte]`. The latter requests CryptoMobile,
which is unavailable from the normal Python package index. CryptoMobile is
optional and is not needed by this CLI.

## Decode a capture

First list the profiles and their aliases:

```text
python dev_diag_decoder.py --list-devices
```

Choose the profile for the phone that produced your capture. **`--device` is
required**; there is no automatic device selection.

```text
python dev_diag_decoder.py capture.pxdg --device poco-x3-surya
python dev_diag_decoder.py capture.pxdg --device mi-11-lite-lisa
python dev_diag_decoder.py capture.pxdg --device poco-x3-surya --output result.json
```

Aliases such as `surya` and `lisa` also work. Quote paths containing spaces:

```text
python dev_diag_decoder.py "C:\My Captures\capture.pxdg" --device lisa --output "C:\Results\result.json"
python dev_diag_decoder.py --help
```

The profile is your explicit selection, **not independent verification of the
phone model or firmware**. The Lisa profile does not imply support for every
phone marketed as Mi 11 Lite.

## Results

JSON export is mandatory. `--output` changes its base path; it does not enable
or disable export. Every filename receives a UTC timestamp:

```text
capture.pxdg.decoded-20261008T120000123456Z.json
result-20261008T120000123456Z.json
```

Without `--output`, the file is saved in the project root, beside
`dev_diag_decoder.py`, even when you run the command from another directory.
With `--output`, a relative path is relative to your current terminal directory.
Generated timestamped JSON exports are ignored by Git.

The terminal displays packet totals and found/decoded counts for signals
actually present. Unclassified signals are hidden from that list but remain
in JSON. Progress and readable errors use stderr and never enter the JSON file.

The JSON contains:

- `device`: selected profile ID, readable model, codename, and
  `selection_mode: "explicit"`.
- `validated_decoder_scope` inside `device`: the reference firmware/baseband
  scope, **not metadata verified from your capture**.
- `summary`: aggregate totals and per-signal counts.
- `packets`: decoded fields, schema IDs, framing metadata where available,
  and unsupported/malformed warnings. Partial decodes carry explicit warnings.

Unsupported or malformed packets do not stop later packets. Missing model,
firmware, or baseband metadata and absent signal IDs do not invalidate a
capture. If nothing decodes, the CLI warns that the chosen profile may not
match, or that the data is unsupported. A fatal container/path error produces
an error JSON when the destination is writable.

“Rejected frames” counts invalid candidate frame boundaries found by the
legacy Poco scanner; it is not a count of successfully framed unsupported
packets. Strict routed-DIAG framing failures are recorded as malformed packets.

## Supported input and limits

File extensions are ignored; the contents must use a supported container:

- PXDG version 1.
- Raw Qualcomm `0x20`-wrapped DIAG data with the selected profile's framing.

Plain HDLC, QMDL, PCAP, other modem vendors, and unknown binary layouts are not
implicitly supported. Renaming a file does not convert it.

| Profile | Decoder coverage |
|---|---|
| `poco-x3-surya` | Existing 37-schema baseline: LTE RRC/NAS, MAC/RLC/PDCP/PHY, random access, GERAN RR, and GPRS GMM. |
| `mi-11-lite-lisa` | Exact routed versions: LTE RRC v27, seven NAS routes, eight lower-layer routes, GERAN RR/GMM/SM, Call Manager, four measurement routes, and two partial NR routes. |

Lisa limitations include:

- Only MODEM peripheral 1 and multi-radio v1/radio 1 are validated; radio 2 is
  unsupported.
- B193 nested v50, Call Manager, some GERAN and lower-layer results are partial.
- Seven measurement/control layouts, WWCoex, opaque NR reports, and
  selected-but-unobserved routes remain unsupported.
- NR B821/v12 supports three observed direct Release-15-compatible RRC roots.
  Its timing split remains opaque. B889/v1 has an opaque two-byte suffix.
- No SA compatibility claim, no NSA/SA mode inference from packet IDs, and no
  neighboring-version fallback.

See [decoder port notes](docs/decoder-port-notes.md) for the complete route
comparison and validated scope.

## Privacy and troubleshooting

Known subscriber identities, security material, message contents, and sensitive
binary fields are redacted. Raw captures are not copied into JSON. Captures and
results can still contain network information; keep them secure.

If Python is not recognized, install Python and reopen the terminal. On Windows,
try `py -3` instead of `python`.

If nothing decodes, confirm both the capture format and the explicitly selected
profile. Large unsupported counts can reflect known layout limits, not a broken
installation. Ciphered NAS contents cannot be recovered without an appropriate
security context; the CLI reports the envelope rather than pretending to decrypt it.

For export errors, choose a writable folder and check free disk space.

Exit codes: `0` means processing and export completed (possibly with packet
warnings); `1` means a fatal format/decoder/output error; `2` means invalid
arguments or paths.

## Tests

The normal tests are self-contained and do not use Java or Android:

```text
python -m unittest discover -s tests -v
```

Synthetic Android-oracle goldens cover every Lisa route and additional signaling
families. Optional private corpus checks are skipped unless
`DECODER_PRIVATE_FIXTURES` points to your local `testdata/private` fixture folder.
Do not add real captures or private subscriber data to Git.

## Adding another device

The CLI, capture reader, JSON export, statistics, and dispatcher are
model-independent. Existing reusable protocols live in `decoder_modules/`;
device-specific binary layouts live in `decoder_profiles/`.

1. Create `decoder_profiles/<new_device>/`.
2. Define a stable ID, readable model, codename, aliases, and validated scope.
3. Declare exact schemas, versions, nested tuples, length rules, and signal names.
4. Reuse shared protocols; add decoders only for genuinely different layouts.
5. Implement the profile adapter's `frames(payload)` and `decode(frame, log_id)`
   contracts. Never add device detection or inferred firmware checks.
6. Add synthetic golden, malformed-input, and profile/capture regression tests.
7. Add the profile in `decoder_profiles/registry.py`.
8. Run the full regression suite and document known limitations.

A minimal profile declaration follows the existing packages:

```python
from decoder_profiles.base import DeviceProfile
from .schemas import SCHEMAS, SIGNAL_NAMES
from .decoders import ExampleDecoders

PROFILE = DeviceProfile(
    profile_id="example-phone-codename",
    model="Example Phone",
    codename="codename",
    aliases=("example",),
    chipset="Documented modem family",
    validated_scope={"firmware": "reference build"},
    capture_formats=("PXDG_V1",),
    signal_names=SIGNAL_NAMES,
    schemas=SCHEMAS,
    adapter_factory=ExampleDecoders,
    limitations=("Only the declared packet versions are validated.",),
)
```

The adapter factory accepts the profile's schema tuple. A routed profile can
reuse `decoder_core.dispatcher.RoutedSchemaDispatcher` directly with the shared
`Schema` dataclass and decoder callbacks, as the extension test demonstrates.

The adapter yields `(frame, log_id, valid)` tuples and returns
`(schema_id, fields)` from decoding. Raise `UnsupportedPacket` for unknown
layouts and `ValueError` for malformed data. The shared pipeline handles
continuity, statistics, and export. See Lisa's adapter for strict routed framing
and privacy-safe partial-result warnings.
