# Decoder scope and port provenance

Reference: Android Signaling App Demo source revision
`a324392823843c70e7420adf7430432cfdf503a2`, including the six Mi11 non-NR decoder
families, separate NR registry, strict routed normalizer, and schema resources.
These are development references, not runtime dependencies.

The source's `app/src/main/assets` contains a Poco capture configuration, not
Mi 11 Lite identity documentation. Lisa identity was therefore checked against
`docs/assessment/mi-11-lite-signal-inventory.md`, the qualification document,
and `DeviceProfile.MI_11_LITE_QUALIFIED`. The exact model/codename is
`2109119DG` / `lisa` (`lisa_global`), Qualcomm SM7325/YUPIK. The selected stable
Python ID is `mi-11-lite-lisa`; the Android versioned profile ID is also an alias.

Validated scope: custom Android 13
`SecurePhone_lisa-userdebug 13 TQ3A.230901.001 eng.root.20260819.090649 test-keys`,
vendor baseline `V14.0.2.0.TKOMIXM`, and baseband
`4.3CPL2-gl-26.1-15406.330108_2219_856558541b4`. These describe reference decoder
scope. The CLI does not read, infer, or verify these values from a capture.

## Route-by-route comparison

All Lisa routes require peripheral 1. Except the three direct routes, they also
require Qualcomm multi-radio command 0x98, wrapper version 1, radio ID 1. The
Poco wrapper/layout is never assumed compatible solely from an ID/version.

| Log ID | Lisa version / nested tuple | Comparison and disposition |
|---|---|---|
| 12C1 | 3, direct | Lisa-specific 21-byte Call Manager prefix; 345-byte tail opaque. |
| 17F7 | 4, direct | Unsupported WWCoex; no exact parser. |
| 184E | 2, direct | Unsupported CSF-family control; not a 5G-mode indicator. |
| 5B2F | 1 | Lisa versioned RR wrapper; shared Paging/Ciphering standards decoders, new safe observed RR projections. |
| 5C30 | 1 | Lisa versioned SM/GMM wrapper with 250-byte opaque tail; shared RAU/Authentication, new Attach/PDP projections. |
| B061 | 1 / 03-v8 + 05-v2 | Different nested layout; partial Lisa trigger. |
| B062 | 1 / 06-v49 | Different from Poco v3 attempt; partial extension-safe Lisa projection. |
| B063 | 50 | Different MAC envelope; partial bounded block count. |
| B064 | 1 / 08-v2 | Lisa sample array; exact bounded scalar projection, MAC content redacted. |
| B082 | 48 | Flat Lisa 8-byte header + 20-byte states + 40-byte metadata; partial configuration interpretation. |
| B083 | 48 | Lisa 10-byte entries; boundaries only, entry contents opaque. |
| B092 | 1 / 46-v4 | Lisa bounded uplink RLC metadata; no content export. |
| B0B3 | 1 / C3-v40 | Lisa bounded PDCP metadata; cipher/security contents redacted. |
| B0C0 | 27 | Lisa-specific 21-byte header, six channel routes; shared LTE UPER engine. No Poco v20 fallback. |
| B0E1 | 1 | Exact 1/9/5/0 NAS header; shared protected EPS envelope, outgoing ESM. |
| B0E2 | 1 | Same NAS header; shared EPS semantics plus observed incoming ESM branches. |
| B0E3 | 1 | Same NAS header; shared EPS semantics plus observed outgoing ESM branches. |
| B0EA | 1 | Shared protected EPS envelope, incoming EMM. |
| B0EB | 1 | Shared protected EPS envelope, outgoing EMM. |
| B0EC | 1 | Shared EPS semantics plus observed incoming EMM branches. |
| B0ED | 1 | Shared EPS semantics plus observed outgoing EMM branches. |
| B130 | 163 | Unsupported; not Poco v123. |
| B139 | 161 | Unsupported; not Poco v124. |
| B14D | 163 | Unsupported 20-byte form; not Poco v103/12 bytes. |
| B14E | 163 | Unsupported 44-byte form; not Poco v103/36 bytes. |
| B167 | 40 | Unsupported; no equivalence to Poco Msg1 v25 proven. |
| B168 | 24 | Proven identical semantic layout; reuse existing Msg2 decoder. |
| B169 | 40 | Unsupported; no equivalence to Poco Msg3 v24 proven. |
| B16A | 1 | Proven identical semantic layout; reuse existing Msg4 decoder. |
| B17F | 5 | Reuse proven 36-byte prefix; four Lisa suffix bytes opaque. |
| B193 | 1 / 19-v50 | Different 180-byte Lisa envelope; PCI and two RSRP values only. Never use Poco nested v39. |
| B197 | 2 | Unsupported; exact serving-cell semantics unproven. |
| B8A7 | 3 / composite 2.3 | Unsupported 88-byte NR CSF layout. |
| B821 | 12 | Lisa 23-byte envelope and three direct Release-15-compatible NR roots; timing split opaque. |
| B97F | 8 / composite 2.8 | Unsupported; lengths 172/304 plus structural-only 260 observation. |
| B883 | 17 / composite 2.17 | Unsupported; frozen lengths plus structural-only 120/132/152 observations. |
| B889 | 1 / composite 2.1 | Exact 30-byte core, Msg3 boundary redacted; two-byte Lisa suffix opaque. |

B0E0, B180, and B975 remain selected-but-unobserved with no promoted decoder.
Unknown IDs/versions, radio 2, incompatible wrappers, and missing schemas are
unsupported. Invalid declared boundaries/counts/checksums are malformed. Both
outcomes preserve available numeric routing metadata and continue to later
packets; raw bytes are not exported for privacy.

The profile carries 37 exact route declarations: 25 supported (including
partial projections), 12 explicit unsupported. Container metadata and absent
IDs are not used to verify or reject a device selection.

## Architecture

- `decoder_core/capture.py`: streaming PXDG/raw containers and generic utilities.
- `decoder_core/diag.py`: strict routed HDLC/CRC/header normalization.
- `decoder_core/dispatcher.py`: selected-profile dispatch and declarative routed
  schema/version/wrapper/length gates, no model branches.
- `decoder_profiles/base.py` and `registry.py`: identity/schema contracts and
  explicit ID/alias lookup. There are no detector callbacks/confidence fields.
- `decoder_modules/`: existing reusable standards decoders, EPS semantics and
  shared LTE/NR UPER engine/resources.
- `decoder_profiles/poco_x3_surya/`: unchanged legacy decoding behavior.
- `decoder_profiles/mi_11_lite_lisa/`: exact schema gates, adapters, partial
  lower-layer/measurement/GERAN/NR projections, privacy boundaries.
- `dev_diag_decoder_core.py`: compatibility imports, not duplicate decoders.

Existing Poco NAS behavior remains unchanged. Strict Lisa EPS decoding disables
the legacy proprietary-tail retry and adds Android's accepted scalar
projections. Both profiles reuse the standards parser; binary layout checks
remain in the owning adapter. NR reuses the LTE schema-driven UPER engine with
its own vendored schema and rejects later-release/unknown-extension branches.

## Verification performed

- 44 Python test methods passed with optional private fixtures configured;
  normal standalone runs skip the four private-corpus tests.
- Public synthetic Android-oracle vectors cover all 37 Lisa routes and 21
  additional NAS/NR cases; expected successful fields are compared exactly.
- Development-only Android oracle replay: 13,065 distinct Lisa packet bodies
  from retained research captures and later real PXDG recordings matched in
  status and decoded fields: 4,357 success, 8,703 unsupported, five malformed.
- Poco: all 37 private goldens and 258 RRC trees match. Two PXDG captures
  totaling 58,011 packets match pre-change packet output exactly.
- Runtime and ordinary tests use Python only. No phone operation, model
  verification, firmware inference, or current NSA/SA classification occurred.

Private captures and development oracle outputs were not copied into tracked
files. Public test fixtures contain synthetic bytes only, not subscriber
data.
