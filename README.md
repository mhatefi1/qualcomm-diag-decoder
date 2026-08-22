# Poco X3 Signal Decoder Tool

A self-contained Python command-line tool for decoding Poco X3 Dev/Diag
captures and exporting the results to JSON. It does not require Android
Studio, Java, Gradle, or the original Android Signaling App Demo.

## Requirements

- Python 3.10 or newer
- Windows, Linux, or macOS
- Enough disk space for the exported JSON

Install the dependencies from the project folder:

```text
python -m pip install --upgrade -r requirements.txt
```

Use plain `pycrate` from `requirements.txt`. Do not install
`pycrate[naslte]`; its optional CryptoMobile package is unavailable from the
normal Python package index and is not required by this tool.

## Usage

Decode a capture:

```text
python dev_diag_decoder.py capture_file
```

Choose an output base name or folder:

```text
python dev_diag_decoder.py capture_file --output result.json
```

Quote paths containing spaces:

```text
python dev_diag_decoder.py "C:\My Captures\capture.pxdg" --output "C:\Results\result.json"
```

Show all command options:

```text
python dev_diag_decoder.py --help
```

## Output

JSON export is mandatory and is always created. A UTC timestamp is appended so
an older result is not overwritten:

```text
capture.pxdg.decoded-20260823T120000123456Z.json
result-20260823T120000123456Z.json
```

Without `--output`, the JSON is saved in the project root beside
`dev_diag_decoder.py`. With `--output`, it is saved in the selected location.
Timestamped exports are ignored by Git.

The terminal displays progress, aggregate statistics, recognized signal
counts, and the JSON path. It does not print decoded packet contents.
Unclassified signals remain in the JSON summary but are hidden from the
terminal signal list.

Unsupported or malformed packets are recorded in JSON and do not stop later
packets from being processed. Progress and errors are written separately so
they cannot corrupt the JSON output.

## Supported data

Capture containers:

- PXDG version 1 streams
- Raw Poco X3 Qualcomm DIAG data using `0x20` driver wrappers

The validated Poco X3 (`surya`) profile includes 37 decoder routes covering:

- LTE RRC Release-14 message trees
- LTE NAS, including protected-envelope metadata
- LTE MAC, RLC, PDCP, PHY, serving-cell, and random-access records
- GERAN RR Paging Response and Ciphering Mode
- GPRS GMM Authentication, Ciphering, and Routing Area Update

Not supported:

- Plain HDLC or QMDL files without the required wrapper
- Other modem vendors or unvalidated device profiles
- Unknown packet versions and layouts
- Unobserved branches such as LTE RRC MCCH
- GERAN/GMM messages outside the decoded sets above

The tool preserves unsupported data where possible instead of guessing its
meaning.

## Privacy

Known subscriber identifiers, security keys, and sensitive binary fields are
redacted. Raw capture payloads are not copied into JSON. Diagnostic results can
still contain device or network information, so store both captures and
exports securely.

## Troubleshooting

### Python is not recognized

Install Python 3.10 or newer, enable the option to add Python to `PATH`, and
reopen the terminal. On Windows, try `py -3` instead of `python`.

### CryptoMobile or `No matching distribution` error

Run:

```text
python -m pip install --upgrade -r requirements.txt
```

CryptoMobile is optional and is not used by this CLI.

### Capture is unsupported

Confirm that it is PXDG v1 or Poco X3 Qualcomm `0x20`-wrapped DIAG data.
Changing a file extension does not change the underlying format.

### JSON cannot be written

Select a writable folder and check available disk space:

```text
python dev_diag_decoder.py capture_file --output "C:\Users\Public\result.json"
```

## Exit codes

- `0`: Capture processed and JSON written
- `1`: Decoder, format, dependency, or output failure
- `2`: Invalid command or path

## Validation

The Python decoder passed parity tests for all 37 validated routes and the
available 258-message private LTE RRC corpus. Automated tests cover GERAN,
GMM, LTE RRC, NAS, protected-NAS correlation, capture handling, JSON export,
and CLI behavior.
