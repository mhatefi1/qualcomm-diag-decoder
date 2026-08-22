# Poco X3 Signal Decoder Tool

This command-line tool reads Poco X3 Dev/Diag capture files and saves the
decoded results as JSON. It works entirely in Python and does not require the
Android Signaling App Demo, Android Studio, Java, or Gradle.

The capture filename and extension do not matter. The tool checks the file's
contents to determine whether it is a supported capture.

## Before you begin

You need:

- Windows, Linux, or macOS
- Python 3.10 or newer
- Enough free disk space for the JSON result

Check your Python version:

```text
python --version
```

On Windows, you can use `py -3` instead of `python` if necessary.

## Install the required packages

Open PowerShell, Command Prompt, or a terminal in this project folder. Then
run:

```text
python -m pip install --upgrade -r requirements.txt
```

Do not install `pycrate[naslte]`. Its optional CryptoMobile package is not
available from the normal Python package index and is not required by this
tool. The included requirements file installs the correct packages.

## Decode a capture

Run the tool with the capture file as the first argument:

```text
python dev_diag_decoder.py capture_file
```

Windows example:

```text
python dev_diag_decoder.py "C:\Users\YourName\Desktop\capture.pxdg"
```

Always put quotation marks around a path that contains spaces.

### Choose an output name or folder

Use `--output` or `-o` to select the base name and location of the JSON file:

```text
python dev_diag_decoder.py capture_file --output result.json
```

Another folder can also be selected:

```text
python dev_diag_decoder.py capture_file --output "C:\Users\YourName\Desktop\result.json"
```

JSON export is always created; it cannot be disabled.

## Where to find the result

Every JSON filename receives a UTC timestamp so an earlier result is not
overwritten.

- Without `--output`, the JSON is saved in the project folder next to
  `dev_diag_decoder.py`.
- With `--output`, it is saved in the selected folder using the selected base
  name.

Examples:

```text
capture.pxdg.decoded-20260823T120000123456Z.json
result-20260823T120000123456Z.json
```

The JSON contains overall statistics, signal counts, decoded packet fields,
schema identifiers, and warnings for packets that could not be decoded.
Timestamped result files are ignored by Git.

## What appears in the terminal

Decoded packet contents are not printed in the terminal. The terminal shows:

- A progress bar while the capture is being read
- A progress bar while JSON is being written
- A summary of found, decoded, unsupported, and malformed packets
- Found and decoded totals for each recognized signal present
- The full path of the generated JSON file

Example:

```text
Statistics:
  Input format:       PXDG_V1
  Capture records:    733
  Packets found:      4976
  Decoded:            885
  Unsupported:        4091
  Malformed:          0
  Rejected frames:    27482
  Signals present:
    0xB061  found=1 decoded=1  LTE MAC RACH trigger
    0xB0C0  found=39 decoded=39  LTE RRC OTA packet

JSON output: C:\path\to\capture.pxdg.decoded-TIMESTAMP.json
```

An unsupported or malformed packet does not stop the operation. The tool logs
the problem in JSON and continues with later packets. Progress and error text
are kept separate from the generated JSON.

Unclassified signal IDs are included in the JSON summary but are hidden from
the terminal's `Signals present` list to keep the console readable.

## Supported data

The tool supports captures from the validated Poco X3 (`surya`) profile in
these containers:

- PXDG version 1 streams
- Raw Qualcomm DIAG data using `0x20` driver wrappers

The bundled decoders cover LTE RRC, NAS, MAC, RLC, PDCP, PHY, serving-cell and
random-access records, plus selected GERAN RR and GPRS GMM messages. This
includes GERAN Paging Response and Ciphering Mode, and GMM Authentication,
Ciphering, and Routing Area Update messages.

The following are not supported:

- Plain HDLC or QMDL files without the required wrapper
- Capture containers from unrelated tools or modem vendors
- Unknown packet versions or layouts
- Device profiles other than the validated Poco X3 profile
- Unobserved protocol branches such as LTE RRC MCCH
- GERAN or GMM message types outside the decoded sets above

Unsupported packets are preserved as warnings where possible; the tool does
not guess their contents.

## Privacy

Known subscriber identifiers, security keys, and sensitive binary fields are
redacted from exported packet fields. Raw capture payloads are not copied into
the JSON. However, diagnostic data can still contain device or network
information, so keep both the capture and JSON result secure.

## Troubleshooting

### `python` is not recognized

Install Python 3.10 or newer and enable the installer option that adds Python
to `PATH`. Reopen the terminal after installation. On Windows, try:

```text
py -3 dev_diag_decoder.py capture_file
```

### CryptoMobile or `No matching distribution` error

Install from this project's requirements file:

```text
python -m pip install --upgrade -r requirements.txt
```

If you previously tried `pycrate[naslte]`, uninstalling it is not necessary;
installing from `requirements.txt` is sufficient. CryptoMobile is optional and
is not used by this CLI.

### The capture is reported as unsupported

Renaming the file or changing its extension does not change its contents.
Confirm that it is a PXDG v1 capture or Poco X3 Qualcomm `0x20`-wrapped DIAG
capture.

### The JSON file cannot be written

Select a folder where your user account can create files:

```text
python dev_diag_decoder.py capture_file --output "C:\Users\Public\result.json"
```

Also check that the disk has enough free space.

### Some packets are unsupported

This is expected when a capture contains signal IDs or packet versions outside
the validated decoder set. Check the per-signal counts in the terminal and the
packet warnings in JSON. Supported packets are still decoded.

## Command help

Show the complete built-in command reference:

```text
python dev_diag_decoder.py --help
```

Exit codes:

- `0`: Capture processed and JSON written successfully
- `1`: Decoder, capture-format, dependency, or output failure
- `2`: Invalid command or input/output path

## Decoder validation

The self-contained Python implementation includes all 37 routes from the
validated decoder manifest. Its parity tests cover GERAN, GMM, LTE RRC, NAS,
and protected-NAS correlation. The bundled LTE RRC decoder uses a Release-14
schema and was verified against the available private RRC corpus.
