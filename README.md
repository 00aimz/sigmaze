# sigmaze

sigmaze is a lightweight CLI scanner that checks file SHA-256 hashes against a
local malware signature list.

## Features
- Recursively scan folders
- Compute SHA-256 hashes
- Compare against a local `signatures.txt`
- Print infected file paths
- Export JSON scan results

## Usage
1. Populate `signatures.txt` with known malicious SHA-256 hashes (one per line).
2. Run the scanner:

```bash
python sigmaze.py /path/to/scan
```

Optional arguments:
- `--signatures PATH` – path to the signature file (default: `signatures.txt` next to the script)
- `--json PATH` – write JSON results to the given file

Example:

```bash
python sigmaze.py ./downloads --json scan_results.json
```

The scanner prints infected file paths and writes detailed entries to JSON when
requested.
