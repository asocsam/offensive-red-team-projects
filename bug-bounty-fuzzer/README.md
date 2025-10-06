# Bug Bounty Fuzzer

Python utility that fuzzes HTTP parameters, headers and JSON payloads using
security testing payloads.  The tool is designed for reconnaissance work where
quickly spotting anomalies is more useful than raw request volume.

## Features

- Concurrent fuzzing with baseline comparison to highlight anomalies.
- Built-in payload catalog for XSS, SQLi, SSTI and traversal vectors.
- Optional payload, header and parameter wordlists for targeted testing.
- CSV export for offline triage.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python fuzzer.py https://target.test/search?q=test \
  --params params.txt \
  --headers headers.txt \
  --payloads payloads.txt \
  --threads 16 \
  --output findings.csv
```

Example parameter wordlist (`params.txt`):

```
q
search
redirect
```

Example header wordlist (`headers.txt`):

```
X-Forwarded-For
X-Original-URL
Forwarded
```

When fuzzing JSON APIs supply a template body and a list of JSON keys to test:

```bash
python fuzzer.py https://api.test/v1/login \
  --method POST \
  --json body_template.json \
  --params json_fields.txt
```

Where `body_template.json` contains the baseline request body and
`json_fields.txt` enumerates keys to mutate (dot notation supported for nested
objects).
