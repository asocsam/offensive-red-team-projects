# Subdomain Takeover Scanner

Async Python scanner that checks for dangling DNS entries pointing to cloud
providers with known takeover behaviours.

## Features

- Enumerates subdomains using a configurable wordlist.
- Resolves CNAME records and probes HTTP endpoints for fingerprints.
- Ships with fingerprints for GitHub Pages, Heroku, Azure, Fastly, Shopify and Amazon S3.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python scanner.py example.com --wordlist words.txt --concurrency 50
```

Example `words.txt`:

```
www
cdn
assets
support
```

The scanner prints a summary of any potential takeovers discovered.  You can
extend fingerprints by editing `TAKEOVER_FINGERPRINTS` in `scanner.py`.
