# Python HTTPS Proxy

Reverse HTTPS proxy that allows traffic inspection and payload injection for
blue/red team exercises.  Provide a certificate/key pair trusted by the client
to perform man-in-the-middle analysis against a chosen upstream target.

## Features

- Terminates TLS locally and forwards to a configurable upstream server.
- Optional HTML/text payload injection to test content security controls.
- Minimal configuration with a single Python dependency (`aiohttp`).

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Generate a certificate/key pair (for lab testing you can create a self-signed
certificate):

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout mitm.key -out mitm.crt \
  -subj "/CN=proxy.lab"
```

## Usage

```bash
python proxy.py https://upstream.internal \
  --cert mitm.crt --key mitm.key \
  --inject payload.html --listen-port 4443
```

Point clients at `https://proxy-host:4443` and trust the generated certificate
to observe injected content.
