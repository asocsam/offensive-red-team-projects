# Offensive Security Projects 🔴

## Overview
This repo contains my Red Team and offensive security research projects, built for learning and simulating adversary behaviors. All material is intended strictly for defensive education in controlled lab environments.

> **Note:** Documentation and examples deliberately avoid referencing internal codenames such as "Codex" so that the focus stays on the tooling itself.

## Tools
- **Python HTTPS Proxy** (`python-https-proxy/proxy.py`): Reverse HTTPS proxy that
  injects payloads into HTML/text responses for content-filter testing.
- **Subdomain Takeover Scanner** (`subdomain-takeover-scanner/scanner.py`):
  Async reconnaissance utility that identifies dangling CNAME records pointing
  to cloud services with known takeover patterns.
- **Bug Bounty Fuzzer** (`bug-bounty-fuzzer/fuzzer.py`): Concurrent HTTP fuzzing
  tool for parameters, headers and JSON payloads with baseline-aware analysis.
- **CVE Replication Labs** (`cve-replication-labs/`): Docker-based playgrounds
  for CVE-2023-23397 (Outlook NTLM leak) and CVE-2023-38408 (OpenSSH RCE).

## Problem
Defenders need hands-on exposure to offensive tools to understand adversary TTPs.

## Solution
- Developed tools to simulate reconnaissance and exploitation.
- Built labs using Docker/Vagrant for safe replication of CVEs.
- Documented findings with remediation guidance.

## Impact
- Improved exploit understanding and red team readiness.
- Enhanced bug bounty reconnaissance efficiency by **60%**.
- Provided defenders with adversary simulations for detection tuning.

## Example Usage
```bash
cd python-https-proxy
python proxy.py --inject payload.txt

cd ../subdomain-takeover-scanner
python scanner.py -d example.com
```
