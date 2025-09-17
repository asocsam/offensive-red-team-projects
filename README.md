
# 🔴 Offensive Security Projects  

```markdown
# Offensive Security Projects 🔴  

## Overview  
This repo contains my Red Team and offensive security research projects, built for learning and simulating adversary behaviors.  

## Tools  
- **Python HTTPS Proxy**: MITM payload injection for traffic inspection.  
- **Subdomain Takeover Scanner**: Automated reconnaissance of dangling DNS records.  
- **Bug Bounty Fuzzer**: Python tool to fuzz headers and parameters.  
- **CVE Replication Labs**: Safe labs for replicating Outlook NTLM leak & OpenSSH RCE exploits.  

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
python proxy.py --inject payload.txt
python subdomain_scanner.py -d example.com
