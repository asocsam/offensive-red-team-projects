"""Subdomain takeover detection helper.

The scanner performs DNS and HTTP probing looking for dangling CNAME
references that match well-known cloud service fingerprints.  The script is
intentionally dependency-light and uses asyncio to parallelise checks without
overwhelming the target infrastructure.
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import dns.asyncresolver
import httpx


DEFAULT_WORDLIST = (
    "www",
    "mail",
    "blog",
    "dev",
    "test",
    "stage",
    "beta",
    "cdn",
    "files",
)


TAKEOVER_FINGERPRINTS: List[Dict[str, Optional[str]]] = [
    {
        "service": "GitHub Pages",
        "cname": ".github.io",
        "http": "There isn't a GitHub Pages site here.",
    },
    {
        "service": "Heroku",
        "cname": ".herokudns.com",
        "http": "No such app",
    },
    {
        "service": "Amazon S3",
        "cname": ".s3.amazonaws.com",
        "status": 404,
    },
    {
        "service": "Azure Web Apps",
        "cname": ".azurewebsites.net",
        "http": "The resource you are looking for has been removed",
    },
    {
        "service": "Fastly",
        "cname": ".global.prod.fastly.net",
        "status": 404,
    },
    {
        "service": "Shopify",
        "cname": ".myshopify.com",
        "http": "Sorry, this shop is currently unavailable.",
    },
]


@dataclass
class Finding:
    domain: str
    cname: str
    service: str
    evidence: str


async def load_wordlist(path: Optional[Path]) -> Iterable[str]:
    if not path:
        return DEFAULT_WORDLIST
    with path.open("r", encoding="utf8") as handle:
        return [line.strip() for line in handle if line.strip() and not line.startswith("#")]


def match_fingerprint(cname: str, response: Optional[httpx.Response]) -> Optional[Finding]:
    for fingerprint in TAKEOVER_FINGERPRINTS:
        expected = fingerprint.get("cname")
        if expected and not cname.endswith(expected):
            continue
        if response is None:
            if fingerprint.get("http") is None and fingerprint.get("status") is None:
                return Finding(cname=cname, domain="", service=fingerprint["service"], evidence="dangling CNAME")
            continue
        status = fingerprint.get("status")
        text_snippet = fingerprint.get("http")
        if status and response.status_code != status:
            continue
        if text_snippet and text_snippet not in response.text:
            continue
        return Finding(
            domain="",
            cname=cname,
            service=fingerprint["service"],
            evidence=text_snippet or f"HTTP {response.status_code}",
        )
    return None


async def probe_http(domain: str, resolver_result: str, timeout: float) -> Optional[httpx.Response]:
    url = f"http://{domain}"
    try:
        async with httpx.AsyncClient(
            verify=False,
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "SubdomainTakeoverScanner/1.0"},
        ) as client:
            return await client.get(url)
    except httpx.HTTPError:
        return None


async def resolve_cname(resolver: dns.asyncresolver.Resolver, domain: str) -> Optional[str]:
    try:
        answers = await resolver.resolve(domain, "CNAME")
        return str(answers[0].target).rstrip(".")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return None


async def worker(
    domain: str,
    resolver: dns.asyncresolver.Resolver,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> Optional[Finding]:
    async with semaphore:
        cname = await resolve_cname(resolver, domain)
        if not cname:
            return None
        response = await probe_http(domain, cname, timeout)
        finding = match_fingerprint(cname, response)
        if finding:
            finding.domain = domain
            return finding
        return None


async def scan(domains: Iterable[str], concurrency: int, timeout: float) -> List[Finding]:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    semaphore = asyncio.Semaphore(concurrency)
    tasks = [worker(domain, resolver, timeout, semaphore) for domain in domains]
    results = await asyncio.gather(*tasks)
    return [finding for finding in results if finding]


def expand_domains(base_domain: str, wordlist: Iterable[str]) -> List[str]:
    return [f"{word}.{base_domain}" for word in wordlist]


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Identify potential subdomain takeover risks.")
    parser.add_argument("domain", help="Base domain to scan (e.g. example.com)")
    parser.add_argument(
        "--wordlist",
        type=Path,
        help="Optional list of subdomain prefixes to brute force.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=20,
        help="Maximum number of concurrent DNS/HTTP checks (default: 20).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Resolver and HTTP timeout per request (default: 5 seconds).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    wordlist = asyncio.run(load_wordlist(args.wordlist))
    domains = expand_domains(args.domain, wordlist)
    print(f"[*] Scanning {len(domains)} candidate subdomains under {args.domain}")
    findings = asyncio.run(scan(domains, args.concurrency, args.timeout))
    if not findings:
        print("[-] No obvious takeover indicators discovered")
        return 0
    print("[+] Potential takeovers detected:\n")
    for finding in findings:
        print(f" - {finding.domain} -> {finding.cname} ({finding.service}) :: {finding.evidence}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
