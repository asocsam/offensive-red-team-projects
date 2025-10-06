"""Bug bounty HTTP fuzzing utility.

This module implements a command line interface that can fuzz headers,
query parameters and JSON fields with attacker controlled payloads.  The
implementation focuses on ergonomics for reconnaissance engagements where
collecting high-signal anomalies quickly is more valuable than raw
throughput.  The fuzzer keeps track of timing information, reflected
payloads and interesting status codes so that testers can triage
potential vulnerabilities efficiently.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import requests
from requests import Response
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


# Default payload catalogue grouped by attack type.  Users can supply their
# own payload file but the built-in list provides sensible starting points for
# common bug bounty checks.
DEFAULT_PAYLOADS: Dict[str, Sequence[str]] = {
    "xss": (
        "\"'><svg onload=alert(1)>",
        "<script>alert('bbf')</script>",
        "javascript:alert(1)",
    ),
    "sqli": (
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL--",
        '" OR "1"="1" --',
    ),
    "ssti": (
        "{{7*7}}",
        "${7*7}",
        "<%#=7*7%>",
    ),
    "path_traversal": (
        "../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
    ),
}


INTERESTING_STATUSES = {401, 403, 404, 500, 502, 503, 504}
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


@dataclass
class FuzzResult:
    """Container for request/response metadata collected during fuzzing."""

    location: str
    payload: str
    status_code: Optional[int]
    response_time: Optional[float]
    reflected: bool
    reason: str


class PayloadSource:
    """Utility class for managing payload sources and enrichment."""

    def __init__(self, user_payloads: Optional[Path] = None) -> None:
        self._payloads: List[str] = []
        if user_payloads:
            self._payloads.extend(self._load_file_payloads(user_payloads))
        if not self._payloads:
            for payloads in DEFAULT_PAYLOADS.values():
                self._payloads.extend(payloads)

    @staticmethod
    def _load_file_payloads(path: Path) -> Iterable[str]:
        with path.open("r", encoding="utf8") as handle:
            for line in handle:
                payload = line.strip()
                if payload and not payload.startswith("#"):
                    yield payload

    @property
    def values(self) -> Sequence[str]:
        return tuple(dict.fromkeys(self._payloads))  # deduplicate


class BaselineResponse:
    """Tracks baseline status/length to highlight anomalies."""

    def __init__(self, response: Response) -> None:
        self.status_code = response.status_code
        self.length = len(response.content or b"")

    def describe_deviation(self, response: Response) -> str:
        if response.status_code != self.status_code:
            return f"status {response.status_code} vs baseline {self.status_code}"
        new_length = len(response.content or b"")
        if abs(new_length - self.length) > max(25, self.length * 0.15):
            return (
                f"length {new_length} (Δ {new_length - self.length}) vs baseline {self.length}"
            )
        return "matches baseline"


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="HTTP fuzzing helper optimised for bug bounty reconnaissance.",
    )
    parser.add_argument("url", help="Target URL to fuzz")
    parser.add_argument(
        "--method",
        default="GET",
        help="HTTP method to use for fuzzing (default: GET)",
    )
    parser.add_argument(
        "--payloads",
        type=Path,
        help="Optional newline-delimited payload file to override defaults.",
    )
    parser.add_argument(
        "--params",
        type=Path,
        help="Wordlist containing parameter names to fuzz (defaults to parameters already present in the URL).",
    )
    parser.add_argument(
        "--headers",
        type=Path,
        help="Wordlist containing header names to fuzz (e.g. X-Forwarded-For).",
    )
    parser.add_argument(
        "--json",
        type=Path,
        help="Path to a JSON template file used as request body when fuzzing JSON APIs.",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=8,
        help="Number of concurrent workers to use (default: 8).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds (default: 10).",
    )
    parser.add_argument(
        "--user-agent",
        default="BugBountyFuzzer/1.0",
        help="User-Agent header to send with requests.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional CSV file to store fuzzing results for later analysis.",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify TLS certificates (disabled by default for recon convenience).",
    )
    return parser


def load_wordlist(path: Optional[Path]) -> List[str]:
    if not path:
        return []
    with path.open("r", encoding="utf8") as handle:
        return [line.strip() for line in handle if line.strip() and not line.startswith("#")]


def prepare_params(url: str, wordlist: Sequence[str]) -> List[str]:
    parsed = urlparse(url)
    params = {key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    params.update(wordlist)
    return sorted(params)


def build_url_with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query_items = list(parse_qsl(parsed.query, keep_blank_values=True))
    updated = False
    for idx, (key, _) in enumerate(query_items):
        if key == param:
            query_items[idx] = (key, value)
            updated = True
            break
    if not updated:
        query_items.append((param, value))
    new_query = urlencode(query_items, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def build_headers(base_headers: Dict[str, str], header: str, payload: str) -> Dict[str, str]:
    headers = {k: v for k, v in base_headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}
    headers[header] = payload
    return headers


def create_json_body(template_path: Optional[Path], field: str, payload: str) -> Optional[str]:
    if not template_path:
        return None
    with template_path.open("r", encoding="utf8") as handle:
        try:
            template = json.load(handle)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Invalid JSON template: {exc}") from exc

    def inject_value(node, key_path: Tuple[str, ...]) -> None:
        if not key_path:
            return
        current_key = key_path[0]
        if isinstance(node, dict):
            if len(key_path) == 1:
                node[current_key] = payload
            else:
                inject_value(node.setdefault(current_key, {}), key_path[1:])
        else:
            raise SystemExit("JSON template must contain only objects for nested fuzzing")

    inject_value(template, tuple(field.split(".")))
    return json.dumps(template)


def baseline_request(
    session: requests.Session,
    url: str,
    method: str,
    headers: Dict[str, str],
    json_body: Optional[str],
    timeout: float,
    verify: bool,
) -> Optional[BaselineResponse]:
    try:
        resp = session.request(
            method,
            url,
            headers=headers,
            data=None if json_body is None else json_body,
            timeout=timeout,
            verify=verify,
        )
        return BaselineResponse(resp)
    except requests.RequestException:
        return None


def fuzz_worker(
    session: requests.Session,
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[str],
    payload: str,
    location: str,
    timeout: float,
    verify: bool,
    baseline: Optional[BaselineResponse],
) -> FuzzResult:
    started = time.perf_counter()
    try:
        response = session.request(
            method,
            url,
            headers=headers,
            data=body,
            timeout=timeout,
            verify=verify,
            allow_redirects=False,
        )
        elapsed = time.perf_counter() - started
        reflected = payload in response.text if response.content else False
        reason = ""
        if baseline and response is not None:
            reason = baseline.describe_deviation(response)
        if response.status_code in INTERESTING_STATUSES and not reason:
            reason = f"interesting status {response.status_code}"
        return FuzzResult(
            location=location,
            payload=payload,
            status_code=response.status_code,
            response_time=elapsed,
            reflected=reflected,
            reason=reason or "",
        )
    except requests.RequestException as exc:
        return FuzzResult(
            location=location,
            payload=payload,
            status_code=None,
            response_time=None,
            reflected=False,
            reason=str(exc),
        )


def build_header_dict(args: argparse.Namespace) -> Dict[str, str]:
    headers = {"User-Agent": args.user_agent}
    # Preserve host header when fuzzing absolute URLs to avoid redirect noise.
    parsed = urlparse(args.url)
    if parsed.hostname:
        headers.setdefault("Host", parsed.hostname)
    return headers


def write_results_to_csv(path: Path, results: Sequence[FuzzResult]) -> None:
    with path.open("w", newline="", encoding="utf8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["location", "payload", "status_code", "response_time", "reflected", "reason"])
        for item in results:
            writer.writerow(
                [
                    item.location,
                    item.payload,
                    item.status_code or "",
                    f"{item.response_time:.3f}" if item.response_time else "",
                    "yes" if item.reflected else "no",
                    item.reason,
                ]
            )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    payloads = PayloadSource(args.payloads).values
    if not payloads:
        parser.error("No payloads available after processing defaults and user file")

    base_headers = build_header_dict(args)
    header_wordlist = load_wordlist(args.headers)
    param_wordlist = load_wordlist(args.params)

    json_fields: List[str] = []
    if args.json:
        json_fields = load_wordlist(args.params) if args.params else []
        if not json_fields:
            parser.error("When using --json you must provide --params listing JSON fields to fuzz")

    session = requests.Session()
    session.headers.update({k: v for k, v in base_headers.items() if k.lower() not in HOP_BY_HOP_HEADERS})

    baseline = baseline_request(
        session,
        args.url,
        args.method,
        session.headers,
        None,
        args.timeout,
        args.verify,
    )

    tasks = []
    lock = threading.Lock()
    results: List[FuzzResult] = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Parameter fuzzing.
        params_to_test = prepare_params(args.url, param_wordlist)
        for param in params_to_test:
            for payload in payloads:
                url = build_url_with_param(args.url, param, payload)
                headers = dict(session.headers)
                future = executor.submit(
                    fuzz_worker,
                    session,
                    args.method,
                    url,
                    headers,
                    None,
                    payload,
                    f"param:{param}",
                    args.timeout,
                    args.verify,
                    baseline,
                )
                tasks.append(future)

        # Header fuzzing.
        for header in header_wordlist:
            for payload in payloads:
                headers = build_headers(session.headers, header, payload)
                future = executor.submit(
                    fuzz_worker,
                    session,
                    args.method,
                    args.url,
                    headers,
                    None,
                    payload,
                    f"header:{header}",
                    args.timeout,
                    args.verify,
                    baseline,
                )
                tasks.append(future)

        # JSON body fuzzing.
        for field in json_fields:
            for payload in payloads:
                body = create_json_body(args.json, field, payload)
                headers = dict(session.headers)
                headers["Content-Type"] = "application/json"
                future = executor.submit(
                    fuzz_worker,
                    session,
                    args.method,
                    args.url,
                    headers,
                    body,
                    payload,
                    f"json:{field}",
                    args.timeout,
                    args.verify,
                    baseline,
                )
                tasks.append(future)

        for future in as_completed(tasks):
            result = future.result()
            with lock:
                results.append(result)
            status = result.status_code if result.status_code is not None else "ERR"
            reflection = "R" if result.reflected else "-"
            reason = f" :: {result.reason}" if result.reason else ""
            time_taken = (
                f"{result.response_time:.2f}s"
                if result.response_time is not None
                else "--"
            )
            print(f"[{status}] ({time_taken}) {reflection} {result.location} -> {result.payload}{reason}")

    if args.output:
        write_results_to_csv(args.output, results)
        print(f"[+] Results written to {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
