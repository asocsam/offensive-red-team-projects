"""Reverse HTTPS proxy with payload injection capabilities.

The proxy terminates TLS locally using operator supplied certificates, forwards
the request to an upstream target and optionally injects payloads into text
responses.  It is aimed at lab environments where defenders want to observe how
clients behave when malicious content is introduced into an otherwise trusted
connection.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path
from typing import Optional

from aiohttp import ClientSession, web


class PayloadInjector:
    """Simple HTML/text payload injector."""

    def __init__(self, payload: Optional[str]) -> None:
        self.payload = payload

    def apply(self, body: bytes, content_type: str) -> bytes:
        if not self.payload:
            return body
        if "html" in content_type:
            text = body.decode("utf8", errors="ignore")
            insertion = self.payload
            if "</body>" in text.lower():
                lower = text.lower()
                index = lower.rfind("</body>")
                return (text[:index] + insertion + text[index:]).encode("utf8")
            return (text + insertion).encode("utf8")
        if content_type.startswith("text/"):
            return body + f"\n{self.payload}\n".encode("utf8")
        return body


async def handle_request(
    request: web.Request,
    client: ClientSession,
    injector: PayloadInjector,
    upstream: str,
) -> web.Response:
    path_qs = request.rel_url
    url = f"{upstream}{path_qs}"
    body = await request.read()
    headers = dict(request.headers)
    headers.pop("Host", None)

    async with client.request(
        request.method,
        url,
        headers=headers,
        data=body if body else None,
        allow_redirects=False,
    ) as resp:
        content = await resp.read()
        content_type = resp.headers.get("Content-Type", "application/octet-stream")
        modified = injector.apply(content, content_type)
        response = web.Response(
            status=resp.status,
            headers=resp.headers,
            body=modified,
        )
        if len(modified) != len(content):
            response.headers["Content-Length"] = str(len(modified))
        return response


async def create_app(upstream: str, injector: PayloadInjector) -> web.Application:
    app = web.Application()

    session = ClientSession(
        base_url=upstream,
        trust_env=True,
    )

    async def close_session(app: web.Application) -> None:
        await session.close()

    app.on_cleanup.append(close_session)

    async def proxy_handler(request: web.Request) -> web.Response:
        return await handle_request(request, session, injector, upstream)

    app.router.add_route("*", "/{tail:.*}", proxy_handler)
    return app


def load_payload(path: Optional[Path]) -> Optional[str]:
    if not path:
        return None
    return path.read_text(encoding="utf8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="HTTPS reverse proxy with payload injection.",
    )
    parser.add_argument("upstream", help="Upstream server base URL (e.g. https://target.local)")
    parser.add_argument(
        "--listen-host",
        default="0.0.0.0",
        help="Local interface to bind to (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=8443,
        help="Local port to bind to (default: 8443)",
    )
    parser.add_argument(
        "--cert",
        type=Path,
        required=True,
        help="Path to PEM encoded TLS certificate served to clients.",
    )
    parser.add_argument(
        "--key",
        type=Path,
        required=True,
        help="Path to PEM encoded private key matching --cert.",
    )
    parser.add_argument(
        "--inject",
        type=Path,
        help="Optional file whose contents will be injected into HTML/text responses.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    injector = PayloadInjector(load_payload(args.inject))
    app = asyncio.run(create_app(args.upstream, injector))

    ssl_context = None
    if args.cert and args.key:
        import ssl

        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(args.cert, args.key)

    web.run_app(app, host=args.listen_host, port=args.listen_port, ssl_context=ssl_context)


if __name__ == "__main__":
    main()
