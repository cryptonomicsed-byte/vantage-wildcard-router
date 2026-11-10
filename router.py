"""
Dynamic wildcard-subdomain router for *.{vps-ip}.sslip.io.
"""
import os
import time
from typing import Dict, Optional, Tuple

import httpx
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse, Response, RedirectResponse
from starlette.routing import Route

VANTAGE_INTERNAL = os.environ.get("VANTAGE_INTERNAL_URL", "http://127.0.0.1:8001")
VANTAGE_PUBLIC = os.environ.get("VANTAGE_PUBLIC_URL", "https://omokoda.duckdns.org")
SSLIP_SUFFIX_HINT = os.environ.get("SSLIP_SUFFIX_HINT", ".sslip.io")
CACHE_TTL_SECONDS = 30

_cache: Dict[str, Tuple[float, bool, Optional[str]]] = {}

EXCLUDED_RESP_HEADERS = {
    "content-encoding", "transfer-encoding", "connection",
    "keep-alive", "date", "server", "content-length",
}


def _agent_name_from_host(host: str) -> Optional[str]:
    host = host.split(":")[0]
    if not host.endswith(SSLIP_SUFFIX_HINT):
        return None
    label = host.split(".")[0]
    return label or None


async def _lookup_agent(agent_name: str) -> Tuple[bool, Optional[str]]:
    now = time.monotonic()
    cached = _cache.get(agent_name)
    if cached and (now - cached[0]) < CACHE_TTL_SECONDS:
        return cached[1], cached[2]

    exists, endpoint = False, None
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"{VANTAGE_INTERNAL}/api/agents/{agent_name}/public-endpoint"
            )
        if resp.status_code == 200:
            exists = True
            endpoint = resp.json().get("public_endpoint")
    except httpx.HTTPError:
        exists, endpoint = False, None

    _cache[agent_name] = (now, exists, endpoint)
    return exists, endpoint


async def ask_tls(request):
    domain = request.query_params.get("domain", "")
    agent_name = _agent_name_from_host(domain)
    if not agent_name:
        return PlainTextResponse("not a recognized sslip.io host", status_code=403)
    exists, _ = await _lookup_agent(agent_name)
    if not exists:
        return PlainTextResponse("no such agent", status_code=403)
    return PlainTextResponse("ok", status_code=200)


async def catch_all(request):
    host = request.headers.get("host", "")
    agent_name = _agent_name_from_host(host)

    if not agent_name:
        return Response("Unknown host", status_code=404)

    _exists, public_endpoint = await _lookup_agent(agent_name)

    if not public_endpoint:
        return RedirectResponse(
            f"{VANTAGE_PUBLIC}/agent/{agent_name}", status_code=302
        )

    target_url = public_endpoint.rstrip("/") + str(request.url.path)
    if request.url.query:
        target_url += f"?{request.url.query}"

    upstream_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length")
    }
    upstream_headers["X-Forwarded-Host"] = host
    upstream_headers["X-Forwarded-Proto"] = "https"
    upstream_headers["Accept-Encoding"] = "identity"

    body = await request.body()
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
            upstream_resp = await client.request(
                request.method,
                target_url,
                headers=upstream_headers,
                content=body,
            )
    except httpx.HTTPError:
        return Response(
            f"Upstream {public_endpoint} unreachable", status_code=502
        )

    body_bytes = upstream_resp.content
    resp_headers = {
        k: v for k, v in upstream_resp.headers.items()
        if k.lower() not in EXCLUDED_RESP_HEADERS
    }
    resp_headers["content-length"] = str(len(body_bytes))
    return Response(
        content=body_bytes,
        status_code=upstream_resp.status_code,
        headers=resp_headers,
    )


app = Starlette(routes=[
    Route("/internal/ask-tls", ask_tls, methods=["GET"]),
    Route("/{path:path}", catch_all, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]),
])
