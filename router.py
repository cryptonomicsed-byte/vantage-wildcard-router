"""
Dynamic wildcard-subdomain router for *.{vps-ip}.sslip.io.

Terminates behind nginx's regex server_name capture, which forwards every
sslip.io request here regardless of subdomain. This process does the part
nginx/Caddy can't do in config alone: resolve "which agent owns this
subdomain" via a live call to Vantage's agent registry, then reverse-proxy
the request to whatever public_endpoint that agent registered.

Design intent (per the plan posted to guild bino / vault):
- One static nginx block hands everything here -- no per-agent config edits.
- Lookup goes through Vantage's cheap, unauthenticated
  GET /api/agents/{name}/public-endpoint route (no joins, purpose-built).
- Falls back to Vantage's own agent-profile page when an agent has no
  public_endpoint registered, per owner decision -- no placeholder page.
- Short in-process TTL cache so we don't hit Vantage on every single request
  for a live subdomain.

Also serves Caddy's on-demand-TLS `ask` callback (/internal/ask-tls?domain=)
-- reuses the exact same registry lookup so "does this hostname deserve a
real cert" and "does this hostname have a backend" are answered by one
source of truth, not two. Denies (non-200) for any hostname whose agent-name
label doesn't exist in Vantage's registry -- this is the abuse-vector guard:
a garbage Host header never reaches Let's Encrypt.
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

# (exists, public_endpoint) -- exists=False means "no such agent", which is
# distinct from exists=True/endpoint=None ("real agent, no endpoint set").
_cache: Dict[str, Tuple[float, bool, Optional[str]]] = {}
_client = httpx.AsyncClient(timeout=10.0)


def _agent_name_from_host(host: str) -> Optional[str]:
    """First label of foo.{ip-with-dashes}.sslip.io is the agent name.
    e.g. 'agent-phone-scout.2-25-70-156.sslip.io' -> 'agent-phone-scout'."""
    host = host.split(":")[0]
    if not host.endswith(SSLIP_SUFFIX_HINT):
        return None
    label = host.split(".")[0]
    return label or None


async def _lookup_agent(agent_name: str) -> Tuple[bool, Optional[str]]:
    """Returns (exists, public_endpoint). Single source of truth shared by
    both request routing and the Caddy ask-callback."""
    now = time.monotonic()
    cached = _cache.get(agent_name)
    if cached and (now - cached[0]) < CACHE_TTL_SECONDS:
        return cached[1], cached[2]

    exists, endpoint = False, None
    try:
        resp = await _client.get(
            f"{VANTAGE_INTERNAL}/api/agents/{agent_name}/public-endpoint"
        )
        if resp.status_code == 200:
            exists = True
            endpoint = resp.json().get("public_endpoint")
    except httpx.HTTPError:
        # Registry unreachable -- fail closed (not-exists) for the ask
        # callback (no cert issuance on an unverifiable claim), and fail
        # toward the safe fallback (Vantage's own profile page) for routing.
        exists, endpoint = False, None

    _cache[agent_name] = (now, exists, endpoint)
    return exists, endpoint


async def ask_tls(request):
    """Caddy on_demand_tls 'ask' callback: GET ?domain=<sni-hostname>.
    200 = allow cert issuance, anything else = deny. This is the guard
    against a garbage Host header triggering a real Let's Encrypt request."""
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
        # Owner decision: fall back to Vantage's own generic agent-profile
        # page, no dedicated placeholder page.
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

    body = await request.body()
    try:
        upstream_resp = await _client.request(
            request.method,
            target_url,
            headers=upstream_headers,
            content=body,
            follow_redirects=False,
        )
    except httpx.HTTPError:
        return Response(
            f"Upstream {public_endpoint} unreachable", status_code=502
        )

    excluded = {"content-encoding", "transfer-encoding", "connection"}
    resp_headers = {
        k: v for k, v in upstream_resp.headers.items() if k.lower() not in excluded
    }
    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=resp_headers,
    )


app = Starlette(routes=[
    Route("/internal/ask-tls", ask_tls, methods=["GET"]),
    Route("/{path:path}", catch_all, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]),
])
