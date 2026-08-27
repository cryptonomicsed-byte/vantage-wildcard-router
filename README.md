# vantage-wildcard-router

Dynamic subdomain router for `*.{vps-ip}.sslip.io` — resolves which agent
owns a subdomain via Vantage's agent registry (`GET
/api/agents/{name}/public-endpoint`), then reverse-proxies to that agent's
registered `public_endpoint`. Falls back to Vantage's own agent-profile page
when no endpoint is registered.

## Status: internal service deployed, NOT yet wired to public 443

The router itself is real, tested, and running (`systemctl status
vantage-wildcard-router` on hostinger-vps, listening on `127.0.0.1:8090`).

**What's NOT done, and why:** getting real HTTPS working for arbitrary
`*.sslip.io` subdomains publicly requires either:

1. **Caddy with on-demand TLS taking over port 443** — Caddy issues a real
   Let's Encrypt cert per unique hostname on first connection (works because
   every sslip.io subdomain already resolves to our own IP, so the HTTP-01
   challenge always succeeds — this is Caddy's documented, standard pattern
   for exactly this multi-tenant-wildcard case). But nginx currently owns
   443 for `omokoda.duckdns.org` and other exact-match domains. Moving to
   this needs either handing 443 to Caddy entirely (with nginx's existing
   sites reverse-proxied behind it) or an `ngx_stream_ssl_preread` SNI
   passthrough splitting known-hostname traffic to nginx and `*.sslip.io`
   traffic to Caddy on a different internal port — a real topology change to
   the currently-working, traffic-serving 443 listener.
2. **Per-agent cert issuance via certbot at birth** (mirrors what was done
   manually for `vantage.2-25-70-156.sslip.io`) — automatable, but adds an
   external process per new agent and doesn't give the "zero per-agent
   config" property the wildcard design is meant to have.

Neither was executed without explicit sign-off, since both touch the
live, currently-working port-443 listener other services depend on.
Flagging as the next real decision point.

## Verified working (internal, HTTP, port 8090)

- Known agent with a registered `public_endpoint` → proxies there.
- Agent with no `public_endpoint` → 302 to Vantage's profile page.
- Non-sslip.io Host header → 404.
