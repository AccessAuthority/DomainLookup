# Security

How DomainLookup defends itself, what you must configure, and how to report a problem.

## Threat model

The server fetches URLs and opens WHOIS sockets that are influenced by third parties (registry data, registrar links, the domain a visitor types). That makes the server an attractive SSRF proxy and a target for abuse and resource exhaustion. The browser renders data that anyone can publish (DNS TXT, WHOIS text), so it must treat that data as hostile.

## Built-in protections

| Risk | Protection | Where |
|---|---|---|
| SSRF to internal services / cloud metadata | Hostnames only (no IP literals), default ports only, no URL credentials, private/reserved IPv4 + IPv6 ranges blocked (mapped, NAT64, 6to4, Teredo, ULA, link-local, CGNAT, TEST-NETs) | `server/guard.js` |
| DNS rebinding (name resolves public, then private) | The address that is validated is the address that is connected to (custom `lookup` on the socket), re-checked on every redirect | `guardedLookup`, `safeGet` |
| Memory exhaustion by huge upstream replies | 2 MB response cap, 200 KB WHOIS cap, 10 s timeouts, no content decompression | `safeGet`, `whoisQuery` |
| Rate-limit bypass with forged `X-Forwarded-For` | Header ignored unless `TRUST_PROXY` is set; only the proxy-appended entry is used; IPv6 limited per /64; limiter cannot be flushed by key floods | `clientKey`, `RateLimiter` |
| Request floods / CPU exhaustion | Per-IP API limit + global per-IP limit, in-flight lookup cap (503 when busy), compress-once file cache with ETag/304 | `server/server.js` |
| Slow-loris / oversized requests | Header/request timeouts, 8 KB header limit, 2 KB URL limit, 200 requests per socket | `server/server.js` |
| XSS | Everything rendered with `textContent`; links pass a protocol allow-list; CSP `script-src 'self'`, no inline script, `object-src 'none'` | `js/ui.js`, headers |
| Clickjacking | `frame-ancestors 'none'`, `X-Frame-Options: DENY` | headers |
| Cross-origin API abuse | CORS is closed by default; `ALLOWED_ORIGIN` takes an explicit allow-list | `corsHeaders` |
| Downgrade / sniffing / leaks | HSTS (behind HTTPS), `nosniff`, `Referrer-Policy`, COOP/CORP, Permissions-Policy, `upgrade-insecure-requests` | headers |
| Path traversal / source disclosure | Static allow-list (only `css`, `js`, `assets`, `.well-known` and a few root file types); `..`, `\`, NUL rejected | `serveStatic` |
| Hostile DNS data in the UI | Record count and length capped, null-prototype maps, CSV export neutralises spreadsheet formulas | `js/model.js`, `js/security.js`, `js/ui.js` |
| Third-party images | None: all images are local, CSP allows `img-src 'self' data:` | |

## Deployment checklist

1. **Serve over HTTPS only.** On Render/Railway this is automatic.
2. **Set `TRUST_PROXY=1`** when behind exactly one reverse proxy (already in `render.yaml`). Without it every visitor behind the proxy shares one bucket. Use `TRUST_PROXY=cloudflare` only if the origin can be reached solely through Cloudflare.
3. **Leave `ALLOWED_ORIGIN` unset** for a single-origin deployment. For a separate front end list its exact origin.
4. **Put Cloudflare (or another WAF/CDN) in front** and add a rate-limit rule on `/api/*`. In-memory limits are per instance.
5. **Cloudflare Worker deployments:** enable the `RATE_LIMITER` binding in `worker/wrangler.toml` and replace `ALLOWED_ORIGIN = "*"` with your site origin.
6. Keep Node on a supported release and run `npm test` in CI (32 tests, including SSRF and rate-limit spoofing cases).
7. Static hosting (Netlify / Cloudflare Pages): the `_headers` file applies the same headers.

## Known limits (be honest about them)

- Google Fonts are loaded from a third party. They cannot be pinned with SRI; self-host the fonts if that matters to you.
- `style-src-attr 'unsafe-inline'` is kept for a few inline `style=""` attributes. Scripts remain fully locked down.
- The in-memory limiter and cache are per process. Run a shared limiter (Cloudflare rule, Redis) if you scale to several instances.
- The browser queries public DNS-over-HTTPS resolvers directly (disclosed in `privacy.html`).

## Reporting a vulnerability

See `/.well-known/security.txt`. Please report privately and allow reasonable time for a fix before disclosure.
