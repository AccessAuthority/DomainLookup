# DomainLookup
Domain lookup (RDAP + WHOIS) by **Access Authority**. Plain HTML/CSS/JS front end + a zero-dependency Node.js server (Node 18+).

## Pages
`index.html` (lookup + home) · `how-it-works.html` · `faq.html` · `developer.html` · `privacy.html` · `terms.html` · `404.html`
Search boxes on other pages open `index.html?d=example.com`, so any result is a shareable link.

## Domain availability
Every search shows a verdict badge (**Available** / **Taken**) and an "Other extensions" grid (.com .net .org .in .co .io .info .co.in) with the same status; click one to open its full record. Server: `GET /api/check?domain=a.com` or `/api/check?name=a&tlds=com,net` (RDAP 404 = available, WHOIS only if RDAP cannot answer; bulk calls count more against the rate limit). Without an API (static hosting) the browser asks each registry's RDAP directly.

## Security check, DNS tools & extras
After the main record loads, the browser runs (via public DNS-over-HTTPS, no backend change) a **Security Check** with a 0-100 score: SPF, DMARC, DKIM (10 common selectors, RSA key size), MTA-STS, TLS-RPT, MX redundancy, DNSSEC (DS record), CAA, name-server redundancy, transfer/delete locks and expiry. A **Subdomains** card resolves www, mail, webmail, ftp, blog, api, cpanel, dev, staging. The DNS card has type filters, Copy all, JSON/CSV export (formula-injection safe) and an IP-info link. Also: expiry progress bar + warning banner, skeleton loading, Print/PDF view. Logic lives in `js/security.js`.

## Platform security
SSRF/DNS-rebinding guard, response-size and time caps, spoof-proof rate limiting (`TRUST_PROXY`), strict CSP + HSTS + anti-framing headers, closed-by-default CORS, slow-loris limits, hostile-DNS-data caps. Full list, threat model and deployment checklist: **[SECURITY.md](SECURITY.md)**. Env vars: `TRUST_PROXY`, `ALLOWED_ORIGIN`, `RATE_LIMIT_PER_MIN`, `GLOBAL_RATE_PER_MIN`, `MAX_INFLIGHT_LOOKUPS`, `FORCE_HSTS`.

## Run
```
npm start            # http://localhost:8080  (site + /api/lookup on one origin)
npm test             # offline tests (parsers, validator, server routes, file-access rules)
```

## Deploy (recommended: Render, Railway, any Node host)
Push this folder, create a **Web Service**, build command: none, start command `node server/server.js` (`render.yaml` included). The API is same-origin, so `js/config.js` needs no change.
Optional env vars: `PORT`, `TRUST_PROXY` (set `1` behind a proxy such as Render), `ALLOWED_ORIGIN` (unset = same-origin only), `RATE_LIMIT_PER_MIN` (default 40).

### Alternative: static site + Cloudflare Worker
Static hosting (GitHub Pages / Netlify) has no API route; the site then falls back to direct browser RDAP (fewer registries work, no WHOIS). For full data deploy `worker/` (`cd worker && npm install && npx wrangler deploy`) and set `API_BASE` in `js/config.js`.

## How it works
`domain-validator.js` normalises input → server loads the IANA RDAP bootstrap and WHOIS server list → queries RDAP (plus the registrar's own RDAP for .com/.net) and port-43 WHOIS in parallel → `model.js` merges them → `ui.js` renders with safe DOM APIs only (`textContent`). Server protections: hostnames only, public-IP check on every outbound connection and redirect (SSRF guard), 60 s cache, per-IP rate limit, static file allow-list, security headers/CSP.

## Images and fonts
All images are served from `assets/images` (no third-party image hosts). Only fonts load from Google Fonts (see `<head>` of each page). If an image fails to load, the gradient behind it is shown.

## Which domains work
Any domain whose TLD is in the IANA RDAP bootstrap (all gTLDs, many ccTLDs) is answered via RDAP; every other TLD falls back to port-43 WHOIS found through whois.iana.org (special query syntax for Verisign, DENIC, JPRS). A subdomain such as `blog.example.com` is mapped to its registered domain `example.com` (public-suffix list in `server/psl-data.js`, ICANN section; regenerate from publicsuffix.org now and then). A bare public suffix such as `co.uk` is rejected. Rate-limit replies from a WHOIS server are never shown as a record. On Render, outbound port 43 must be reachable (it is on current plans; if WHOIS-only TLDs fail, check this first).

## Known limitations
- Many registries redact registrant data; DomainLookup shows only what is published.
- "Appears available" is not a purchase guarantee.
- Live network lookups could not be run in the build environment (no internet); logic and server routes are covered by `npm test`.
