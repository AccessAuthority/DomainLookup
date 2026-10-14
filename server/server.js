// DomainLookup — zero-dependency Node.js server (Node 18+).
// Serves the static site AND the lookup API from one origin, so no CORS problems and no extra setup.
//   npm start            -> http://localhost:8080
//   Render / Railway     -> build: (none)   start: node server/server.js
import http from 'node:http';
import net from 'node:net';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { normalizeDomain } from '../js/domain-validator.js';
import { registrable } from './psl.js';
import { whoisState } from './whois-state.js';
import { HOST, isPrivateIp, safeGet, clientKey, RateLimiter, securityHeaders, corsHeaders } from './guard.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = Number(process.env.PORT) || 8080;
const ALLOWED = (process.env.ALLOWED_ORIGIN || '').split(',').map(x => x.trim()).filter(Boolean); // empty = same-origin only
const RATE = Number(process.env.RATE_LIMIT_PER_MIN) || 40;          // API cost per IP per minute
const GLOBAL_RATE = Number(process.env.GLOBAL_RATE_PER_MIN) || 300;  // every request per IP per minute
const MAX_INFLIGHT = Number(process.env.MAX_INFLIGHT_LOOKUPS) || 60; // concurrent uncached upstream lookups
const TTL = 60_000;

/* ---------- SSRF guard: only public IPs, hostnames only (WHOIS path; HTTP path uses guard.js safeGet) ---------- */
async function publicAddress(host) {
  if (!HOST.test(host)) throw new Error('bad host');
  const list = await dns.lookup(host, { all: true });
  if (!list.length || list.some(a => isPrivateIp(a.address))) throw new Error('blocked address');
  return list[0].address;
}

/* ---------- RDAP ---------- */
let boot = null, bootAt = 0;
async function bootstrap() {
  if (boot && Date.now() - bootAt < 3_600_000) return boot;
  let lastErr;
  for (let i = 0; i < 2; i++) { // one retry, then fall back to the last good copy so a flaky IANA never takes the whole site down
    try {
      const r = await fetch('https://data.iana.org/rdap/dns.json', { signal: AbortSignal.timeout(10_000) });
      if (!r.ok) throw new Error('bootstrap ' + r.status);
      const j = await r.json(), m = new Map();
      for (const s of j.services || []) {
        const urls = s[1].filter(u => /^https:/i.test(u)).concat(s[1].filter(u => /^http:/i.test(u)));
        for (const e of s[0]) m.set(String(e).toLowerCase(), urls);
      }
      if (!m.size) throw new Error('empty bootstrap');
      boot = m; bootAt = Date.now(); return m;
    } catch (e) { lastErr = e; }
  }
  if (boot) { bootAt = Date.now() - 3_300_000; return boot; } // stale copy, retry in ~5 min
  throw lastErr;
}
function service(domain, m) {
  const l = domain.split('.');
  for (let i = 0; i < l.length; i++) { const u = m.get(l.slice(i).join('.')); if (u?.length) return u; }
  return null;
}
async function rdap(url) {
  try {
    const r = await safeGet(url, { headers: { accept: 'application/rdap+json, application/json' }, timeout: 10_000, maxBytes: 2_000_000, hops: 3 });
    if (r.status === 404) return { code: 'http404' };
    if (r.status === 429) return { code: 'http429' };
    if (r.status >= 500) return { code: 'http5xx' };
    if (r.status < 200 || r.status >= 300) return { code: 'httpOther' };
    try { return { url, json: JSON.parse(r.body.toString('utf8')) }; } catch { return { code: 'json' }; }
  } catch (e) { return { code: e?.name === 'TimeoutError' ? 'timeout' : e?.name === 'TooLargeError' ? 'json' : 'network' }; }
}
const safeRdapUrl = h => { try { const u = new URL(h); return u.protocol === 'https:' && HOST.test(u.hostname) ? u.href : null; } catch { return null; } };

async function getRdap(domain, out) {
  try {
    const bases = service(domain, await bootstrap());
    if (!bases) { out.errors.rdap = 'noservice'; return; }
    let last;
    for (const b of bases.slice(0, 2)) {
      const r = await rdap(b.replace(/\/?$/, '/') + 'domain/' + encodeURIComponent(domain));
      if (r.json) { out.rdap = r; break; }
      last = r.code; if (!['network', 'timeout', 'http5xx'].includes(r.code)) break;
    }
    if (!out.rdap) { out.errors.rdap = last; return; }
    // Thin registries (.com/.net) link to the registrar's full RDAP record.
    const rel = (out.rdap.json.links || []).find(l => l?.rel === 'related' && /rdap/i.test(l.type || '') && l.href);
    const x = rel && safeRdapUrl(rel.href);
    if (x && x !== out.rdap.url) { const r = await rdap(x); if (r.json) out.registrarRdap = r; }
  } catch { out.errors.rdap = 'network'; }
}

/* ---------- WHOIS (port 43) ---------- */
async function whoisQuery(server, query, ms = 8000) {
  const ip = await publicAddress(server);
  return new Promise(resolve => {
    let text = '', done = false;
    const finish = () => { if (done) return; done = true; clearTimeout(timer); sock.destroy(); resolve(text); };
    const sock = net.connect({ host: ip, port: 43 });
    const timer = setTimeout(finish, ms);
    sock.setEncoding('utf8');
    sock.on('connect', () => sock.write(query + '\r\n'));
    sock.on('data', d => { text += d; if (text.length > 200_000) finish(); });
    sock.on('end', finish); sock.on('close', finish); sock.on('error', finish);
  });
}
// A few registries need a special query syntax (Verisign: "domain x", DENIC: "-T dn,ace x", JPRS: "x/e").
const wq = (srv, d) => whoisQuery(srv, /verisign-grs/i.test(srv) ? 'domain ' + d : /(^|\.)denic\.de$/i.test(srv) ? '-T dn,ace ' + d : /(^|\.)jprs\.jp$/i.test(srv) ? d + '/e' : d);
const whoisSrv = new Map();

async function getWhois(domain, out) {
  try {
    const tld = domain.split('.').pop();
    let srv = whoisSrv.get(tld);
    if (srv === undefined) {
      const t = await whoisQuery('whois.iana.org', tld);
      srv = (t.match(/^whois:\s*(\S+)/mi) || [])[1] || '';
      if (srv || t.trim()) whoisSrv.set(tld, srv);
    }
    if (!srv || !HOST.test(srv)) { out.errors.whois = 'noservice'; return; }
    const text = await wq(srv, domain);
    if (!text.trim()) { out.errors.whois = 'network'; return; }
    out.whois = { server: srv, text };
    const m = text.match(/(?:Registrar WHOIS Server|Whois Server|Registrar Whois):\s*(\S+)/i);
    const ref = m && m[1].replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase();
    if (ref && ref !== srv && HOST.test(ref)) {
      try { const t = await wq(ref, domain); if (t.trim()) out.whois.referral = { server: ref, text: t }; } catch { /* optional hop */ }
    }
  } catch { out.errors.whois = 'network'; }
}

/* ---------- Lookup API ---------- */
const cache = new Map(), inflight = new Map();
const apiLimiter = new RateLimiter(RATE), globalLimiter = new RateLimiter(GLOBAL_RATE);
async function lookup(domain) {
  const c = cache.get(domain);
  if (c && c.exp > Date.now()) return c.val;
  if (inflight.has(domain)) return inflight.get(domain);
  if (inflight.size >= MAX_INFLIGHT) return { status: 503, body: { error: 'busy' } }; // shed load instead of exhausting sockets/memory
  const p = (async () => {
    const out = { domain, rdap: null, registrarRdap: null, whois: null, errors: {}, available: null };
    await Promise.all([getRdap(domain, out), getWhois(domain, out)]);
    const ws = whoisState(out.whois?.text);
    if (out.whois && ws === 'unknown' && !out.rdap) { out.whois = null; out.errors.whois = 'http429'; } // rate-limit / junk reply is not a record
    if (out.rdap) out.available = false;
    else if (out.errors.rdap === 'http404' && ws !== 'registered') out.available = true; // RDAP: 404 = no such domain
    else if (ws === 'available') out.available = true;
    else if (ws === 'registered') out.available = false;
    const wt = out.whois?.text;
    const status = !out.rdap && !wt && out.available !== true ? 502 : 200;
    const val = { status, body: out };
    if (status === 200) { cache.set(domain, { val, exp: Date.now() + TTL }); if (cache.size > 2000) cache.clear(); }
    return val;
  })().finally(() => inflight.delete(domain));
  inflight.set(domain, p);
  return p;
}

/* ---------- Availability check (fast: RDAP first, WHOIS only if RDAP can't answer) ---------- */
const chkCache = new Map();
async function checkOne(domain) {
  const c = chkCache.get(domain);
  if (c && c.exp > Date.now()) return c.val;
  let state = 'unknown', via = null;
  try {
    const bases = service(domain, await bootstrap());
    for (const b of (bases || []).slice(0, 2)) {
      const r = await rdap(b.replace(/\/?$/, '/') + 'domain/' + encodeURIComponent(domain));
      if (r.json) { state = 'registered'; via = 'rdap'; break; }
      if (r.code === 'http404') { state = 'available'; via = 'rdap'; break; } // RDAP: 404 = no such domain
      if (!['network', 'timeout', 'http5xx'].includes(r.code)) break;
    }
  } catch { /* fall through to WHOIS */ }
  if (state === 'unknown') {
    const o = { errors: {} }; await getWhois(domain, o);
    state = whoisState(o.whois?.text); if (state !== 'unknown') via = 'whois';
  }
  const val = { domain, state, via };
  if (state !== 'unknown') { chkCache.set(domain, { val, exp: Date.now() + TTL }); if (chkCache.size > 5000) chkCache.clear(); }
  return val;
}
const TLD_OK = /^(?:[a-z]{2,24}|xn--[a-z0-9-]{1,40})(?:\.[a-z]{2,24})?$/;
function checkList(q) { // ?domain=a.com  OR  ?name=a&tlds=com,net,org
  const one = q.get('domain');
  if (one) { const n = normalizeDomain(one), r = n.error ? null : registrable(n.domain); return r ? [r] : null; }
  const name = (q.get('name') || '').trim().toLowerCase(), tlds = (q.get('tlds') || '').toLowerCase().split(',').map(x => x.trim().replace(/^\./, '')).filter(Boolean);
  if (!name || !tlds.length || tlds.length > 12 || !tlds.every(t => TLD_OK.test(t))) return null;
  const out = tlds.map(t => normalizeDomain(name + '.' + t)); // reuses the same validation (IDN, length, labels)
  const regs = out.map(o => (o.error ? null : registrable(o.domain)));
  return regs.some(r => !r) ? null : [...new Set(regs)];
}

/* ---------- HTTP helpers ---------- */
function json(req, res, status, body, extra = {}) {
  res.writeHead(status, { ...securityHeaders(req, { api: true }), ...corsHeaders(req, ALLOWED), 'content-type': 'application/json; charset=utf-8', 'cache-control': status === 200 ? 'public, max-age=60' : 'no-store', ...extra });
  res.end(status === 204 ? undefined : JSON.stringify(body));
}
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.webp': 'image/webp', '.ico': 'image/x-icon', '.json': 'application/json', '.txt': 'text/plain; charset=utf-8', '.xml': 'application/xml', '.webmanifest': 'application/manifest+json' };
const PUBLIC_TOP = new Set(['css', 'js', 'assets', '.well-known']);

// Small in-memory file cache: compress once, not on every request (gzipSync per request is a CPU-exhaustion vector).
const files = new Map();
function loadFile(file, cb) {
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) return cb(err || new Error('not a file'));
    const hit = files.get(file);
    if (hit && hit.mtime === st.mtimeMs) return cb(null, hit);
    if (st.size > 5_000_000) return cb(new Error('too large'));
    fs.readFile(file, (e, buf) => {
      if (e) return cb(e);
      const type = MIME[path.extname(file)], text = /^(text|application\/(json|xml)|image\/svg)/.test(type);
      const ent = { mtime: st.mtimeMs, buf, gz: text && buf.length > 1024 ? zlib.gzipSync(buf) : null, etag: `W/"${st.size.toString(16)}-${Math.round(st.mtimeMs).toString(16)}"`, type };
      if (files.size >= 300) files.clear();
      files.set(file, ent); cb(null, ent);
    });
  });
}

function serveStatic(req, res, pathname) {
  let rel;
  try { rel = decodeURIComponent(pathname); } catch { return notFound(req, res); }
  if (rel.includes('\0') || rel.includes('\\')) return notFound(req, res);
  if (rel === '/') rel = '/index.html';
  else if (!path.extname(rel)) rel += '.html'; // clean URLs: /faq -> /faq.html
  const file = path.resolve(ROOT, '.' + rel);
  const top = path.relative(ROOT, file).split(path.sep);
  const ok = !top[0].startsWith('..') && !path.isAbsolute(path.relative(ROOT, file)) &&
    (top.length === 1 ? /\.(html|txt|xml|svg|ico|webmanifest)$/.test(top[0]) : PUBLIC_TOP.has(top[0]));
  if (!ok || !MIME[path.extname(file)]) return notFound(req, res);
  loadFile(file, (err, f) => {
    if (err) return notFound(req, res);
    const h = { ...securityHeaders(req), 'content-type': f.type, etag: f.etag, 'cache-control': /\.html$/.test(file) ? 'no-cache' : 'public, max-age=3600' };
    if (req.headers['if-none-match'] === f.etag) { res.writeHead(304, h); return res.end(); }
    let body = f.buf;
    if (f.gz && /\bgzip\b/.test(req.headers['accept-encoding'] || '')) { h['content-encoding'] = 'gzip'; body = f.gz; }
    if (f.gz) h.vary = 'Accept-Encoding';
    res.writeHead(200, h); res.end(req.method === 'HEAD' ? undefined : body);
  });
}
function notFound(req, res) {
  fs.readFile(path.join(ROOT, '404.html'), (err, buf) => {
    res.writeHead(404, { ...securityHeaders(req), 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
    res.end(err ? 'Not found' : String(buf).replace('<head>', '<head><base href="/">')); // nested bad URLs still load css/js
  });
}

const server = http.createServer({ maxHeaderSize: 8192 }, async (req, res) => {
  try {
    if (req.url.length > 2048) { res.writeHead(414, securityHeaders(req)); return res.end(); }
    const u = new URL(req.url, 'http://x');
    const key = clientKey(req);
    if (u.pathname !== '/api/health' && globalLimiter.hit(key)) return json(req, res, 429, { error: 'http429' }, { 'retry-after': '60' });
    if (req.method === 'OPTIONS') return json(req, res, 204, {}, { 'content-length': '0' });
    if (u.pathname === '/api/health') return json(req, res, 200, { ok: true, service: 'DomainLookup', time: new Date().toISOString() });
    if (u.pathname === '/api/lookup') {
      if (req.method !== 'GET') return json(req, res, 405, { error: 'method' }, { allow: 'GET, OPTIONS' });
      if (apiLimiter.hit(key)) return json(req, res, 429, { error: 'http429' }, { 'retry-after': '60' });
      const n = normalizeDomain(u.searchParams.get('domain'));
      if (n.error) return json(req, res, 400, { error: 'invalid' });
      const reg = registrable(n.domain); // subdomain -> its registered domain (blog.example.com -> example.com)
      if (!reg) return json(req, res, 400, { error: 'invalid' });
      const { status, body } = await lookup(reg);
      return json(req, res, status, { ...body, input: n.domain });
    }
    if (u.pathname === '/api/check') {
      if (req.method !== 'GET') return json(req, res, 405, { error: 'method' }, { allow: 'GET, OPTIONS' });
      const list = checkList(u.searchParams);
      if (!list) return json(req, res, 400, { error: 'invalid' });
      if (apiLimiter.hit(key, Math.ceil(list.length / 2))) return json(req, res, 429, { error: 'http429' }, { 'retry-after': '60' });
      return json(req, res, 200, { results: await Promise.all(list.map(checkOne)) });
    }
    if (u.pathname.startsWith('/api/')) return json(req, res, 404, { error: 'notfound' });
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405, { ...securityHeaders(req), allow: 'GET, HEAD, OPTIONS' }); return res.end(); }
    serveStatic(req, res, u.pathname);
  } catch (e) {
    console.error(e); if (!res.headersSent) json(req, res, 500, { error: 'server' }); else res.end();
  }
});
// Slow-loris / idle-connection protection
server.headersTimeout = 10_000; server.requestTimeout = 15_000; server.keepAliveTimeout = 5_000; server.maxHeadersCount = 60; server.maxRequestsPerSocket = 200;
server.on('clientError', (err, socket) => { if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nconnection: close\r\n\r\n'); else socket.destroy(); });
server.listen(PORT, () => console.log(`DomainLookup running on http://localhost:${PORT}`));
