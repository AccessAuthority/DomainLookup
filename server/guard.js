// DomainLookup — server-side security primitives (zero dependencies).
// Kept in its own module so every rule here is unit-testable without starting the server.
import net from 'node:net';
import dnsCb from 'node:dns';
import http from 'node:http';
import https from 'node:https';

/** Hostnames only, never IP literals. */
export const HOST = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/i;

/* ================= SSRF: address classification ================= */
function v4Blocked(a, b, c) {
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||            // carrier-grade NAT
    (a === 169 && b === 254) ||                      // link-local + cloud metadata
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0 && (c === 0 || c === 2)) || // IETF protocol + TEST-NET-1
    (a === 192 && b === 88 && c === 99) ||           // 6to4 relay anycast
    (a === 198 && (b === 18 || b === 19)) ||         // benchmarking
    (a === 198 && b === 51 && c === 100) ||          // TEST-NET-2
    (a === 203 && b === 0 && c === 113);             // TEST-NET-3
}
function v6Bytes(ip) {
  let s = String(ip).toLowerCase().split('%')[0];
  const m = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (m) {
    const p = m[2].split('.').map(Number);
    if (p.length !== 4 || p.some(x => !(x >= 0 && x <= 255))) return null;
    s = m[1] + ((p[0] << 8) | p[1]).toString(16) + ':' + ((p[2] << 8) | p[3]).toString(16);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null;
  const groups = [...head, ...Array(fill).fill('0'), ...tail];
  if (groups.length !== 8) return null;
  const out = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    const n = parseInt(g, 16); out.push(n >> 8, n & 255);
  }
  return out;
}
/** true = must NOT be contacted. Anything unparsable is blocked (fail closed). */
export function isPrivateIp(ip) {
  if (net.isIPv4(ip)) { const [a, b, c] = ip.split('.').map(Number); return v4Blocked(a, b, c); }
  if (!net.isIPv6(ip)) return true;
  const b = v6Bytes(ip);
  if (!b) return true;
  const zeros = n => b.slice(0, n).every(x => x === 0);
  if (zeros(10) && b[10] === 0xff && b[11] === 0xff) return v4Blocked(b[12], b[13], b[14]);          // ::ffff:a.b.c.d
  if (zeros(12)) return true;                                                                         // ::, ::1, IPv4-compatible
  if (b[0] === 0 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) return b[4] !== 0 || b.slice(4, 12).some(Boolean) ? true : v4Blocked(b[12], b[13], b[14]); // NAT64
  if ((b[0] & 0xe0) !== 0x20) return true;                                                            // only 2000::/3 is global unicast
  if (b[0] === 0x20 && b[1] === 0x01 && ((b[2] === 0x0d && b[3] === 0xb8) || (b[2] === 0 && b[3] === 0))) return true; // docs + Teredo
  if (b[0] === 0x20 && b[1] === 0x02) return v4Blocked(b[2], b[3], b[4]);                             // 6to4
  return false;
}

/** net/tls call this to resolve names: the address that is CHECKED is the address that is USED (defeats DNS rebinding). */
export function guardedLookup(host, opts, cb) {
  if (typeof opts === 'function') { cb = opts; opts = {}; }
  dnsCb.lookup(host, { all: true, verbatim: true }, (err, list) => {
    if (err) return cb(err);
    if (!Array.isArray(list) || !list.length || list.some(a => isPrivateIp(a.address))) {
      return cb(Object.assign(new Error('blocked address'), { code: 'EBLOCKED' }));
    }
    if (opts && opts.all) return cb(null, list);
    cb(null, list[0].address, list[0].family);
  });
}

const fail = (msg, name = 'Error') => Object.assign(new Error(msg), { name });

function once(u, { headers, timeout, maxBytes }) {
  return new Promise((resolve, reject) => {
    let done = false, timer;
    const end = (fn, v) => { if (done) return; done = true; clearTimeout(timer); fn(v); };
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request(u, {
      method: 'GET', lookup: guardedLookup, agent: false,
      headers: { 'user-agent': 'DomainLookup/2', 'accept-encoding': 'identity', ...headers },
    }, res => {
      const chunks = []; let n = 0;
      res.on('data', c => { n += c.length; if (n > maxBytes) { req.destroy(); end(reject, fail('response too large', 'TooLargeError')); } else chunks.push(c); });
      res.on('end', () => end(resolve, { status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on('error', e => end(reject, e));
    });
    timer = setTimeout(() => { req.destroy(); end(reject, fail('timeout', 'TimeoutError')); }, timeout);
    req.on('error', e => end(reject, e));
    req.end();
  });
}

/**
 * Outbound GET that is safe to point at attacker-influenced URLs:
 * hostnames only, default ports only, no credentials, public IPs only (checked at connect time),
 * redirects re-validated every hop, response size and time capped, never decompresses.
 */
export async function safeGet(startUrl, { headers = {}, timeout = 10_000, maxBytes = 2_000_000, hops = 3 } = {}) {
  let url = startUrl;
  for (let i = 0; i <= hops; i++) {
    const u = new URL(url);
    if (!/^https?:$/.test(u.protocol)) throw fail('bad protocol');
    if (u.username || u.password) throw fail('credentials not allowed');
    if (u.port) throw fail('non-default port not allowed');
    if (!HOST.test(u.hostname)) throw fail('bad host');
    const r = await once(u, { headers, timeout, maxBytes });
    if (r.status >= 300 && r.status < 400 && r.headers.location) { url = new URL(r.headers.location, u).href; continue; }
    return r;
  }
  throw fail('too many redirects');
}

/* ================= Client identity + rate limiting ================= */
/**
 * Who is the client? X-Forwarded-For is attacker-controlled, so it is ignored unless TRUST_PROXY is set.
 *   TRUST_PROXY=1            one trusted proxy in front (Render, Railway, nginx): use the entry that proxy appended
 *   TRUST_PROXY=cloudflare   use CF-Connecting-IP (only if the origin is reachable through Cloudflare alone)
 */
export function clientKey(req, trust = process.env.TRUST_PROXY || '') {
  let ip = req.socket.remoteAddress || 'unknown';
  if (trust === 'cloudflare') ip = String(req.headers['cf-connecting-ip'] || ip);
  else if (/^[1-9]\d?$/.test(trust)) {
    const list = String(req.headers['x-forwarded-for'] || '').split(',').map(s => s.trim()).filter(Boolean);
    const pick = list[list.length - Number(trust)];
    if (pick) ip = pick;
  }
  ip = ip.replace(/^::ffff:/i, '');
  if (!net.isIP(ip)) return 'unknown';
  if (net.isIPv6(ip)) { const b = v6Bytes(ip); if (b) return 'v6:' + b.slice(0, 8).map(x => x.toString(16).padStart(2, '0')).join(''); } // one bucket per /64
  return ip;
}

export class RateLimiter {
  constructor(limit, windowMs = 60_000, maxKeys = 20_000) { this.limit = limit; this.win = windowMs; this.max = maxKeys; this.m = new Map(); }
  /** returns true when the caller is over the limit */
  hit(key, cost = 1) {
    const now = Date.now(); let e = this.m.get(key);
    if (!e || now > e.reset) { this.m.delete(key); e = { n: 0, reset: now + this.win }; this.m.set(key, e); this.prune(now); }
    e.n += cost;
    return e.n > this.limit;
  }
  prune(now) { // evict expired first, then oldest, so a flood of fake keys can never reset real counters
    if (this.m.size <= this.max) return;
    for (const [k, v] of this.m) { if (v.reset < now) this.m.delete(k); else break; }
    for (const k of this.m.keys()) { if (this.m.size <= this.max * 0.9) break; this.m.delete(k); }
  }
}

/* ================= Response headers ================= */
const CSP = [
  "default-src 'none'", "script-src 'self'", "style-src 'self' https://fonts.googleapis.com", "style-src-attr 'unsafe-inline'",
  "font-src https://fonts.gstatic.com", "img-src 'self' data:", "connect-src 'self' https:", "manifest-src 'self'",
  "base-uri 'self'", "form-action 'self'", "frame-ancestors 'none'", "object-src 'none'", "upgrade-insecure-requests",
].join('; ');

export function securityHeaders(req, { api = false, trust = process.env.TRUST_PROXY || '' } = {}) {
  const h = {
    'content-security-policy': CSP,
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()',
    'cross-origin-opener-policy': 'same-origin',
    'cross-origin-resource-policy': api ? 'cross-origin' : 'same-origin',
    'x-permitted-cross-domain-policies': 'none',
    'origin-agent-cluster': '?1',
  };
  const https_ = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https' && trust;
  if (https_ || process.env.FORCE_HSTS === '1') h['strict-transport-security'] = 'max-age=31536000; includeSubDomains';
  return h;
}

/** CORS: same-origin only unless ALLOWED_ORIGIN lists origins (comma separated, or "*" to knowingly open the API). */
export function corsHeaders(req, allowed) {
  if (!allowed.length) return {};
  if (allowed.includes('*')) return { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET, OPTIONS', 'access-control-max-age': '600' };
  const o = req.headers.origin;
  const h = { vary: 'Origin' };
  if (o && allowed.includes(o)) Object.assign(h, { 'access-control-allow-origin': o, 'access-control-allow-methods': 'GET, OPTIONS', 'access-control-max-age': '600' });
  return h;
}
