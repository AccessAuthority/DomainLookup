import { connect } from 'cloudflare:sockets';
import { normalizeDomain } from '../../js/domain-validator.js';

const HOST = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/i; // hostnames only, never IPs
const NOT_FOUND = /(no match for|not found|no data found|no entries found|no object found|nothing found|status:\s*(free|available)|is available)/i;
const SECURE = {
  'content-type': 'application/json; charset=utf-8', 'cache-control': 'public, max-age=60',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'", 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer', 'cross-origin-resource-policy': 'cross-origin', 'strict-transport-security': 'max-age=31536000; includeSubDomains',
};
// CORS allow-list: ALLOWED_ORIGIN = "https://site.example" or a comma list. "*" (or unset) opens the public API to any site.
function pickOrigin(req, env) {
  const list = String(env.ALLOWED_ORIGIN || '*').split(',').map(x => x.trim()).filter(Boolean);
  if (list.includes('*')) return '*';
  const o = req.headers.get('origin'); return o && list.includes(o) ? o : '';
}
const hdr = o => ({ ...SECURE, vary: 'Origin', ...(o ? { 'access-control-allow-origin': o, 'access-control-allow-methods': 'GET, OPTIONS', 'access-control-max-age': '600' } : {}) });
const send = (b, s, o) => new Response(JSON.stringify(b), { status: s, headers: hdr(o) });

let boot = null, bootAt = 0; const whoisSrv = new Map(), hits = new Map();
function limited(ip) { // small per-isolate limiter; add a Cloudflare rate-limit rule for real protection
  const now = Date.now(), h = hits.get(ip);
  if (!h || now > h[1]) { hits.set(ip, [1, now + 60000]); if (hits.size > 5000) hits.clear(); return false; }
  return ++h[0] > 30;
}
async function bootstrap() {
  if (boot && Date.now() - bootAt < 3600e3) return boot;
  const r = await fetch('https://data.iana.org/rdap/dns.json', { cf: { cacheTtl: 86400, cacheEverything: true }, signal: AbortSignal.timeout(10000) });
  const j = await r.json(), m = new Map();
  for (const s of j.services || []) for (const e of s[0]) m.set(String(e).toLowerCase(), s[1].filter(u => /^https:/i.test(u)).concat(s[1].filter(u => /^http:/i.test(u))));
  boot = m; bootAt = Date.now(); return m;
}
function service(domain, m) { const l = domain.split('.'); for (let i = 0; i < l.length; i++) { const u = m.get(l.slice(i).join('.')); if (u?.length) return u; } return null; }

async function readCapped(r, max = 2_000_000) { // never buffer more than `max` bytes of an untrusted body
  if (Number(r.headers.get('content-length')) > max) throw Object.assign(new Error('too large'), { name: 'TooLargeError' });
  const rd = r.body.getReader(), parts = []; let n = 0;
  for (;;) { const { value, done } = await rd.read(); if (done) break; n += value.length; if (n > max) { rd.cancel().catch(() => {}); throw Object.assign(new Error('too large'), { name: 'TooLargeError' }); } parts.push(value); }
  const all = new Uint8Array(n); let o = 0; for (const p of parts) { all.set(p, o); o += p.length; }
  return new TextDecoder().decode(all);
}
async function rdap(url) {
  try {
    let r;
    for (let hop = 0; hop <= 3; hop++) { // redirects are followed by hand so every hop is re-validated
      const u = new URL(url);
      if (u.protocol !== 'https:' || u.username || u.password || u.port || !HOST.test(u.hostname)) return { code: 'network' };
      r = await fetch(u, { headers: { accept: 'application/rdap+json, application/json' }, signal: AbortSignal.timeout(10000), redirect: 'manual' });
      if (r.status >= 300 && r.status < 400 && r.headers.get('location')) { url = new URL(r.headers.get('location'), u).href; continue; }
      break;
    }
    if (r.status >= 300 && r.status < 400) return { code: 'network' };
    if (r.status === 404) return { code: 'http404' }; if (r.status === 429) return { code: 'http429' };
    if (r.status >= 500) return { code: 'http5xx' }; if (!r.ok) return { code: 'httpOther' };
    try { return { url, json: JSON.parse(await readCapped(r)) }; } catch { return { code: 'json' }; }
  } catch (e) { return { code: e?.name === 'TimeoutError' ? 'timeout' : 'network' }; }
}
function safeRdapUrl(h) { try { const u = new URL(h); return u.protocol === 'https:' && HOST.test(u.hostname) ? u.href : null; } catch { return null; } }

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
    const rel = (out.rdap.json.links || []).find(l => l?.rel === 'related' && /rdap/i.test(l.type || '') && l.href); // thin registries (.com/.net) point to the registrar's full record
    const x = rel && safeRdapUrl(rel.href);
    if (x && x !== out.rdap.url) { const r = await rdap(x); if (r.json) out.registrarRdap = r; }
  } catch { out.errors.rdap = 'network'; }
}

async function whoisQuery(server, query, ms = 8000) {
  const sock = connect({ hostname: server, port: 43 });
  const w = sock.writable.getWriter(); await w.write(new TextEncoder().encode(query + '\r\n')); w.releaseLock();
  const rd = sock.readable.getReader(), dec = new TextDecoder(); let text = '';
  const timer = setTimeout(() => sock.close().catch(() => {}), ms);
  try { for (;;) { const { value, done } = await rd.read(); if (done) break; text += dec.decode(value, { stream: true }); if (text.length > 200000) break; } }
  catch { /* timeout / reset: keep whatever text arrived */ }
  finally { clearTimeout(timer); try { await sock.close(); } catch {} }
  return text;
}
const wq = (srv, d) => whoisQuery(srv, /verisign-grs/i.test(srv) ? 'domain ' + d : d);

async function getWhois(domain, out) {
  try {
    const tld = domain.split('.').pop(); let srv = whoisSrv.get(tld);
    if (srv === undefined) { const t = await whoisQuery('whois.iana.org', tld); srv = (t.match(/^whois:\s*(\S+)/mi) || [])[1] || ''; if (srv || t.trim()) whoisSrv.set(tld, srv); }
    if (!srv || !HOST.test(srv)) { out.errors.whois = 'noservice'; return; }
    const text = await wq(srv, domain); if (!text.trim()) { out.errors.whois = 'network'; return; }
    out.whois = { server: srv, text };
    const m = text.match(/(?:Registrar WHOIS Server|Whois Server|Registrar Whois):\s*(\S+)/i);
    const ref = m && m[1].replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase();
    if (ref && ref !== srv && HOST.test(ref)) { try { const t = await wq(ref, domain); if (t.trim()) out.whois.referral = { server: ref, text: t }; } catch {} }
  } catch { out.errors.whois = 'network'; }
}

const chk = new Map();
async function checkOne(domain) {
  const c = chk.get(domain); if (c && c.exp > Date.now()) return c.val;
  let state = 'unknown', via = null;
  try {
    for (const b of (service(domain, await bootstrap()) || []).slice(0, 2)) {
      const r = await rdap(b.replace(/\/?$/, '/') + 'domain/' + encodeURIComponent(domain));
      if (r.json) { state = 'registered'; via = 'rdap'; break; }
      if (r.code === 'http404') { state = 'available'; via = 'rdap'; break; }
      if (!['network', 'timeout', 'http5xx'].includes(r.code)) break;
    }
  } catch {}
  if (state === 'unknown') {
    const o = { errors: {} }; await getWhois(domain, o); const wt = o.whois?.text;
    if (wt) { state = NOT_FOUND.test(wt) && wt.length < 4000 ? 'available' : /domain name:/i.test(wt) ? 'registered' : 'unknown'; if (state !== 'unknown') via = 'whois'; }
  }
  const val = { domain, state, via };
  if (state !== 'unknown') { chk.set(domain, { val, exp: Date.now() + 60000 }); if (chk.size > 2000) chk.clear(); }
  return val;
}
const TLD_OK = /^(?:[a-z]{2,24}|xn--[a-z0-9-]{1,40})(?:\.[a-z]{2,24})?$/;
function checkList(q) {
  const one = q.get('domain');
  if (one) { const n = normalizeDomain(one); return n.error ? null : [n.domain]; }
  const name = (q.get('name') || '').trim().toLowerCase(), tlds = (q.get('tlds') || '').toLowerCase().split(',').map(x => x.trim().replace(/^\./, '')).filter(Boolean);
  if (!name || !tlds.length || tlds.length > 12 || !tlds.every(t => TLD_OK.test(t))) return null;
  const out = tlds.map(t => normalizeDomain(name + '.' + t));
  return out.some(o => o.error) ? null : [...new Set(out.map(o => o.domain))];
}

export default {
  async fetch(req, env, ctx) {
    const o = pickOrigin(req, env);
    if (req.url.length > 2048) return send({ error: 'invalid' }, 414, o);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: hdr(o) });
    const u = new URL(req.url);
    const ip = req.headers.get('cf-connecting-ip') || 'x';
    // Preferred: Cloudflare Rate Limiting binding (global, see wrangler.toml). Fallback: small per-isolate limiter.
    const over = async () => env.RATE_LIMITER ? !(await env.RATE_LIMITER.limit({ key: ip })).success : limited(ip);
    if (u.pathname === '/api/check' && req.method === 'GET') {
      const list = checkList(u.searchParams); if (!list) return send({ error: 'invalid' }, 400, o);
      if (await over()) return send({ error: 'http429' }, 429, o);
      return send({ results: await Promise.all(list.map(checkOne)) }, 200, o);
    }
    if (u.pathname === '/api/health') return send({ ok: true, service: 'DomainLookup' }, 200, o);
    if (u.pathname !== '/api/lookup' || req.method !== 'GET') return send({ error: 'notfound' }, 404, o);
    if (await over()) return send({ error: 'http429' }, 429, o);
    const n = normalizeDomain(u.searchParams.get('domain'));
    if (n.error) return send({ error: 'invalid' }, 400, o);
    const key = new Request('https://cache.local/lookup/' + n.domain), cache = caches.default;
    const hit = await cache.match(key); if (hit) return new Response(hit.body, { headers: hdr(o) });

    const out = { domain: n.domain, rdap: null, registrarRdap: null, whois: null, errors: {}, available: null };
    await Promise.all([getRdap(n.domain, out), getWhois(n.domain, out)]);
    const wt = out.whois?.text;
    if (out.rdap) out.available = false;
    else if (wt) out.available = NOT_FOUND.test(wt) && wt.length < 4000 ? true : /domain name:/i.test(wt) ? false : null;
    else if (out.errors.rdap === 'http404') out.available = true;

    if (!out.rdap && !wt && out.available !== true) return send(out, 502, o);
    const res = send(out, 200, o); ctx.waitUntil(cache.put(key, res.clone())); return res;
  },
};
