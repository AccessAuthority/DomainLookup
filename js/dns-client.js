// DNS records fetched directly from public DNS-over-HTTPS resolvers.
// No backend required — works on static hosting just like the RDAP fallback.
const DOH_ENDPOINTS = [
  { url: 'https://cloudflare-dns.com/dns-query', name: 'Cloudflare' },
  { url: 'https://dns.google/resolve',           name: 'Google' },
];
const TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA'];

const TYPE_MAP = { 1: 'A', 28: 'AAAA', 15: 'MX', 2: 'NS', 16: 'TXT', 5: 'CNAME', 6: 'SOA', 257: 'CAA' };

async function queryOne(endpoint, domain, type, signal) {
  const u = new URL(endpoint.url);
  u.searchParams.set('name', domain);
  u.searchParams.set('type', type);

  // Per-query timeout (8s) — combined with the outer signal
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  const onAbort = () => ctrl.abort();
  signal?.addEventListener('abort', onAbort);

  try {
    const r = await fetch(u, {
      signal: ctrl.signal,
      headers: { Accept: 'application/dns-json' },
    });
    if (!r.ok) throw new Error('http ' + r.status);
    const j = await r.json();
    return Array.isArray(j.Answer) ? j.Answer : [];
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', onAbort);
  }
}

function normalize(answers, type) {
  const out = [];
  for (const a of answers) {
    if (!a || a.type == null || a.data == null) continue;
    // Handle both number (standard DoH JSON) and string type values
    const t = typeof a.type === 'string' ? a.type.toUpperCase() : TYPE_MAP[a.type];
    if (!t || t !== type) continue;
    out.push({
      type: t,
      zone: '@',
      value: String(a.data).trim(),
      ttl: a.TTL ? Number(a.TTL) : null,
    });
  }
  return out;
}

/**
 * Fetch DNS records for a domain from public DoH resolvers.
 * Tries each endpoint in order; only returns when records are found.
 * Returns { records, unavailable } — never throws for expected failures.
 */
export async function fetchDns(domain, signal) {
  const records = [];
  let anySuccess = false;

  for (const ep of DOH_ENDPOINTS) {
    try {
      const results = await Promise.all(
        TYPES.map(t => queryOne(ep, domain, t, signal).catch(err => {
          if (signal?.aborted) throw err;
          console.warn(`DoH ${ep.name} ${t} failed:`, err.message || err);
          return [];
        }))
      );

      // If the outer signal aborted during this batch, stop.
      if (signal?.aborted) throw { code: 'aborted' };

      const flat = results.flatMap((ans, i) => normalize(ans, TYPES[i]));

      if (flat.length) {
        anySuccess = true;
        records.push(...flat);
        break; // got records from this resolver — stop
      }

      // Resolver responded but produced no matching records.
      // Some registries only return CNAME/SOA; only treat as success
      // if at least one query returned a non-empty Answer.
      if (results.some(r => r.length > 0)) {
        anySuccess = true;
        break;
      }

      // Otherwise try the next endpoint (likely CORS or transient failure).
    } catch (e) {
      if (signal?.aborted) throw e;
      console.warn(`DoH endpoint ${ep.name} failed:`, e.message || e);
      // continue to next endpoint
    }
  }

  // Deduplicate by type+value
  const seen = new Set();
  const unique = records.filter(r => {
    const k = r.type + '|' + r.value;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  return { records: unique, unavailable: !anySuccess };
}

/**
 * Single DoH query against any name/type (used by the security checks and subdomain scan).
 * Returns { answers, ok } where ok=false means no resolver could be reached.
 */
export async function dohQuery(name, type, signal) {
  for (const ep of DOH_ENDPOINTS) {
    try { return { answers: await queryOne(ep, name, type, signal), ok: true }; }
    catch (e) { if (signal?.aborted) throw e; }
  }
  return { answers: [], ok: false };
}
