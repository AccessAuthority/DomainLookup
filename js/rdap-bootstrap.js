const URL_DNS = 'https://data.iana.org/rdap/dns.json';
let cache = null;

export async function loadBootstrap(force = false) {
  if (cache && !force) return cache;
  cache = (async () => {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 12000);
    try {
      const res = await fetch(URL_DNS, { signal: ctrl.signal, headers: { Accept: 'application/json' } });
      if (!res.ok) throw new Error('http ' + res.status);
      const j = await res.json();
      if (!j || !Array.isArray(j.services)) throw new Error('bad structure');
      const map = new Map();
      for (const s of j.services) {
        if (!Array.isArray(s) || !Array.isArray(s[0]) || !Array.isArray(s[1])) continue;
        const urls = s[1].filter(u => typeof u === 'string' && /^https?:\/\//i.test(u))
          .sort((a, b) => (b.startsWith('https') ? 1 : 0) - (a.startsWith('https') ? 1 : 0));
        if (urls.length) for (const e of s[0]) map.set(String(e).toLowerCase(), urls);
      }
      if (!map.size) throw new Error('empty');
      return { map };
    } finally { clearTimeout(t); }
  })();
  cache.catch(() => { cache = null; });
  return cache;
}

export function findServices(domain, bootstrap) {
  const labels = domain.split('.');
  for (let i = 0; i < labels.length; i++) {
    const suffix = labels.slice(i).join('.');
    if (bootstrap.map.has(suffix)) return { suffix, urls: bootstrap.map.get(suffix) };
  }
  return null;
}