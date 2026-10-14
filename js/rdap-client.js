export class RdapError extends Error {
  constructor(code, status) {
    super(code);
    this.name = 'RdapError';
    this.code = code;
    this.status = status;
  }
}

async function request(url, outer, timeout) {
  const ctrl = new AbortController();
  let timedOut = false;
  const t = setTimeout(() => { timedOut = true; ctrl.abort(); }, timeout);
  const onAbort = () => ctrl.abort();
  outer?.addEventListener('abort', onAbort);
  try {
    let res;
    try {
      res = await fetch(url, { signal: ctrl.signal, redirect: 'follow', headers: { Accept: 'application/rdap+json, application/json' } });
    } catch (e) {
      if (outer?.aborted) throw new RdapError('aborted');
      throw new RdapError(timedOut ? 'timeout' : 'network');
    }
    if (res.status === 404) throw new RdapError('http404', 404);
    if (res.status === 429) throw new RdapError('http429', 429);
    if (res.status >= 500) throw new RdapError('http5xx', res.status);
    if (!res.ok) throw new RdapError('httpOther', res.status);
    let text;
    try { text = await res.text(); } catch { throw new RdapError(timedOut ? 'timeout' : 'network'); }
    if (!text.trim()) throw new RdapError('json');
    try { const j = JSON.parse(text); if (!j || typeof j !== 'object' || Array.isArray(j)) throw 0; return j; }
    catch { throw new RdapError('json'); }
  } finally { clearTimeout(t); outer?.removeEventListener('abort', onAbort); }
}

/** Tries advertised base URLs in order; only falls back on network/timeout/5xx (max 2 hosts). */
export async function lookupDomain(domain, bases, signal, timeout = 12000) {
  let last;
  for (const base of bases.slice(0, 2)) {
    const url = base.replace(/\/?$/, '/') + 'domain/' + encodeURIComponent(domain);
    try { const json = await request(url, signal, timeout); return { json, url }; }
    catch (e) {
      last = e;
      if (!['network', 'timeout', 'http5xx'].includes(e.code)) throw e;
    }
  }
  throw last;
}