import { API_BASE } from './config.js';
import { loadBootstrap, findServices } from './rdap-bootstrap.js';
import { lookupDomain } from './rdap-client.js';

export const TLDS = ['com', 'net', 'org', 'in', 'co', 'io', 'info', 'co.in'];
const SLD = new Set(['co.uk', 'org.uk', 'me.uk', 'ac.uk', 'gov.uk', 'co.in', 'net.in', 'org.in', 'firm.in', 'gen.in', 'ind.in', 'ac.in', 'edu.in', 'gov.in', 'res.in',
  'com.au', 'net.au', 'org.au', 'co.nz', 'co.za', 'com.br', 'com.sg', 'com.my', 'co.jp', 'or.jp', 'ne.jp', 'com.cn', 'com.hk', 'com.mx', 'com.tr', 'com.pk', 'com.bd', 'co.id', 'co.kr']);

export function splitDomain(domain) {
  const l = domain.split('.');
  if (l.length >= 3 && SLD.has(l.slice(-2).join('.'))) return { name: l.at(-3), tld: l.slice(-2).join('.') };
  return { name: l.at(-2), tld: l.at(-1) };
}

let apiDown = location.protocol === 'file:';
async function viaApi(name, tlds, signal) {
  const base = (API_BASE || '').replace(/\/$/, '');
  const r = await fetch(`${base}/api/check?name=${encodeURIComponent(name)}&tlds=${encodeURIComponent(tlds.join(','))}`, { signal });
  if (r.status === 429) throw { code: 'http429' };
  if (r.status === 404 || r.status === 405) { apiDown = true; return null; }
  if (!r.ok) return null;
  let j; try { j = await r.json(); } catch { apiDown = true; return null; }
  return Array.isArray(j.results) ? j.results : null;
}
async function viaDirect(name, tlds, signal) {
  const bs = await loadBootstrap();
  return Promise.all(tlds.map(async t => {
    const domain = `${name}.${t}`, svc = findServices(domain, bs);
    if (!svc) return { domain, state: 'unknown' };
    try { await lookupDomain(domain, svc.urls, signal, 8000); return { domain, state: 'registered', via: 'rdap' }; }
    catch (e) { return { domain, state: e.code === 'http404' ? 'available' : 'unknown', via: 'rdap' }; }
  }));
}
export async function checkMany(name, tlds, signal) {
  if (!apiDown) {
    try { const r = await viaApi(name, tlds, signal); if (r) return r; }
    catch (e) {
      if (signal?.aborted || e.code === 'http429') throw e;
      console.warn('API check failed, falling back to direct RDAP:', e.message || e);
    }
  }
  return viaDirect(name, tlds, signal);
}