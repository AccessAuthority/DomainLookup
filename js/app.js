import { normalizeDomain } from './domain-validator.js';
import { loadBootstrap, findServices } from './rdap-bootstrap.js';
import { lookupDomain } from './rdap-client.js';
import { buildModel } from './model.js';
import { API_BASE } from './config.js';
import { $, showLoading, showError, showResult, showAvailable, toast, altCard, securityPanel, subdomainCard } from './ui.js';
import { runSecurity, scanSubdomains } from './security.js';
import { checkMany, splitDomain, TLDS } from './availability.js';
import { fetchDns } from './dns-client.js';

const MSG = {
  empty: 'Please enter a domain name to continue.',
  invalid: 'The domain name appears to be invalid. Please check the format and try again.',
  noservice: 'An RDAP service could not be identified for this domain extension.',
  bootstrap: 'Unable to load domain service information. Please try again.',
  network: 'The registry may not permit direct browser access, or the service may be temporarily unavailable.',
  http404: 'The RDAP service did not return a matching domain record.',
  http429: 'The registry is temporarily limiting requests. Please wait before trying again.',
  http5xx: 'The registry service is currently experiencing an issue. Please try again later.',
  timeout: 'The lookup took too long. Please try again.',
  json: 'The registry returned a response that could not be processed.',
  httpOther: 'The registry returned an unexpected response. Please try again.',
};
const input = $('#q'), go = $('#go'), clearBtn = $('#clear');
let runId = 0, ctrl = null, busy = false;
const setBusy = b => { busy = b; go.disabled = b; go.textContent = b ? 'Searching…' : 'Search Domain'; };

let apiDown = location.protocol === 'file:';
async function viaApi(domain, signal) {
  const c = new AbortController(); let to = false;
  const t = setTimeout(() => { to = true; c.abort(); }, 25000), onAbort = () => c.abort();
  signal.addEventListener('abort', onAbort);
  try {
    let r;
    try { r = await fetch(`${(API_BASE || '').replace(/\/$/, '')}/api/lookup?domain=${encodeURIComponent(domain)}`, { signal: c.signal }); }
    catch { throw { code: signal.aborted ? 'aborted' : to ? 'timeout' : 'network', api: !signal.aborted }; }
    if (r.status === 404 || r.status === 405) { apiDown = true; throw { code: 'network', api: true }; }
    if (r.status === 429) throw { code: 'http429' };
    if (r.status === 400) throw { code: 'invalid' };
    let j; try { j = await r.json(); } catch { apiDown = true; throw { code: 'json', api: true }; }
    if (!r.ok && !j.rdap && !j.whois) {
      const code = j.errors && (j.errors.rdap || j.errors.whois);
      if (!code) throw { code: 'http5xx', api: true };
      throw { code, api: ['network', 'timeout', 'http5xx'].includes(code) };
    }
    return j;
  } finally { clearTimeout(t); signal.removeEventListener('abort', onAbort); }
}
async function viaDirect(domain, signal) {
  let bs; try { bs = await loadBootstrap(); } catch { throw { code: 'bootstrap' }; }
  const svc = findServices(domain, bs); if (!svc) throw { code: 'noservice' };
  try { const r = await lookupDomain(domain, svc.urls, signal); return { domain, rdap: { url: r.url, json: r.json } }; }
  catch (e) { if (e.code === 'http404') return { domain, rdap: null, available: true }; throw e; }
}
async function fetchData(domain, signal) {
  if (!apiDown) { try { return await viaApi(domain, signal); } catch (e) { if (!e.api) throw e; } }
  return viaDirect(domain, signal);
}

function showAlternatives(m, domain, id) {
  const { name, tld } = splitDomain(domain);
  const current = { domain, state: m.available ? 'available' : 'registered' };
  const alt = altCard(name, current, d => { input.value = d; run(d); window.scrollTo({ top: 0, behavior: 'smooth' }); });
  $('#result').append(alt.node);
  checkMany(name, TLDS.filter(t => t !== tld), ctrl.signal)
    .then(items => { if (id === runId) alt.set(items); })
    .catch(e => { if (id === runId && !ctrl.signal.aborted) alt.fail(e.code === 'http429' ? 'Too many checks right now. Wait a minute and try again.' : 'Could not check other extensions right now.'); });
}

function showSecurity(m, domain, id) {
  const slot = $('#sec-slot'), sslot = $('#sub-slot');
  if (!slot) return;
  const sp = securityPanel(), sub = subdomainCard();
  slot.replaceWith(sp.node); sslot?.replaceWith(sub.node);
  const sig = ctrl.signal, live = () => id === runId && !sig.aborted;
  runSecurity(domain, m, sig).then(r => { if (live()) sp.set(r); }).catch(() => { if (live()) sp.fail('Security checks could not be completed. Public DNS resolvers may be unreachable.'); });
  scanSubdomains(domain, sig).then(r => { if (live()) sub.set(r); }).catch(() => { if (live()) sub.fail('Subdomain scan could not be completed.'); });
}

async function run(raw) {
  const n = normalizeDomain(raw);
  if (n.error) { showError(MSG[n.error]); input.focus(); return; }
  const id = ++runId; ctrl?.abort(); ctrl = new AbortController();
  let domain = n.domain; const retry = () => run(domain), ctx = { domain };
  input.value = domain; clearBtn.hidden = false; setBusy(true); showLoading(domain);
  const again = () => { $('#result').replaceChildren(); input.value = ''; clearBtn.hidden = true; input.focus(); window.scrollTo({ top: 0 }); };
  try {
    const resp = await fetchData(domain, ctrl.signal);
    if (id !== runId) return;
    // Server maps a subdomain to its registered domain (blog.example.com -> example.com): show that record.
    if (resp.domain && resp.domain !== domain) {
      const typed = domain; domain = resp.domain; ctx.domain = domain; input.value = domain;
      toast(typed + ' is a subdomain — showing ' + domain);
    }

    /* ---------- DNS records — frontend se, backend untouched ---------- */
    try {
      const dns = await fetchDns(domain, ctrl.signal);
      resp.dns = dns.records;
      resp.dnsUnavailable = dns.unavailable;
    } catch (e) {
      if (e.code === 'aborted' || ctrl.signal.aborted) return;
      console.warn('DNS fetch failed:', e.message || e);
      resp.dns = [];
      resp.dnsUnavailable = true;
    }

    let m; try { m = buildModel(resp); } catch { throw { code: 'json' }; }
    m.available ? showAvailable(m, ctx, again) : showResult(m, ctx, again);
    showAlternatives(m, domain, id);
    if (!m.available) showSecurity(m, domain, id);
    try { history.replaceState(null, '', '?d=' + encodeURIComponent(domain)); } catch {}
    $('#result').scrollIntoView({ behavior: 'smooth', block: 'start' });
    toast('Lookup successful');
  } catch (e) {
    if (id !== runId || e.code === 'aborted') return;
    console.error('Lookup failed:', e);
    e.code === 'http404'
      ? showError(MSG.http404, retry, 'No record returned', 'This can happen when a domain is unregistered, but the registry did not confirm it. Check with a registrar.')
      : showError(MSG[e.code] || MSG.network, e.code === 'noservice' ? null : retry);
    toast('Lookup failed', 'err');
  } finally { if (id === runId) setBusy(false); }
}

$('#form').addEventListener('submit', e => { e.preventDefault(); run(input.value); });
input.addEventListener('input', () => { clearBtn.hidden = !input.value; });
clearBtn.addEventListener('click', () => { input.value = ''; clearBtn.hidden = true; $('#result').replaceChildren(); input.focus(); });
document.querySelectorAll('[data-d]').forEach(b => b.addEventListener('click', () => { input.value = b.dataset.d; run(b.dataset.d); }));
const deep = new URLSearchParams(location.search).get('d');
if (deep) { input.value = deep; run(deep); }