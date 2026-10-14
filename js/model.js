import { parseDomain, safeUrl } from './rdap-parser.js';
import { parseWhois } from './whois-parser.js';

const blank = n => ({ name: n, unicodeName: null, ldhName: n, objectClass: null, handle: null, registered: null, expires: null, changed: null,
  events: [], registrar: null, nameservers: [], status: [], dnssec: null, contacts: [] });

function merge(a, b) {
  const o = { ...a };
  for (const k of ['name', 'unicodeName', 'ldhName', 'objectClass', 'handle', 'registered', 'expires', 'changed', 'dnssec']) o[k] = a[k] ?? b[k];
  o.registrar = a.registrar && b.registrar ? Object.fromEntries(Object.keys(a.registrar).map(k => [k, a.registrar[k] ?? b.registrar[k]])) : a.registrar || b.registrar;
  for (const k of ['events', 'nameservers', 'status']) o[k] = a[k].length >= b[k].length ? a[k] : b[k];
  o.contacts = [...a.contacts, ...b.contacts];
  return o;
}
function fill(d, w) {
  const o = { ...d };
  for (const k of ['registered', 'expires', 'changed', 'handle', 'dnssec']) o[k] ??= w[k];
  if (w.registrar) {
    const url = w.registrarUrl ? safeUrl(/^https?:/i.test(w.registrarUrl) ? w.registrarUrl : 'https://' + w.registrarUrl) : null;
    o.registrar = o.registrar ? { ...o.registrar, name: o.registrar.name ?? w.registrar, ianaId: o.registrar.ianaId ?? w.ianaId, url: o.registrar.url ?? url }
      : { name: w.registrar, ianaId: w.ianaId, url, email: null, tel: null, handle: null };
  }
  if (!o.status.length) o.status = w.status;
  if (!o.nameservers.length) o.nameservers = w.ns.map(name => ({ name, ips: [] }));
  if (!o.events.length) o.events = [['registration', w.registered], ['expiration', w.expires], ['last changed', w.changed]].filter(e => e[1]).map(([action, date]) => ({ action, date }));
  return o;
}
const cap = s => s.replace(/(^|\s)\S/g, m => m.toUpperCase());
function rdapAsWhois(d) {
  const L = [], add = (k, v) => { if (v) L.push(`${k}: ${v}`); };
  add('Domain Name', d.name); add('Registry Domain ID', d.handle); add('Registrar', d.registrar?.name); add('Registrar IANA ID', d.registrar?.ianaId);
  add('Registrar URL', d.registrar?.url); add('Registrar Contact Email', d.registrar?.email); add('Registrar Contact Phone', d.registrar?.tel);
  d.events.forEach(e => add(cap(e.action) + ' Date', e.date)); d.status.forEach(x => add('Domain Status', x));
  d.nameservers.forEach(n => add('Name Server', n.name)); add('DNSSEC', d.dnssec);
  return L.join('\n') + '\n\n>>> Formatted from RDAP data by DomainLookup <<<';
}

/** resp: { domain, rdap?, registrarRdap?, whois?, dns?, available? } from the API or direct RDAP. */
export function buildModel(resp) {
  let d = resp.rdap?.json ? parseDomain(resp.rdap.json) : blank(resp.domain);
  if (resp.registrarRdap?.json) d = merge(d, parseDomain(resp.registrarRdap.json));
  const reg = resp.whois, ref = reg?.referral, tabs = [], sources = [];
  if (ref?.text) tabs.push({ label: 'Registrar WHOIS', text: ref.text.trim() }), sources.push('WHOIS ' + ref.server);
  if (reg?.text) tabs.push({ label: 'Registry WHOIS', text: reg.text.trim() }), sources.push('WHOIS ' + reg.server);
  const ws = [ref?.text, reg?.text].filter(Boolean).map(parseWhois);
  for (const w of ws) d = fill(d, w);
  const pick = k => ws.map(w => w.contacts[k]).find(Boolean) || null;
  const cards = [['Registrant Contact', pick('registrant')], ['Administrative Contact', pick('admin')], ['Technical Contact', pick('tech')], ['Billing Contact', pick('billing')]].filter(c => c[1]);
  if (!tabs.length && resp.rdap) tabs.push({ label: 'Raw Whois Data (from RDAP)', text: rdapAsWhois(d) });
  if (resp.rdap?.json) tabs.push({ label: 'RDAP JSON', text: JSON.stringify(resp.rdap.json, null, 2) }), sources.unshift('RDAP ' + resp.rdap.url);
  if (resp.registrarRdap?.json) tabs.push({ label: 'Registrar RDAP JSON', text: JSON.stringify(resp.registrarRdap.json, null, 2) });

  // DNS records — frontend se aate hain (resp.dns), warna empty
  // Zone data is attacker-controlled (anyone can publish any TXT): bound count and length so a hostile domain cannot freeze the page.
  const dns = Array.isArray(resp.dns) ? resp.dns.slice(0, 300).map(r => ({
    type: String(r.type || '').toUpperCase().slice(0, 10),
    zone: r.zone || '@',
    value: String(r.value || r.data || '').slice(0, 4096),
    ttl: Number.isFinite(Number(r.ttl)) ? Number(r.ttl) : null,
  })).filter(r => r.type && r.value) : [];
  const dnsUnavailable = resp.dnsUnavailable === true;

  // people: contact jismein kuch bhi data ho (naam/org/email/tel/address) YA kam se kam role ho
  const people = d.contacts.filter(c => {
    const hasData = c.name || c.org || c.email || c.tel || c.address;
    const hasRole = c.roles && c.roles.length > 0;
    return hasData || hasRole;
  });

  return { d, cards, people, tabs, sources, dns, dnsUnavailable, available: resp.available === true && !resp.rdap };
}