const A = x => (Array.isArray(x) ? x : []);
const S = x => (x == null || x === '' ? null : String(x));

export function safeUrl(u) {
  try { const x = new URL(String(u)); return /^https?:$/.test(x.protocol) ? x.href : null; } catch { return null; }
}

function vcard(e) {
  const o = {};
  for (const p of A(e.vcardArray?.[1])) { if (Array.isArray(p) && p[0]) (o[p[0]] ??= []).push(p[3]); }
  const adr = o.adr?.[0];
  return {
    name: S(o.fn?.[0]), org: S([].concat(o.org?.[0] ?? []).join(', ')),
    email: S(o.email?.[0]), tel: S(String(o.tel?.[0] ?? '').replace(/^tel:/, '')),
    url: S(o.url?.[0]),
    address: S(Array.isArray(adr) ? adr.flat().filter(Boolean).join(', ') : adr),
  };
}

function walk(list, out) { for (const e of A(list)) { if (e && typeof e === 'object') { out.push(e); walk(e.entities, out); } } }

export function parseDomain(j) {
  if (!j || typeof j !== 'object') throw new Error('invalid');
  const events = A(j.events).filter(e => e?.eventAction && e.eventDate)
    .map(e => ({ action: String(e.eventAction), date: String(e.eventDate) }));
  const find = (...names) => events.find(e => names.includes(e.action.toLowerCase()))?.date ?? null;
  const ents = []; walk(j.entities, ents);
  const has = (e, r) => A(e.roles).map(x => String(x).toLowerCase()).includes(r);

  const regE = ents.find(e => has(e, 'registrar'));
  let registrar = null;
  if (regE) {
    const v = vcard(regE);
    const ianaId = S(A(regE.publicIds).find(p => /iana/i.test(p?.type ?? ''))?.identifier);
    const link = A(regE.links).find(l => ['about', 'related'].includes(l?.rel) && safeUrl(l.href));
    registrar = { name: v.name || v.org, ianaId, url: safeUrl(v.url) || safeUrl(link?.href), email: v.email, tel: v.tel, handle: S(regE.handle) };
  }

  const contacts = ents.filter(e => e !== regE).map(e => {
    const v = vcard(e);
    const redacted = A(e.remarks).some(r => /redact|privacy/i.test(`${r?.title} ${A(r?.description).join(' ')}`)) ||
      A(e.vcardArray?.[1]).some(p => /redact/i.test(String(p?.[3] ?? '')));
    return { roles: A(e.roles).map(String), handle: S(e.handle), ...v, redacted, empty: !(v.name || v.org || v.email || v.tel || v.address) };
  });

  const nameservers = A(j.nameservers).map(n => ({
    name: (S(n?.ldhName) || S(n?.unicodeName) || '').toLowerCase() || null,
    ips: [...A(n?.ipAddresses?.v4), ...A(n?.ipAddresses?.v6)].map(String),
  })).filter(n => n.name);

  const sd = j.secureDNS;
  const dnssec = sd && typeof sd.delegationSigned === 'boolean' ? (sd.delegationSigned ? 'Signed' : 'Unsigned') : null;

  return {
    name: (S(j.ldhName) || S(j.unicodeName) || '').toLowerCase() || null, unicodeName: S(j.unicodeName), ldhName: S(j.ldhName),
    objectClass: S(j.objectClassName), handle: S(j.handle),
    registered: find('registration'), expires: find('expiration'), changed: find('last changed'),
    events, registrar, nameservers, status: A(j.status).map(String), dnssec, contacts,
  };
}
