/** Parses raw port-43 WHOIS text (any registry) into common fields and contact blocks. */
export function parseWhois(text) {
  const kv = [];
  for (const line of String(text).split(/\r?\n/)) {
    // Allow optional whitespace before the colon: "Key : Value" and "Key: Value"
    const m = line.match(/^\s*([A-Za-z][\w \/.\-]{1,40}?)\s*:\s*(.*)$/);
    if (m && m[2].trim()) kv.push([m[1].trim().toLowerCase(), m[2].trim()]);
  }
  const all = (...k) => kv.filter(([a]) => k.includes(a)).map(x => x[1]);
  const first = (...k) => all(...k)[0] ?? null;
  const uniq = a => [...new Set(a)];
  const contact = p => {
    const g = (...s) => first(...s.map(x => `${p} ${x}`));
    const c = {
      name: g('name'),
      org: g('organization', 'organisation'),
      street: all(`${p} street`).join(', ') || null,
      city: g('city'),
      state: g('state/province', 'state'),
      postal: g('postal code'),
      country: g('country'),
      phone: g('phone'),
      email: g('email'),
    };
    return Object.values(c).some(Boolean) ? c : null;
  };
  const dn = first('dnssec');
  return {
    registered: first('creation date', 'created', 'created on', 'registered on', 'registration time', 'domain registration date'),
    expires: first('registry expiry date', 'registrar registration expiration date', 'expiration date', 'expires on', 'expiry date', 'paid-till', 'renewal date'),
    changed: first('updated date', 'last updated', 'last modified', 'last update', 'modified'),
    handle: first('registry domain id'),
    registrar: first('registrar', 'sponsoring registrar'),
    ianaId: first('registrar iana id'),
    registrarUrl: first('registrar url'),
    status: uniq(all('domain status', 'status', 'state').map(s => s.split(/\s+/)[0])),
    ns: uniq(all('name server', 'nserver', 'nameserver', 'name servers').map(s => s.split(/\s+/)[0].toLowerCase())),
    dnssec: dn ? (/unsigned|inactive/i.test(dn) ? 'Unsigned' : /signed|active/i.test(dn) ? 'Signed' : null) : null,
    contacts: {
      registrant: contact('registrant'),
      admin: contact('admin') || contact('administrative'),
      tech: contact('tech') || contact('technical'),
      billing: contact('billing'),
    },
  };
}