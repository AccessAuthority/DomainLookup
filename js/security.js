// Domain security checks (email authentication, DNSSEC, CAA, registrar locks, expiry) + common-subdomain scan.
// Everything is read from public DNS-over-HTTPS and the data already fetched; nothing is sent to our own server.
import { dohQuery } from './dns-client.js';

const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 's1', 's2', 'mail', 'dkim', 'smtp'];
const SUBS = ['www', 'mail', 'webmail', 'ftp', 'blog', 'api', 'cpanel', 'dev', 'staging'];
const clean = v => String(v || '').slice(0, 4096).replace(/"\s+"/g, '').replace(/^"|"$/g, '').trim(); // hostile zones can publish huge TXT: clamp first
const txtOf = a => a.filter(x => Number(x.type) === 16 || String(x.type).toUpperCase() === 'TXT').map(x => clean(x.data));

const W = { spf: 15, dmarc: 20, dkim: 8, mtasts: 4, tlsrpt: 3, mx: 3, dnssec: 12, caa: 8, ns: 6, lock: 14, del: 4, exp: 8 };
const mk = (id, group, title, status, detail, o = {}) => ({ id, group, title, status, detail, value: o.value || null, fix: o.fix || null, weight: W[id] || 0 });

function checkSpf(dns) {
  const recs = dns.filter(r => r.type === 'TXT').map(r => clean(r.value)).filter(v => /^v=spf1(\s|$)/i.test(v));
  if (!recs.length) return mk('spf', 'Email security', 'SPF (sender policy)', 'fail', 'No SPF record found. Anyone can forge mail that appears to come from this domain.', { fix: 'Add a TXT record such as "v=spf1 include:your-mail-provider -all".' });
  if (recs.length > 1) return mk('spf', 'Email security', 'SPF (sender policy)', 'fail', 'More than one SPF record exists. Receivers treat this as a permanent error.', { value: recs[0], fix: 'Merge everything into a single v=spf1 record.' });
  const v = recs[0], all = /(?:^|\s)([+\-~?])?all\b/i.exec(v), q = all ? (all[1] || '+') : null;
  const lookups = (v.match(/(?:^|\s)[+\-~?]?(include:|a\b|mx\b|ptr\b|exists:|redirect=)/gi) || []).length;
  if (q === '+') return mk('spf', 'Email security', 'SPF (sender policy)', 'fail', '"+all" lets any server send as this domain, which makes SPF useless.', { value: v, fix: 'Change the ending to "-all" (or "~all" while testing).' });
  if (!q) return mk('spf', 'Email security', 'SPF (sender policy)', 'warn', 'The record has no "all" ending, so unlisted senders are not rejected.', { value: v, fix: 'End the record with "-all" or "~all".' });
  if (q === '?') return mk('spf', 'Email security', 'SPF (sender policy)', 'warn', '"?all" is neutral and gives no protection.', { value: v, fix: 'Use "~all" or "-all".' });
  if (lookups > 10) return mk('spf', 'Email security', 'SPF (sender policy)', 'warn', `About ${lookups} DNS lookups; the SPF limit is 10, so checks may fail.`, { value: v, fix: 'Remove unused include: entries or flatten the record.' });
  return mk('spf', 'Email security', 'SPF (sender policy)', 'pass', q === '-' ? 'Strict policy: unlisted servers are rejected (-all).' : 'Soft-fail policy (~all). Unlisted servers are flagged; -all is stricter.', { value: v });
}

function tags(v) { const o = Object.create(null); v.split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim().toLowerCase()] = p.slice(i + 1).trim(); }); return o; }

function checkDmarc(txts) {
  const v = txts.find(t => /^v=DMARC1/i.test(t));
  const G = 'Email security', T = 'DMARC (policy & reports)';
  if (!v) return mk('dmarc', G, T, 'fail', 'No DMARC record. Receivers have no instruction for mail that fails SPF/DKIM.', { fix: 'Publish a TXT record at _dmarc with e.g. "v=DMARC1; p=none; rua=mailto:you@domain" and tighten later.' });
  const t = tags(v), p = (t.p || '').toLowerCase(), pct = t.pct ? Number(t.pct) : 100;
  if (p === 'reject' || p === 'quarantine') {
    if (pct < 100) return mk('dmarc', G, T, 'warn', `Policy is ${p} but only applies to ${pct}% of mail.`, { value: v, fix: 'Raise pct to 100 once reports look clean.' });
    return mk('dmarc', G, T, 'pass', `Enforced policy: p=${p}.${t.rua ? ' Aggregate reports enabled.' : ' Add rua= to receive reports.'}`, { value: v });
  }
  return mk('dmarc', G, T, 'warn', 'Monitoring only (p=none). Spoofed mail is reported but not blocked.', { value: v, fix: 'Move to p=quarantine, then p=reject, after reviewing reports.' });
}

function checkDkim(found) {
  const G = 'Email security', T = 'DKIM (message signing)';
  if (!found.length) return mk('dkim', G, T, 'warn', 'No DKIM key found on common selectors. Your provider may use a custom selector, so this is not conclusive.', { fix: 'Enable DKIM in your mail provider and publish the TXT key it gives you.' });
  const weak = found.find(f => f.bits && f.bits < 2000 && f.bits > 0), revoked = found.every(f => f.revoked);
  const names = found.map(f => f.selector).join(', ');
  if (revoked) return mk('dkim', G, T, 'warn', 'DKIM selectors exist but their keys are revoked (empty p=).', { value: names, fix: 'Publish an active key.' });
  if (weak) return mk('dkim', G, T, 'warn', `Selector "${weak.selector}" uses about a ${weak.bits}-bit key. 2048-bit is recommended.`, { value: names, fix: 'Rotate to a 2048-bit RSA key.' });
  return mk('dkim', G, T, 'pass', `Signing key published (selector${found.length > 1 ? 's' : ''}: ${names}).`, { value: names });
}

const rsaBits = p => { try { const n = atob(p.replace(/\s/g, '')).length; return n < 100 ? 0 : n < 200 ? 1024 : n < 400 ? 2048 : 4096; } catch { return 0; } };

export async function runSecurity(domain, m, signal) {
  const dns = m.dns || [], d = m.d, G2 = 'DNS security', G3 = 'Domain protection';
  const ask = (n, t) => dohQuery(n, t, signal).catch(e => { if (signal?.aborted) throw e; return { answers: [], ok: false }; });
  const [dmarc, mta, tls, ds, ...dk] = await Promise.all([
    ask('_dmarc.' + domain, 'TXT'), ask('_mta-sts.' + domain, 'TXT'), ask('_smtp._tls.' + domain, 'TXT'), ask(domain, 'DS'),
    ...DKIM_SELECTORS.map(s => ask(`${s}._domainkey.${domain}`, 'TXT')),
  ]);
  const checks = [checkSpf(dns), checkDmarc(txtOf(dmarc.answers))];

  const found = [];
  dk.forEach((r, i) => txtOf(r.answers).forEach(t => {
    if (!/v=DKIM1|p=/i.test(t)) return;
    const p = (tags(t).p || ''); found.push({ selector: DKIM_SELECTORS[i], revoked: !p, bits: p ? rsaBits(p) : 0 });
  }));
  checks.push(checkDkim(found));

  const sts = txtOf(mta.answers).find(t => /^v=STSv1/i.test(t)), rpt = txtOf(tls.answers).find(t => /^v=TLSRPTv1/i.test(t));
  checks.push(sts ? mk('mtasts', 'Email security', 'MTA-STS (TLS for mail)', 'pass', 'Receivers are told to require encrypted delivery.', { value: sts })
    : mk('mtasts', 'Email security', 'MTA-STS (TLS for mail)', 'warn', 'Not configured (optional). Mail between servers can be downgraded to plain text.', { fix: 'Publish _mta-sts TXT and a policy file at https://mta-sts.domain/.well-known/mta-sts.txt.' }));
  checks.push(rpt ? mk('tlsrpt', 'Email security', 'TLS-RPT (TLS reports)', 'pass', 'TLS failure reports are requested.', { value: rpt })
    : mk('tlsrpt', 'Email security', 'TLS-RPT (TLS reports)', 'warn', 'Not configured (optional).', { fix: 'Add _smtp._tls TXT "v=TLSRPTv1; rua=mailto:you@domain".' }));

  const mx = dns.filter(r => r.type === 'MX');
  if (mx.length) checks.push(mk('mx', 'Email security', 'MX (mail routing)', mx.length > 1 ? 'pass' : 'warn', mx.length > 1 ? `${mx.length} mail servers configured, so there is a backup.` : 'Only one mail server; mail bounces if it is down.', { value: mx.map(r => r.value).join(' · ') }));

  const signed = ds.answers.length > 0 || (/signed/i.test(d.dnssec || "") && !/unsigned/i.test(d.dnssec || ""));
  checks.push(signed ? mk('dnssec', G2, 'DNSSEC (signed DNS)', 'pass', 'DNS answers are cryptographically signed and tamper-evident.')
    : mk('dnssec', G2, 'DNSSEC (signed DNS)', 'warn', 'Zone is not signed. DNS answers could be spoofed on the way to users.', { fix: 'Enable DNSSEC at your DNS host and add the DS record at the registrar.' }));

  const caa = dns.filter(r => r.type === 'CAA');
  checks.push(caa.length ? mk('caa', G2, 'CAA (certificate authorities)', 'pass', 'Only listed authorities may issue SSL certificates.', { value: caa.map(r => r.value).join(' · ') })
    : mk('caa', G2, 'CAA (certificate authorities)', 'warn', 'No CAA record. Any certificate authority may issue certificates for this domain.', { fix: 'Add a CAA record such as: 0 issue "letsencrypt.org".' }));

  const ns = dns.filter(r => r.type === 'NS');
  if (ns.length) checks.push(mk('ns', G2, 'Name server redundancy', ns.length > 1 ? 'pass' : 'warn', ns.length > 1 ? `${ns.length} name servers, so DNS survives one failing.` : 'Single name server is a point of failure.', { value: ns.map(r => r.value).join(' · ') }));

  const st = (d.status || []).map(x => x.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase());
  if (st.length) {
    const tl = st.some(x => /transfer prohibited/.test(x)), dl = st.some(x => /delete prohibited/.test(x));
    checks.push(tl ? mk('lock', G3, 'Transfer lock', 'pass', 'The domain cannot be transferred to another registrar without unlocking.')
      : mk('lock', G3, 'Transfer lock', 'warn', 'No transfer lock in the registry status. A hijacker with account access could move the domain.', { fix: 'Enable "Registrar lock" in your registrar panel.' }));
    checks.push(dl ? mk('del', G3, 'Delete lock', 'pass', 'Deletion is blocked until the lock is removed.')
      : mk('del', G3, 'Delete lock', 'info', 'No delete lock published.'));
  } else checks.push(mk('lock', G3, 'Registrar locks', 'info', 'This registry did not publish status codes, so locks cannot be verified.'));

  if (d.expires && !isNaN(new Date(d.expires))) {
    const days = Math.round((new Date(d.expires) - Date.now()) / 864e5);
    checks.push(days < 0 ? mk('exp', G3, 'Registration expiry', 'fail', `Expired ${-days} days ago.`, { fix: 'Renew immediately to avoid losing the domain.' })
      : days < 30 ? mk('exp', G3, 'Registration expiry', 'fail', `Expires in ${days} days.`, { fix: 'Renew now and enable auto-renew.' })
      : days < 90 ? mk('exp', G3, 'Registration expiry', 'warn', `Expires in ${days} days.`, { fix: 'Renew soon or enable auto-renew.' })
      : mk('exp', G3, 'Registration expiry', 'pass', `Registered for another ${days} days.`));
  }

  let got = 0, max = 0;
  for (const c of checks) { if (c.status === 'info') continue; max += c.weight; got += c.status === 'pass' ? c.weight : c.status === 'warn' ? c.weight * 0.5 : 0; }
  const score = max ? Math.round((got / max) * 100) : 0;
  const grade = score >= 90 ? ['A', 'Excellent'] : score >= 75 ? ['B', 'Good'] : score >= 55 ? ['C', 'Fair'] : score >= 35 ? ['D', 'Weak'] : ['E', 'Poor'];
  return { checks, score, grade: grade[0], label: grade[1], counts: { pass: checks.filter(c => c.status === 'pass').length, warn: checks.filter(c => c.status === 'warn').length, fail: checks.filter(c => c.status === 'fail').length } };
}

/** Looks up A records (and any CNAME chain) for common subdomains. Returns only names that resolve. */
export async function scanSubdomains(domain, signal) {
  const res = await Promise.all(SUBS.map(s => dohQuery(`${s}.${domain}`, 'A', signal).then(r => ({ s, r })).catch(e => { if (signal?.aborted) throw e; return { s, r: { answers: [], ok: false } }; })));
  return res.map(({ s, r }) => ({
    name: `${s}.${domain}`,
    records: r.answers.filter(a => a && a.data != null && (a.type === 1 || a.type === 5 || a.type === 28)).map(a => ({ type: a.type === 5 ? 'CNAME' : a.type === 28 ? 'AAAA' : 'A', value: String(a.data).trim(), ttl: a.TTL ? Number(a.TTL) : null })),
  })).filter(x => x.records.length);
}
