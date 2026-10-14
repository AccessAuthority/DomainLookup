import { safeUrl } from './rdap-parser.js';

export const $ = s => document.querySelector(s);
export function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else if (v != null && v !== false) n.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null) n.append(c.nodeType ? c : document.createTextNode(String(c)));
  return n;
}

export function toast(msg, type = 'ok') {
  const t = el('div', { class: 'toast ' + type, role: 'status' }, msg);
  $('#toasts').append(t); setTimeout(() => t.remove(), 2600);
}
export async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast('Copied to clipboard'); return; } catch {}
  const ta = el('textarea', { style: 'position:fixed;opacity:0' }); ta.value = text; document.body.append(ta); ta.select();
  let ok = false; try { ok = document.execCommand('copy'); } catch {} ta.remove();
  toast(ok ? 'Copied to clipboard' : 'Clipboard is unavailable in this browser', ok ? 'ok' : 'err');
}

const cp = (text, label) => el('button', { class: 'cp', type: 'button', 'aria-label': label || 'Copy', onclick: () => copy(text) }, 'Copy');
const na = () => el('span', { class: 'na' }, 'Not provided by registry');
const row = (l, v, c) => el('div', { class: 'row' }, el('dt', {}, l), el('dd', {}, v ? el('span', {}, v) : na(), v && c ? cp(c, 'Copy ' + l) : null));
const link = u => { const s = safeUrl(u); return s ? el('a', { href: s, target: '_blank', rel: 'noopener noreferrer' }, s) : null; };
/* ---------- Icons (static inline SVG, built with DOM APIs) ---------- */
const ICONS = {
  globe: ['<circle cx="12" cy="12" r="10"/>', 'M2 12h20', 'M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z'],
  server: ['<rect x="2" y="3" width="20" height="8" rx="2"/>', '<rect x="2" y="13" width="20" height="8" rx="2"/>', 'M6 7h.01', 'M6 17h.01'],
  mail: ['<rect x="2" y="4" width="20" height="16" rx="2"/>', 'm22 7-10 7L2 7'],
  file: ['M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z', 'M14 2v6h6', 'M8 13h8', 'M8 17h5'],
  link: ['M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71', 'M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71'],
  flag: ['M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z', 'M4 22v-7'],
  shield: ['M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z', 'm9 12 2 2 4-4'],
  pin: ['M20 10c0 6-8 12-8 12S4 16 4 10a8 8 0 0 1 16 0z', '<circle cx="12" cy="10" r="3"/>'],
  activity: ['M22 12h-4l-3 9L9 3l-3 9H2'],
  info: ['<circle cx="12" cy="12" r="10"/>', 'M12 16v-4', 'M12 8h.01'],
  bank: ['M3 21h18', 'M5 21V10', 'M9 21V10', 'M15 21V10', 'M19 21V10', 'M12 3 2 9h20z'],
  user: ['<circle cx="12" cy="8" r="4"/>', 'M4 21v-1a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v1'],
  users: ['<circle cx="9" cy="8" r="3.5"/>', 'M2 21v-1a6 6 0 0 1 6-6h2a6 6 0 0 1 6 6v1', 'M16 4.5a3.5 3.5 0 0 1 0 7', 'M22 21v-1a6 6 0 0 0-4-5.6'],
  wrench: ['M14.7 6.3a4 4 0 0 0 5 5L22 9.5a7 7 0 0 1-9.7 9.7L5 22l-3-3 2.8-7.3A7 7 0 0 1 14.5 2z'],
  card: ['<rect x="2" y="5" width="20" height="14" rx="2"/>', 'M2 10h20'],
  calendar: ['<rect x="3" y="4" width="18" height="18" rx="2"/>', 'M16 2v4', 'M8 2v4', 'M3 10h18'],
  clock: ['<circle cx="12" cy="12" r="10"/>', 'M12 6v6l4 2'],
  tag: ['M20.6 13.4 13.4 20.6a2 2 0 0 1-2.8 0L2 12V2h10l8.6 8.6a2 2 0 0 1 0 2.8z', 'M7 7h.01'],
  lock: ['<rect x="3" y="11" width="18" height="11" rx="2"/>', 'M7 11V7a5 5 0 0 1 10 0v4'],
  grid: ['<rect x="3" y="3" width="7" height="7" rx="1"/>', '<rect x="14" y="3" width="7" height="7" rx="1"/>', '<rect x="3" y="14" width="7" height="7" rx="1"/>', '<rect x="14" y="14" width="7" height="7" rx="1"/>'],
  check: ['M20 6 9 17l-5-5'],
  alert: ['M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z', 'M12 9v4', 'M12 17h.01'],
  xcircle: ['<circle cx="12" cy="12" r="10"/>', 'm15 9-6 6', 'm9 9 6 6'],
  download: ['M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4', 'm7 10 5 5 5-5', 'M12 15V3'],
  copy: ['<rect x="9" y="9" width="13" height="13" rx="2"/>', 'M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1'],
  print: ['M6 9V2h12v7', '<rect x="6" y="14" width="12" height="8"/>', 'M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2'],
  ext: ['M15 3h6v6', 'M10 14 21 3', 'M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6'],
  mailshield: ['<rect x="2" y="4" width="20" height="14" rx="2"/>', 'm22 7-10 6L2 7', 'M12 22s4-2 4-5'],
  hash: ['M4 9h16', 'M4 15h16', 'M10 3 8 21', 'M16 3l-2 18'],
};
const SVGNS = 'http://www.w3.org/2000/svg';
export function icon(name, cls = 'ico') {
  const svg = document.createElementNS(SVGNS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('class', cls); svg.setAttribute('aria-hidden', 'true'); svg.setAttribute('focusable', 'false');
  for (const part of ICONS[name] || ICONS.info) {
    let n;
    if (part.startsWith('<')) {
      const t = document.createElement('template'); t.innerHTML = '<svg xmlns="' + SVGNS + '">' + part + '</svg>';
      n = document.importNode(t.content.firstChild.firstChild, true);
    } else { n = document.createElementNS(SVGNS, 'path'); n.setAttribute('d', part); }
    svg.append(n);
  }
  return svg;
}
// Heading icon + colour tone for every result card (looked up by card title)
const HEAD = {
  'Domain Information': ['globe', 'blue'], 'Registrar': ['bank', 'purple'], 'Registrant & Contacts': ['users', 'teal'],
  'Registrant Contact': ['user', 'teal'], 'Administrative Contact': ['user', 'amber'], 'Technical Contact': ['wrench', 'green'], 'Billing Contact': ['card', 'red'],
  'All dates & events': ['calendar', 'amber'], 'DNS Records': ['server', 'red'], 'Security Check': ['shield', 'green'], 'Subdomains': ['globe', 'teal'],
};
const heading = (title, ic, tone, extra) => {
  const [i, t] = HEAD[title] || [ic || 'info', tone || 'blue'];
  return el('h3', {}, el('span', { class: 'ht' }, el('span', { class: 'hic tone-' + (tone || t) }, icon(ic || i)), el('span', {}, title)), extra || null);
};
const card = (title, body, cls = '') => el('section', { class: 'card ' + cls }, heading(title), body);
const fmt = d => {
  if (!d) return null;
  const x = new Date(d);
  if (isNaN(x)) return String(d);
  return x.toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }) + ' UTC';
};

function download(name, text, mime) {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = el('a', { href: url, download: name }); document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}
const csvCell = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';
const safeCsv = v => /^[=+\-@\t\r]/.test(String(v)) ? "'" + v : v; // blocks spreadsheet formula injection

const STATUS = {
  'client delete prohibited': 'Registrar has blocked deletion of this domain.', 'client update prohibited': 'Registrar has blocked changes to the record.',
  'client transfer prohibited': 'Registrar has locked the domain against transfers.', 'client renew prohibited': 'Registrar has blocked renewal.',
  'server delete prohibited': 'Registry has blocked deletion.', 'server update prohibited': 'Registry has blocked changes.',
  'server transfer prohibited': 'Registry has locked transfers.', 'server renew prohibited': 'Registry has blocked renewal.',
  'active': 'Domain is active and can resolve.', 'ok': 'Domain is active with no pending actions.', 'inactive': 'Domain has no delegated nameservers.',
  'pending delete': 'Domain is scheduled for deletion.', 'pending transfer': 'A transfer is in progress.', 'pending create': 'Registration is pending.',
  'pending renew': 'Renewal is pending.', 'pending update': 'An update is pending.', 'redemption period': 'Expired and in the redemption grace period.',
  'client hold': 'Registrar has suspended DNS resolution.', 'server hold': 'Registry has suspended DNS resolution.',
  'add period': 'Newly registered, within the add grace period.', 'renew period': 'Recently renewed, within the grace period.',
};
const explain = s => STATUS[s.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase()];

export function showLoading(domain) {
  const sk = (cls = '') => el('div', { class: 'skel ' + cls });
  $('#result').replaceChildren(
    el('div', { class: 'card state' }, el('div', { class: 'spin', role: 'progressbar', 'aria-label': 'Loading' }), el('h3', {}, 'Looking up ' + domain + '…'), el('p', {}, 'Finding the registry and requesting the record.')),
    el('div', { class: 'sum skeleton', 'aria-hidden': 'true' }, ...[1, 2, 3, 4, 5].map(() => el('div', { class: 'card' }, sk('s-sm'), sk('s-md')))),
    el('div', { class: 'sections skeleton', 'aria-hidden': 'true' },
      el('div', { class: 'col' }, el('div', { class: 'card' }, sk('s-md'), sk(), sk(), sk(), sk(), sk())),
      el('div', { class: 'col' }, el('div', { class: 'card' }, sk('s-md'), sk(), sk(), sk()), el('div', { class: 'card' }, sk('s-md'), sk(), sk()))));
}
export function showError(msg, onRetry, title = 'Lookup unsuccessful', hint = null) {
  $('#result').replaceChildren(el('div', { class: 'card state err', role: 'alert' }, el('h3', {}, title), el('p', {}, msg), hint ? el('p', { class: 'na' }, hint) : null,
    onRetry ? el('div', { class: 'row-b' }, el('button', { class: 'primary grad', type: 'button', onclick: onRetry }, 'Retry')) : null));
}

function lifeBar(d, left) {
  const a = new Date(d.registered), b = new Date(d.expires), total = b - a;
  const pct = left < 0 ? 0 : total > 0 && !isNaN(total) ? Math.max(3, Math.min(100, ((b - Date.now()) / total) * 100)) : Math.min(100, (left / 365) * 100);
  const fill = el('i', {}); fill.style.width = pct.toFixed(1) + '%';
  return el('div', { class: 'life ' + (left < 30 ? 'bad' : left < 90 ? 'warn' : 'good'), role: 'img', 'aria-label': 'Registration time remaining' }, fill);
}
const daysLeft = d => Math.round((new Date(d) - Date.now()) / 864e5);
function age(d) {
  const y = (Date.now() - new Date(d)) / 31557600000;
  if (isNaN(y) || y < 0) return null;
  return y >= 1 ? `${Math.floor(y)} yr ${Math.floor((y % 1) * 12)} mo` : `${Math.floor(y * 12)} mo`;
}
const cRows = c => [['Name', c.name], ['Organization', c.org], ['Street', c.street], ['City', c.city], ['State/Province', c.state], ['Postal code', c.postal], ['Country', c.country], ['Phone', c.phone], ['Email', c.email]]
  .filter(([, v]) => v).map(([l, v]) => row(l, v, v));

function tabsCard(tabs) {
  let cur = 0;
  const pre = el('pre', { tabindex: '0' }, tabs[0].text);
  const btns = tabs.map((t, i) => {
    const b = el('button', { class: 'tab' + (i ? '' : ' on'), type: 'button' }, t.label);
    b.addEventListener('click', () => { cur = i; pre.textContent = t.text; btns.forEach((x, j) => x.classList.toggle('on', i === j)); });
    return b;
  });
  return el('section', { class: 'card full' }, el('div', { class: 'tabs' }, ...btns, el('button', { type: 'button', onclick: () => copy(tabs[cur].text) }, 'Copy')), pre);
}
const PILL = { available: ['Available', 'ok'], registered: ['Taken', 'taken'], unknown: ['Unknown', 'unk'] };
const pill = st => { const [t, c] = PILL[st] || PILL.unknown; return el('span', { class: 'pill ' + c }, t); };

export function altCard(name, current, onPick) {
  const grid = el('div', { class: 'alt' }, el('p', { class: 'na' }, 'Checking other extensions…'));
  const node = el('section', { class: 'card full altcard' }, heading('Other extensions for "' + name + '"', 'grid', 'green'), grid);
  return {
    node,
    set(items) {
      const all = [...(current ? [current] : []), ...items.filter(i => !current || i.domain !== current.domain)];
      grid.replaceChildren(...all.map(i => el('button', { type: 'button', class: 'altc' + (current && i.domain === current.domain ? ' cur' : ''), 'aria-label': i.domain + ': ' + (PILL[i.state] || PILL.unknown)[0], onclick: () => onPick(i.domain) },
        el('span', { class: 'altd' }, i.domain), pill(i.state))));
    },
    fail(msg) { grid.replaceChildren(el('p', { class: 'na' }, msg)); },
  };
}

// const srcNote = m => el('p', { class: 'srcnote' }, 'Sources: ', el('span', { class: 'code' }, m.sources.join(' · ') || 'registry'));.
const srcNote = () => el('p', { class: 'srcnote' }, 'Note: Check out Access Authority Youtube Channel for more information on how to use this tool.');  

/* ---------- DNS Records Card: labels, icons, colours ---------- */
const DNS_META = {
  A:     { label: 'IPv4 Address',      desc: 'Points the domain to an IPv4 server address', icon: 'pin',    tone: 'blue' },
  AAAA:  { label: 'IPv6 Address',      desc: 'Points the domain to an IPv6 server address', icon: 'globe',  tone: 'green' },
  MX:    { label: 'Mail Server',       desc: 'Where email for this domain is delivered',    icon: 'mail',   tone: 'amber' },
  NS:    { label: 'Name Server',       desc: 'Servers that host this domain\'s DNS zone',   icon: 'server', tone: 'purple' },
  TXT:   { label: 'Text Record',       desc: 'SPF, DKIM, verification and other text data', icon: 'file',   tone: 'red' },
  CNAME: { label: 'Canonical Name',    desc: 'Alias that forwards to another hostname',     icon: 'link',   tone: 'teal' },
  SOA:   { label: 'Start of Authority', desc: 'Primary zone info, serial number and timers', icon: 'flag',  tone: 'slate' },
  CAA:   { label: 'Certificate Authority', desc: 'Which CAs may issue SSL certificates',    icon: 'shield', tone: 'pink' },
};
const DNS_ORDER = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA'];
const dnsMeta = t => DNS_META[t] || { label: t + ' Record', desc: 'DNS record', icon: 'hash', tone: 'slate' };
const ttlText = s => !s ? '' : s >= 86400 && s % 86400 === 0 ? (s / 86400) + ' d' : s >= 3600 && s % 3600 === 0 ? (s / 3600) + ' h' : s >= 60 && s % 60 === 0 ? (s / 60) + ' min' : s + ' s';

function dnsRow(type, r) {
  let val = r.value || '—', pri = null;
  if (type === 'MX') { const m = /^(\d+)\s+(.+)$/.exec(val); if (m) { pri = m[1]; val = m[2]; } }
  return el('div', { class: 'dns-row' },
    pri != null ? el('span', { class: 'dns-pri', title: 'MX priority (lower = tried first)' }, 'Priority ' + pri) : null,
    el('span', { class: 'dns-val' }, val),
    r.ttl ? el('span', { class: 'dns-ttl', title: 'Time to live: ' + r.ttl + ' seconds' }, icon('clock', 'ico sm'), 'TTL ' + ttlText(r.ttl)) : el('span', { class: 'dns-ttl none' }, '—'),
    el('span', { class: 'dns-act' },
      (type === 'A' || type === 'AAAA') && /^[0-9a-f:.]+$/i.test(val) ? el('a', { class: 'ipl', href: 'https://ipinfo.io/' + encodeURIComponent(val), target: '_blank', rel: 'noopener noreferrer', title: 'Look up this IP (opens ipinfo.io)', 'aria-label': 'Look up IP ' + val }, icon('ext', 'ico sm')) : null,
      cp(r.value || val, 'Copy ' + type + ' record')));
}

function dnsCard(m) {
  const dns = m.dns;
  if (!dns || (!dns.length && !m.dnsUnavailable)) return null;
  const live = el('span', { class: 'live' }, el('i'), 'Live');
  const body = el('div', { class: 'dns-block' });

  if (!dns.length) {
    body.append(el('div', { class: 'dns-empty' }, icon('info', 'ico lg'), el('p', {}, m.dnsUnavailable ? 'DNS records could not be fetched from public resolvers. Try again in a moment.' : 'No DNS records were returned for this domain.')));
    return el('section', { class: 'card dns-card' }, heading('DNS Records', 'server', 'red', live), body);
  }

  const groups = new Map();
  for (const r of dns) { const k = r.type || 'OTHER'; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(r); }
  const types = [...groups.keys()].sort((a, b) => (DNS_ORDER.indexOf(a) + 1 || 99) - (DNS_ORDER.indexOf(b) + 1 || 99));

  // Toolbar: copy all + export
  const plain = dns.map(r => `${r.type}\t${r.value}\t${r.ttl ?? ''}`).join('\n');
  const fname = (m.d && m.d.name ? m.d.name : 'domain').replace(/[^a-z0-9.-]/gi, '_');
  const tb = el('div', { class: 'dns-tools' },
    el('button', { type: 'button', onclick: () => copy(plain) }, icon('copy', 'ico sm'), 'Copy all'),
    el('button', { type: 'button', onclick: () => download(fname + '-dns.json', JSON.stringify(dns.map(({ type, value, ttl }) => ({ type, value, ttl })), null, 2), 'application/json') }, icon('download', 'ico sm'), 'JSON'),
    el('button', { type: 'button', onclick: () => download(fname + '-dns.csv', 'type,value,ttl\n' + dns.map(r => [r.type, safeCsv(r.value), r.ttl ?? ''].map(csvCell).join(',')).join('\n'), 'text/csv') }, icon('download', 'ico sm'), 'CSV'));

  // Filter chips: click to show only that type
  const zones = new Map(), active = new Set();
  const chipBtns = new Map();
  const apply = () => {
    for (const [t, z] of zones) z.hidden = active.size > 0 && !active.has(t);
    for (const [t, b] of chipBtns) b.setAttribute('aria-pressed', String(active.has(t)));
    allChip.setAttribute('aria-pressed', String(active.size === 0));
  };
  const allChip = el('button', { type: 'button', class: 'dns-chip tone-slate', 'aria-pressed': 'true', onclick: () => { active.clear(); apply(); } }, el('b', {}, 'All'), el('em', {}, String(dns.length)));
  const chips = el('div', { class: 'dns-chips', role: 'group', 'aria-label': 'Filter by record type' }, allChip,
    ...types.map(t => {
      const x = dnsMeta(t);
      const b = el('button', { type: 'button', class: 'dns-chip tone-' + x.tone, 'aria-pressed': 'false', onclick: () => { active.has(t) ? active.delete(t) : active.add(t); apply(); } }, icon(x.icon, 'ico sm'), el('b', {}, t), el('em', {}, String(groups.get(t).length)));
      chipBtns.set(t, b); return b;
    }));
  body.append(el('div', { class: 'dns-bar' }, chips, tb));

  for (const type of types) {
    const records = groups.get(type), x = dnsMeta(type);
    const z = el('div', { class: 'dns-zone tone-' + x.tone },
      el('div', { class: 'dns-zone-h' },
        el('span', { class: 'dns-icon-wrap' }, icon(x.icon, 'dns-icon')),
        el('span', { class: 'dns-zone-title' }, el('b', {}, x.label), el('small', {}, x.desc)),
        el('code', { class: 'dns-code' }, type),
        el('span', { class: 'dns-count' }, records.length + (records.length === 1 ? ' record' : ' records'))),
      el('div', { class: 'dns-cols', 'aria-hidden': 'true' }, el('span', {}, 'Value'), el('span', {}, 'TTL')),
      el('div', { class: 'dns-records' }, ...records.map(r => dnsRow(type, r))));
    zones.set(type, z); body.append(z);
  }
  return el('section', { class: 'card dns-card' }, heading('DNS Records', 'server', 'red', live), body);
}

/* ---------- Security Check ---------- */
const SIC = { pass: ['check', 'Pass'], warn: ['alert', 'Warning'], fail: ['xcircle', 'Fail'], info: ['info', 'Info'] };
function ring(score, grade) {
  const r = 34, c = 2 * Math.PI * r, col = score >= 75 ? '#127a43' : score >= 55 ? '#b26a00' : '#b01e2d';
  const svg = document.createElementNS(SVGNS, 'svg');
  svg.setAttribute('viewBox', '0 0 84 84'); svg.setAttribute('class', 'ring'); svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', `Security score ${score} out of 100, grade ${grade}`);
  const mkc = (cls) => { const k = document.createElementNS(SVGNS, 'circle'); k.setAttribute('cx', 42); k.setAttribute('cy', 42); k.setAttribute('r', r); k.setAttribute('class', cls); return k; };
  const bg = mkc('ring-bg'), fg = mkc('ring-fg');
  fg.setAttribute('stroke', col); fg.setAttribute('stroke-dasharray', `${(c * score) / 100} ${c}`); fg.setAttribute('transform', 'rotate(-90 42 42)');
  const t = document.createElementNS(SVGNS, 'text'); t.setAttribute('x', 42); t.setAttribute('y', 47); t.setAttribute('text-anchor', 'middle'); t.setAttribute('class', 'ring-t'); t.textContent = score;
  svg.append(bg, fg, t); return svg;
}
export function securityPanel() {
  const body = el('div', { class: 'sec-body' }, el('div', { class: 'sec-load' }, el('div', { class: 'spin', role: 'progressbar', 'aria-label': 'Running security checks' }), el('p', {}, 'Running security checks (SPF, DMARC, DKIM, DNSSEC, CAA)…')));
  const node = el('section', { class: 'card sec-card' }, heading('Security Check', 'shield', 'green'), body);
  return {
    node,
    set(res) {
      const groups = new Map();
      for (const c of res.checks) { if (!groups.has(c.group)) groups.set(c.group, []); groups.get(c.group).push(c); }
      const GI = { 'Email security': 'mailshield', 'DNS security': 'server', 'Domain protection': 'lock' };
      const top = el('div', { class: 'sec-top' },
        el('div', { class: 'sec-score' }, ring(res.score, res.grade), el('div', {}, el('b', { class: 'sec-grade g-' + res.grade.toLowerCase() }, 'Grade ' + res.grade), el('span', {}, res.label + ' security posture'))),
        el('div', { class: 'sec-counts' },
          el('span', { class: 'sc pass' }, icon('check', 'ico sm'), res.counts.pass + ' passed'),
          el('span', { class: 'sc warn' }, icon('alert', 'ico sm'), res.counts.warn + ' warnings'),
          el('span', { class: 'sc fail' }, icon('xcircle', 'ico sm'), res.counts.fail + ' failed')));
      const list = [...groups].map(([g, items]) => el('div', { class: 'sec-group' },
        el('h4', {}, icon(GI[g] || 'shield', 'ico'), g),
        ...items.map(c => el('div', { class: 'sec-item ' + c.status },
          el('span', { class: 'sec-ic', title: SIC[c.status][1] }, icon(SIC[c.status][0], 'ico'), el('span', { class: 'sr' }, SIC[c.status][1])),
          el('div', { class: 'sec-main' },
            el('b', {}, c.title), el('p', {}, c.detail),
            c.value ? el('code', { class: 'sec-val' }, c.value.length > 160 ? c.value.slice(0, 157) + '…' : c.value) : null,
            c.fix ? el('p', { class: 'sec-fix' }, el('b', {}, 'How to fix: '), c.fix) : null)))));
      body.replaceChildren(top, ...list, el('p', { class: 'srcnote' }, 'Checks read public DNS and registry data only. DKIM is tested on common selectors, so a "not found" result is not conclusive.'));
    },
    fail(msg) { body.replaceChildren(el('div', { class: 'dns-empty' }, icon('info', 'ico lg'), el('p', {}, msg))); },
  };
}
export function subdomainCard() {
  const body = el('div', { class: 'sub-body' }, el('p', { class: 'na' }, 'Scanning common subdomains…'));
  const node = el('section', { class: 'card sub-card' }, heading('Subdomains', 'globe', 'teal'), body);
  return {
    node,
    set(items) {
      if (!items.length) { body.replaceChildren(el('p', { class: 'na' }, 'No common subdomains (www, mail, ftp, api…) resolved for this domain.')); return; }
      body.replaceChildren(el('div', { class: 'sub-list' }, ...items.map(it => el('div', { class: 'sub-item' },
        el('b', {}, it.name),
        el('div', { class: 'sub-recs' }, ...it.records.map(r => el('span', { class: 'sub-rec' }, el('em', { class: 'dns-type ' + r.type.toLowerCase() }, r.type), el('code', {}, r.value))))))));
    },
    fail(msg) { body.replaceChildren(el('p', { class: 'na' }, msg)); },
  };
}

export function showAvailable(m, ctx, onAgain) {
  $('#result').replaceChildren(
    el('div', { class: 'card banner avail' }, el('div', {}, el('h2', { class: 'dname' }, ctx.domain, ' ', pill('available')),
      el('p', { class: 'okt' }, '✓ This domain appears to be available. The registry has no record for it. Confirm with a registrar before you buy, because reserved and blocked names can look the same.')),
      el('div', { class: 'acts' }, el('button', { type: 'button', onclick: onAgain }, 'Search another'))),
    m.tabs.length ? el('div', { class: 'sections' }, tabsCard(m.tabs)) : null, srcNote(m));
}

function contactBlock(m) {
  if (m.cards && m.cards.length) {
    return m.cards.map(([title, c]) => card(title, el('dl', {}, ...cRows(c))));
  }
  if (m.people && m.people.length) {
    return [card('Registrant & Contacts', el('ul', { class: 'list' },
      m.people.map(c => el('li', {},
        el('span', {},
          el('b', {}, c.name || c.org || (c.roles && c.roles[0] ? `(${c.roles[0]})` : 'Contact')),
          el('small', {}, (c.roles || []).join(', ') || 'entity'),
          ...[c.org && c.name ? c.org : null, c.email, c.tel, c.address].filter(Boolean).map(x => el('small', {}, x))
        ),
        c.email ? cp(c.email, 'Copy email') : null
      ))
    ))];
  }
  return [card('Registrant & Contacts',
    el('p', { class: 'na' }, 'The registry did not publish registrant details (usually redacted for privacy). No owner is identified.')
  )];
}

export function showResult(m, ctx, onAgain) {
  const d = m.d, rg = d.registrar, name = d.name || ctx.domain;
  const valid = x => x && !isNaN(new Date(x));
  const left = valid(d.expires) ? daysLeft(d.expires) : null, a = valid(d.registered) ? age(d.registered) : null;
  const dl = (...rows) => el('dl', {}, ...rows);

  const banner = el('div', { class: 'card banner' },
    el('div', {}, el('h2', { class: 'dname' }, name, ' ', pill('registered')), el('p', { class: 'okt' }, 'This domain is registered. Data retrieved live from the registry.')),
    el('div', { class: 'acts' }, el('button', { type: 'button', onclick: () => copy(name) }, 'Copy domain'), el('button', { type: 'button', onclick: () => copy(location.origin + location.pathname + '?d=' + encodeURIComponent(name)) }, 'Copy link'), el('button', { type: 'button', onclick: () => window.print() }, icon('print', 'ico sm'), 'Print / PDF'), el('button', { type: 'button', onclick: onAgain }, 'Search another')));

  const alertBox = left == null ? null : left < 0 ? ['xcircle', 'bad', `This domain expired ${-left} days ago. It may enter a redemption period or be released.`]
    : left < 30 ? ['alert', 'bad', `This domain expires in ${left} days. Renew it soon to avoid losing it.`] : left < 90 ? ['alert', 'warn', `This domain expires in ${left} days.`] : null;
  const alertNode = alertBox ? el('div', { class: 'alert ' + alertBox[1], role: 'alert' }, icon(alertBox[0], 'ico'), el('span', {}, alertBox[2])) : null;

  const sum = el('div', { class: 'sum' }, ...[
    ['Domain age', a], ['Expires in', left == null ? null : left < 0 ? 'Expired' : left + ' days'], ['Registrar', rg?.name], ['DNSSEC', d.dnssec], ['Nameservers', String(d.nameservers.length)],
  ].map(([l, v], i) => el('div', { class: 'card' }, el('small', {}, icon(['clock', 'calendar', 'bank', 'lock', 'server'][i], 'ico sm'), l), v ? el('b', { class: i === 1 && left != null && left < 30 ? 'warnv' : '' }, v) : na(), i === 1 && left != null ? lifeBar(d, left) : null)));

  const statusNode = d.status.length ? el('div', { class: 'stack' }, d.status.map(x => el('span', {}, el('span', { class: 'code' }, x), explain(x) ? el('small', {}, explain(x)) : null))) : null;
  const nsNode = d.nameservers.length ? el('div', { class: 'stack' }, d.nameservers.map(n => el('span', { class: 'ns' }, el('span', { class: 'code' }, n.name, n.ips.length ? el('small', {}, n.ips.join(', ')) : null), cp(n.name, 'Copy nameserver')))) : null;

  const info = card('Domain Information', dl(
    row('Domain', d.name, d.name), row('Unicode name', d.unicodeName), row('Registrar', rg?.name, rg?.name), row('Registrar IANA ID', rg?.ianaId, rg?.ianaId),
    row('Registered on', d.registered && fmt(d.registered), d.registered), row('Expires on', d.expires && fmt(d.expires), d.expires),
    row('Updated on', d.changed && fmt(d.changed), d.changed), row('Status', statusNode), row('Name servers', nsNode),
    row('DNSSEC', d.dnssec), row('Registry ID', d.handle, d.handle)));

  const registrar = card('Registrar', rg ? dl(row('Name', rg.name, rg.name), row('IANA ID', rg.ianaId, rg.ianaId), row('Website', rg.url && link(rg.url), rg.url),
    row('Abuse / contact email', rg.email, rg.email), row('Phone', rg.tel, rg.tel)) : el('p', { class: 'na' }, 'Not provided by registry'));

  const contactCards = contactBlock(m);

  const dates = card('All dates & events', d.events.length ? el('ul', { class: 'list' }, d.events.map(e =>
    el('li', {}, el('span', {}, e.action.replace(/(^|\s)\S/g, x => x.toUpperCase())), el('span', {}, fmt(e.date), ' ', cp(e.date, 'Copy date'))))) : el('p', { class: 'na' }, 'Not provided by registry'));

  const dns = dnsCard(m);

  // Balanced layout: left column = info; right column = registrar + contacts + dates
  // DNS card full-width below
    $('#result').replaceChildren(...[
    banner,
    alertNode,
    sum,
    el('div', { class: 'sections' },
      el('div', { class: 'col' }, info),
      el('div', { class: 'col' }, registrar, ...contactCards, dates)
    ),
    dns,
    el('div', { id: 'sec-slot' }),
    el('div', { id: 'sub-slot' }),
    m.tabs.length ? tabsCard(m.tabs) : null,
    srcNote(m)
  ].filter(Boolean));
}