const LABEL = /^(?:xn--)?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

/** Returns { domain } (ASCII/punycode) or { error: 'empty' | 'invalid' }. */
export function normalizeDomain(raw) {
  const s = String(raw ?? '').trim();
  if (!s) return { error: 'empty' };
  let host;
  if (/\s/.test(s) || s.length > 2048) return { error: 'invalid' };
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    if (!/^https?:\/\//i.test(s)) return { error: 'invalid' };
  } else if (/^[a-z][a-z0-9+.-]*:(?!\d+(?:[\/?#]|$))/i.test(s)) return { error: 'invalid' }; // mailto:, javascript: etc.
  try { host = new URL(/^https?:\/\//i.test(s) ? s : 'http://' + s).hostname; } catch { return { error: 'invalid' }; }
  host = host.toLowerCase().replace(/\.$/, '');
  if (/^\[.*\]$/.test(host) || /^[\d.]+$/.test(host)) return { error: 'invalid' }; // IP addresses
  let labels = host.split('.');
  if (labels.length > 2 && labels[0] === 'www') labels = labels.slice(1);
  host = labels.join('.');
  if (labels.length < 2 || host.length > 253) return { error: 'invalid' };
  if (!labels.every(l => l.length <= 63 && LABEL.test(l))) return { error: 'invalid' };
  if (/^\d+$/.test(labels.at(-1))) return { error: 'invalid' };
  return { domain: host };
}
