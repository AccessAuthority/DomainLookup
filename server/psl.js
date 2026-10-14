// Registrable-domain finder (public-suffix algorithm, ICANN section only).
// blog.example.com -> example.com, shop.foo.co.uk -> foo.co.uk, a.b.city.kobe.jp -> city.kobe.jp
// Without this, a subdomain would be looked up at the registry, get "404", and wrongly show as "Available".
import { RULES } from './psl-data.js';

const normal = new Set(), wild = new Set(), except = new Set();
for (const r of RULES) {
  if (r.startsWith('!')) except.add(r.slice(1));
  else if (r.startsWith('*.')) wild.add(r.slice(2));
  else normal.add(r);
}

/** Number of labels in the public suffix of `labels` (unknown TLDs count as 1, per the PSL default rule "*"). */
function suffixLen(labels) {
  let best = 1;
  for (let i = 0; i < labels.length; i++) {
    const cand = labels.slice(i).join('.'), n = labels.length - i;
    if (except.has(cand)) return n - 1;
    if (normal.has(cand)) best = Math.max(best, n);
    const parent = labels.slice(i + 1).join('.');
    if (i + 1 < labels.length && wild.has(parent)) best = Math.max(best, n);
  }
  return best;
}

/** Returns the registrable domain, or null if the host is itself a public suffix (e.g. "co.uk"). */
export function registrable(host) {
  const labels = String(host).toLowerCase().split('.');
  const n = suffixLen(labels);
  if (labels.length <= n) return null;
  return labels.slice(-(n + 1)).join('.');
}
