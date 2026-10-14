// Shared header, footer, toast container, mobile menu and "search a domain" forms for every page.
import { normalizeDomain } from './domain-validator.js';
import { SITE } from './config.js';

const NAV = [
  ['index.html', 'Domain Lookup'],
  ['how-it-works.html', 'How It Works'],
  ['faq.html', 'FAQ'],
  ['developer.html', 'Developer']
];
const page = (location.pathname.split('/').pop() || 'index.html').replace(/^$/, 'index.html');
const cur = /\.html$/.test(page) ? page : page + '.html';

// Logo image — SVG file se load hoga (assets/icons/logo.svg)
const LOGO_IMG = `<img class="logo-img" src="assets/icons/logo.svg" alt="${SITE.name} logo" width="30" height="30" loading="eager" decoding="async">`;
const logo = `<a class="logo" href="index.html" aria-label="${SITE.name} home">${LOGO_IMG}<span>Domain<b>Lookup</b></span></a>`;

const header = document.getElementById('site-header');
if (header) {
  header.className = 'top';
  header.innerHTML = `<div class="wrap bar">${logo}
    <nav class="main" id="nav" aria-label="Main">${NAV.map(([h, t]) => `<a href="${h}"${h === cur ? ' aria-current="page"' : ''}>${t}</a>`).join('')}</nav>
    <a class="btn grad" href="index.html#lookup">Check a Domain</a>
    <button class="burger" id="burger" type="button" aria-label="Menu" aria-expanded="false" aria-controls="nav"><span></span></button></div>`;
  const nav = header.querySelector('#nav'), b = header.querySelector('#burger');
  b.addEventListener('click', () => { const o = nav.classList.toggle('open'); b.setAttribute('aria-expanded', String(o)); });
  nav.addEventListener('click', e => { if (e.target.closest('a')) { nav.classList.remove('open'); b.setAttribute('aria-expanded', 'false'); } });
}

const footer = document.getElementById('site-footer');
if (footer) {
  footer.innerHTML = `<div class="wrap"><div class="fgrid">
    <div>${logo}<p>Free domain lookup tool — check WHOIS, RDAP, registrar, DNS records, nameservers, expiry dates and domain availability for any TLD instantly.</p></div>
    <div><h4>Tools</h4><ul><li><a href="index.html#lookup">Domain Lookup</a></li><li><a href="index.html#lookup">WHOIS Lookup</a></li><li><a href="index.html#lookup">RDAP Lookup</a></li><li><a href="index.html#lookup">DNS Records</a></li><li><a href="index.html#lookup">Domain Availability</a></li></ul></div>
    <div><h4>Learn</h4><ul><li><a href="how-it-works.html">How It Works</a></li><li><a href="faq.html">FAQ</a></li><li><a href="faq.html">What is RDAP?</a></li><li><a href="faq.html">Status Codes</a></li></ul></div>
    <div><h4>Company</h4><ul><li><a href="developer.html">Developer</a></li><li><a href="${SITE.developerUrl}" target="_blank" rel="noopener">${SITE.developer}</a></li><li><a href="privacy.html">Privacy Policy</a></li><li><a href="terms.html">Terms of Use</a></li></ul></div>
  </div><div class="fbar"><span>© ${new Date().getFullYear()} ${SITE.name}. All rights reserved.</span><span>Built by <strong><a href="${SITE.developerUrl}" target="_blank" rel="noopener" style="color:#fff">${SITE.developer}</a></strong></span></div></div>`;
}
if (!document.getElementById('toasts')) { const t = document.createElement('div'); t.id = 'toasts'; t.className = 'toasts'; document.body.append(t); }

// Search forms on pages other than the lookup page: validate, then open the lookup page with ?d=
document.querySelectorAll('form.js-goto').forEach(f => f.addEventListener('submit', e => {
  e.preventDefault();
  const i = f.querySelector('input'), n = normalizeDomain(i.value);
  if (n.error) { i.setCustomValidity('Enter a valid domain, e.g. example.com'); i.reportValidity(); i.addEventListener('input', () => i.setCustomValidity(''), { once: true }); return; }
  location.href = 'index.html?d=' + encodeURIComponent(n.domain) + '#out';
}));

// Photos load from the web; if one fails, hide it and let the gradient behind it show.
document.addEventListener('error', e => { if (e.target.tagName === 'IMG') e.target.style.visibility = 'hidden'; }, true);