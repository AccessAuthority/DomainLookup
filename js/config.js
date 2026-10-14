// API_BASE: where the lookup API lives.
//   ''  (default) -> same origin (works automatically when you run `npm start` / deploy server/server.js on Render, Railway, VPS…)
//   'https://DomainLookup-api.yourname.workers.dev' -> use the Cloudflare Worker in /worker
// If the API is unreachable (e.g. plain static hosting), the site falls back to direct browser RDAP.
export const API_BASE = '';
export const SITE = {
  name: 'Domain Lookup',
  tagline: 'Free WHOIS, RDAP & DNS Lookup',
  developer: 'Access Authority',
  developerUrl: 'https://accessauthority.in'
};