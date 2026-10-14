// Preload for tests: fakes the network (IANA, two RDAP hosts, WHOIS, DNS) so the server can be tested offline.
import dns from 'node:dns/promises';
import net from 'node:net';
import { EventEmitter } from 'node:events';
import https from 'node:https';
import http from 'node:http';
import dnsCb from 'node:dns';
import { Readable } from 'node:stream';

globalThis.__calls = [];
dns.lookup = async host => [{ address: /internal/.test(host) ? '10.0.0.5' : '93.184.216.34', family: 4 }];

const J = (status, body) => new Response(body == null ? '' : JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
globalThis.fetch = async (url) => {
  const u = new URL(String(url)); globalThis.__calls.push(u.href);
  if (u.hostname === 'data.iana.org') return J(200, { services: [[['com', 'net', 'org'], ['https://rdap.test/']], [['in', 'co', 'io', 'info', 'co.in'], ['https://rdap2.test/']]] });
  const m = u.pathname.match(/\/domain\/(.+)$/);
  if (m) {
    const d = decodeURIComponent(m[1]);
    if (d.startsWith('free')) return J(404, { errorCode: 404 });
    if (d.startsWith('boom')) return J(500, {});
    if (d.startsWith('taken')) return J(200, { objectClassName: 'domain', ldhName: d.toUpperCase(), events: [{ eventAction: 'registration', eventDate: '2001-01-01T00:00:00Z' }], links: [{ rel: 'related', type: 'application/rdap+json', href: 'https://registrar.internal/domain/' + d }] });
  }
  return J(404, {});
};

net.connect = ({ host }) => {
  const s = new EventEmitter(); s.setEncoding = () => {}; s.destroy = () => {};
  s.write = q => {
    const query = String(q).trim().replace(/^domain /, '');
    let out = '';
    if (query === 'com' || query === 'in' || query === 'net') out = 'whois:        whois.test\n';
    else if (query.startsWith('taken')) out = `Domain Name: ${query.toUpperCase()}\nRegistrar: Test Registrar\n`;
    else if (query.startsWith('free')) out = `No match for "${query.toUpperCase()}".\n`;
    setTimeout(() => { if (out) s.emit('data', out); s.emit('end'); }, 5);
  };
  setTimeout(() => s.emit('connect'), 1);
  return s;
};

// guard.js resolves names through the callback API and talks HTTP via http(s).request: fake both,
// but keep the real guardedLookup in the loop so private addresses are still rejected.
dnsCb.lookup = (host, opts, cb) => {
  if (typeof opts === 'function') { cb = opts; opts = {}; }
  const address = /internal/.test(host) ? '10.0.0.5' : '93.184.216.34';
  setImmediate(() => (opts.all ? cb(null, [{ address, family: 4 }]) : cb(null, address, 4)));
};
function fakeRequest(url, opts, cb) {
  const req = new EventEmitter(); req.destroy = () => {};
  req.end = () => {
    const u = new URL(String(url));
    opts.lookup(u.hostname, { all: true }, async err => {
      if (err) return req.emit('error', err);
      const r = await globalThis.fetch(u.href), buf = Buffer.from(await r.text());
      const res = Readable.from(buf.length ? [buf] : []); res.statusCode = r.status; res.headers = {};
      cb(res);
    });
  };
  return req;
}
https.request = fakeRequest; http.request = fakeRequest;
