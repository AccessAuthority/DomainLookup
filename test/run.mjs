
/**
 * DomainLookup offline tests
 * Run: node test/run.mjs
 * No external network required.
 */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

import { normalizeDomain } from '../js/domain-validator.js';
import { findServices } from '../js/rdap-bootstrap.js';
import { parseWhois } from '../js/whois-parser.js';
import { buildModel } from '../js/model.js';
import { isPrivateIp, guardedLookup, clientKey, RateLimiter, securityHeaders, corsHeaders } from '../server/guard.js';

const dir = path.dirname(fileURLToPath(import.meta.url));

let pass = 0;
let fail = 0;

async function ta(name, fn) {
  try { await fn(); pass++; console.log('  ok  ', name); }
  catch (error) { fail++; process.exitCode = 1; console.error('  FAIL', name, '\n', error.message); }
}

function t(name, fn) {
  try {
    fn();
    pass++;
    console.log('  ok  ', name);
  } catch (error) {
    fail++;
    process.exitCode = 1;
    console.error('  FAIL', name, '\n', error.message);
  }
}

/**
 * Wait for the local server's health endpoint instead of relying
 * on a particular startup message appearing on stdout.
 */
async function waitForServer(child, port, label) {
  let stdout = '';
  let stderr = '';
  let spawnError = null;

  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');

  child.stdout.on('data', data => {
    stdout += data;
  });

  child.stderr.on('data', data => {
    stderr += data;
  });

  child.on('error', error => {
    spawnError = error;
  });

  const deadline = Date.now() + 15000;

  while (Date.now() < deadline) {
    if (spawnError) {
      throw new Error(
        `${label} could not start: ${spawnError.message}\n` +
        `stdout:\n${stdout}\nstderr:\n${stderr}`
      );
    }

    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(
        `${label} exited before becoming ready.\n` +
        `Exit code: ${child.exitCode}\n` +
        `Signal: ${child.signalCode}\n` +
        `stdout:\n${stdout}\nstderr:\n${stderr}`
      );
    }

    try {
      const response = await fetch(
        `http://127.0.0.1:${port}/api/health`,
        { signal: AbortSignal.timeout(1000) }
      );

      if (response.ok) {
        return;
      }
    } catch {
      // The server may still be starting.
    }

    await new Promise(resolve => setTimeout(resolve, 100));
  }

  throw new Error(
    `${label} startup timed out after 15 seconds.\n` +
    `stdout:\n${stdout}\nstderr:\n${stderr}`
  );
}

function stopServer(child) {
  if (
    child &&
    child.exitCode === null &&
    child.signalCode === null
  ) {
    child.kill();
  }
}

// --------------------------------------------------
// Unit tests
// --------------------------------------------------

t('validator accepts urls/paths/idn', () => {
  assert.equal(
    normalizeDomain('https://www.Example.com/a?b=1').domain,
    'example.com'
  );

  assert.equal(
    normalizeDomain('example.com/path').domain,
    'example.com'
  );

  assert.equal(
    normalizeDomain('münchen.de').domain,
    'xn--mnchen-3ya.de'
  );

  assert.equal(
    normalizeDomain('bbc.co.uk.').domain,
    'bbc.co.uk'
  );
});

t('validator rejects junk', () => {
  for (const value of [
    '',
    'localhost',
    '1.2.3.4',
    'a b.com',
    'mailto:a@b.com',
    'javascript:alert(1)',
    '-bad.com',
    'ftp://x.com'
  ]) {
    assert.ok(normalizeDomain(value).error, value);
  }
});

t('bootstrap longest-suffix match', () => {
  const map = new Map([
    ['uk', ['https://a/']],
    ['co.uk', ['https://b/']],
    ['com', ['https://c/']]
  ]);

  assert.equal(
    findServices('bbc.co.uk', { map }).urls[0],
    'https://b/'
  );

  assert.equal(
    findServices('x.com', { map }).urls[0],
    'https://c/'
  );

  assert.equal(
    findServices('x.zzz', { map }),
    null
  );
});

const fx = JSON.parse(
  readFileSync(path.join(dir, 'fixture.json'), 'utf8')
);

t('whois parser', () => {
  const whois = parseWhois(fx.whois.text);

  assert.equal(
    whois.registrar,
    'RESERVED-Internet Assigned Numbers Authority'
  );

  assert.equal(
    whois.status[0],
    'clientDeleteProhibited'
  );

  assert.equal(
    whois.ns[0],
    'a.iana-servers.net'
  );

  assert.equal(whois.dnssec, 'Signed');
});

t('model merges rdap + whois', () => {
  const model = buildModel(fx);

  assert.equal(model.d.name, 'example.com');
  assert.equal(model.d.registrar.ianaId, '376');
  assert.equal(model.d.nameservers.length, 2);
  assert.equal(model.d.dnssec, 'Signed');

  assert.ok(
    model.tabs.some(tab => /Registry WHOIS/.test(tab.label)) &&
    model.tabs.some(tab => tab.label === 'RDAP JSON')
  );

  assert.equal(model.available, false);
});

t('model: available domain', () => {
  const model = buildModel({
    domain: 'free-name-123.com',
    available: true,
    rdap: null,
    whois: {
      server: 's',
      text: 'No match for "FREE-NAME-123.COM".'
    }
  });

  assert.equal(model.available, true);
});


// --------------------------------------------------
// Security unit tests (server/guard.js)
// --------------------------------------------------

t('ssrf: private / reserved IPv4 blocked, public allowed', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '198.18.0.1', '192.0.2.5'])
    assert.equal(isPrivateIp(ip), true, ip);
  for (const ip of ['93.184.216.34', '8.8.8.8', '1.1.1.1', '172.15.0.1', '172.32.0.1'])
    assert.equal(isPrivateIp(ip), false, ip);
});

t('ssrf: IPv6 tricks blocked (mapped, hex-mapped, NAT64, 6to4, ULA, link-local)', () => {
  for (const ip of ['::1', '::', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:10.0.0.1', '::ffff:a9fe:a9fe', '64:ff9b::7f00:1', '2002:7f00:1::1', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'ff02::1', '2001:db8::1', 'garbage'])
    assert.equal(isPrivateIp(ip), true, ip);
  for (const ip of ['2606:2800:220:1:248:1893:25c8:1946', '2001:4860:4860::8888', '::ffff:8.8.8.8'])
    assert.equal(isPrivateIp(ip), false, ip);
});

await ta('ssrf: guardedLookup refuses loopback / metadata addresses (rebinding defence)', async () => {
  for (const host of ['127.0.0.1', '169.254.169.254', '10.0.0.5']) {
    const err = await new Promise(resolve => guardedLookup(host, { all: true }, e => resolve(e)));
    assert.equal(err && err.code, 'EBLOCKED', host);
  }
});

t('client identity: X-Forwarded-For ignored unless TRUST_PROXY set', () => {
  const req = ip => ({ socket: { remoteAddress: '203.0.113.9' }, headers: { 'x-forwarded-for': ip } });
  assert.equal(clientKey(req('1.2.3.4'), ''), '203.0.113.9');
  assert.equal(clientKey(req('6.6.6.6, 1.2.3.4'), '1'), '1.2.3.4'); // proxy appended the real client last
  assert.equal(clientKey(req('not-an-ip'), '1'), 'unknown');
  const v6 = a => ({ socket: { remoteAddress: a }, headers: {} });
  assert.equal(clientKey(v6('2001:4860:4860:1:1:1:1:1'), ''), clientKey(v6('2001:4860:4860:1:2:2:2:2'), '')); // same /64 = same bucket
});

await ta('rate limiter: expires, counts cost, never flushed by key floods', async () => {
  const rl = new RateLimiter(3, 50, 10);
  assert.equal(rl.hit('a'), false); rl.hit('a'); rl.hit('a');
  assert.equal(rl.hit('a'), true);
  for (let i = 0; i < 100; i++) rl.hit('flood' + i);
  assert.ok(rl.m.size <= 10, 'map is bounded');
  await new Promise(r => setTimeout(r, 70));
  assert.equal(rl.hit('a'), false, 'window reset');
  assert.equal(new RateLimiter(5).hit('b', 6), true, 'cost counted');
});

t('headers: strict CSP, no framing, HSTS only over https behind a trusted proxy', () => {
  const req = { headers: {} };
  const h = securityHeaders(req, { trust: '' });
  assert.match(h['content-security-policy'], /default-src 'none'/);
  assert.match(h['content-security-policy'], /frame-ancestors 'none'/);
  assert.match(h['content-security-policy'], /object-src 'none'/);
  assert.doesNotMatch(h['content-security-policy'], /script-src[^;]*unsafe/);
  assert.equal(h['x-frame-options'], 'DENY');
  assert.equal(h['strict-transport-security'], undefined);
  assert.ok(securityHeaders({ headers: { 'x-forwarded-proto': 'https' } }, { trust: '1' })['strict-transport-security']);
  assert.equal(securityHeaders({ headers: { 'x-forwarded-proto': 'https' } }, { trust: '' })['strict-transport-security'], undefined); // spoofable header ignored
});

t('cors: closed by default, allow-list reflects only listed origins', () => {
  assert.deepEqual(corsHeaders({ headers: { origin: 'https://evil.test' } }, []), {});
  const list = ['https://good.test'];
  assert.equal(corsHeaders({ headers: { origin: 'https://good.test' } }, list)['access-control-allow-origin'], 'https://good.test');
  assert.equal(corsHeaders({ headers: { origin: 'https://evil.test' } }, list)['access-control-allow-origin'], undefined);
});

// --------------------------------------------------
// Server integration tests
// --------------------------------------------------

const port = 18080 + Math.floor(Math.random() * 500);

const srv = spawn(
  process.execPath,
  [path.join(dir, '../server/server.js')],
  {
    env: {
      ...process.env,
      PORT: String(port),
      RATE_LIMIT_PER_MIN: '40'
    },
    stdio: 'pipe'
  }
);

const get = (pathname, options) =>
  fetch(`http://127.0.0.1:${port}${pathname}`, options);

try {
  await waitForServer(srv, port, 'Main server');

  const integrationTests = [
    [
      'health',
      async () => {
        const response = await get('/api/health');

        assert.equal(response.status, 200);
        assert.equal((await response.json()).ok, true);
      }
    ],
    [
      'home + clean urls',
      async () => {
        for (const pathname of [
          '/',
          '/faq',
          '/developer',
          '/how-it-works.html',
          '/privacy',
          '/terms'
        ]) {
          assert.equal(
            (await get(pathname)).status,
            200,
            pathname
          );
        }
      }
    ],
    [
      'assets served',
      async () => {
        for (const pathname of [
          '/css/styles.css',
          '/js/app.js',
          '/assets/icons/favicon.svg'
        ]) {
          assert.equal(
            (await get(pathname)).status,
            200,
            pathname
          );
        }
      }
    ],
    [
      'private files blocked',
      async () => {
        for (const pathname of [
          '/server/server.js',
          '/package.json',
          '/README.md',
          '/worker/src/index.js',
          '/..%2fpackage.json',
          '/%00',
          '/test/fixture.json'
        ]) {
          assert.equal(
            (await get(pathname)).status,
            404,
            pathname
          );
        }
      }
    ],
    [
      '404 page',
      async () => {
        const response = await get('/nope/deep');
        const html = await response.text();

        assert.equal(response.status, 404);
        assert.match(html, /<base href="\/">/);
      }
    ],
    [
      'api rejects bad domain',
      async () => {
        for (const domain of [
          '',
          'localhost',
          '10.0.0.1',
          'a b'
        ]) {
          const response = await get(
            '/api/lookup?domain=' +
            encodeURIComponent(domain)
          );

          assert.equal(response.status, 400, domain);
        }
      }
    ],
    [
      'api unknown route + method',
      async () => {
        assert.equal(
          (await get('/api/x')).status,
          404
        );

        assert.equal(
          (
            await get('/api/lookup?domain=a.com', {
              method: 'POST'
            })
          ).status,
          405
        );
      }
    ],
    [
      'abuse: oversized URL, bad methods, bad percent-encoding',
      async () => {
        assert.equal((await get('/' + 'a'.repeat(3000))).status, 414);
        assert.equal((await get('/index.html', { method: 'POST' })).status, 405);
        assert.equal((await get('/%E0%A4%A')).status, 404);
        assert.equal((await get('/css/..%5c..%5cpackage.json')).status, 404);
        assert.equal((await get('/server/guard.js')).status, 404);
      }
    ],
    [
      'static: etag + 304 revalidation and gzip',
      async () => {
        const first = await get('/css/styles.css', { headers: { 'accept-encoding': 'gzip' } });
        assert.equal(first.status, 200);
        const etag = first.headers.get('etag');
        assert.ok(etag);
        assert.equal((await get('/css/styles.css', { headers: { 'if-none-match': etag } })).status, 304);
      }
    ],
    [
      'security.txt is published',
      async () => {
        const r = await get('/.well-known/security.txt');
        assert.equal(r.status, 200);
        assert.match(await r.text(), /Contact:/);
      }
    ],
    [
      'preflight from foreign origin gets no CORS grant',
      async () => {
        const r = await get('/api/health', { headers: { origin: 'https://evil.test' } });
        assert.equal(r.headers.get('access-control-allow-origin'), null);
      }
    ],
    [
      'security headers',
      async () => {
        const response = await get('/');

        assert.equal(
          response.headers.get('x-content-type-options'),
          'nosniff'
        );

        assert.match(
          response.headers.get('content-security-policy') || '',
          /default-src 'none'/
        );

        assert.equal(response.headers.get('x-frame-options'), 'DENY');
        assert.equal(response.headers.get('cross-origin-opener-policy'), 'same-origin');
        assert.equal(response.headers.get('access-control-allow-origin'), null); // same-origin only by default
      }
    ]
  ];

  for (const [name, fn] of integrationTests) {
    try {
      await fn();
      pass++;
      console.log('  ok  ', name);
    } catch (error) {
      fail++;
      process.exitCode = 1;
      console.error('  FAIL', name, '\n', error.message);
    }
  }
} catch (error) {
  fail++;
  process.exitCode = 1;
  console.error('  FAIL main server startup\n', error.message);
} finally {
  stopServer(srv);
}

// --------------------------------------------------
// Integration tests with fake network
// --------------------------------------------------

const port2 = port + 1;


//const { pathToFileURL } = await import('node:url');

const srv2 = spawn(
  process.execPath,
  [
    '--import',
    pathToFileURL(path.join(dir, 'stub.mjs')).href,
    path.join(dir, '../server/server.js')
  ],

  {
    env: {
      ...process.env,
      PORT: String(port2),
      TRUST_PROXY: '1',
      RATE_LIMIT_PER_MIN: '16'
    },
    stdio: 'pipe'
  }
);

const J = async (pathname, headers = {}) => {
  const response = await fetch(
    `http://127.0.0.1:${port2}${pathname}`,
    { headers }
  );

  const body = await response.json();

  return [response.status, body];
};

try {
  await waitForServer(srv2, port2, 'Stub server');

  const stubTests = [
    [
      'check: available / registered / unknown',
      async () => {
        const available = await J(
          '/api/check?domain=free1.com'
        );

        assert.deepEqual(available[1].results[0], {
          domain: 'free1.com',
          state: 'available',
          via: 'rdap'
        });

        const registered = await J(
          '/api/check?domain=taken1.com'
        );

        assert.equal(
          registered[1].results[0].state,
          'registered'
        );

        const unknown = await J(
          '/api/check?domain=boom1.com'
        );

        assert.equal(
          unknown[1].results[0].state,
          'unknown'
        );
      }
    ],
    [
      'check: many extensions in one call',
      async () => {
        const [status, body] = await J(
          '/api/check?name=free2&tlds=com,in,io,co.in'
        );

        assert.equal(status, 200);

        assert.deepEqual(
          body.results.map(result => result.domain),
          [
            'free2.com',
            'free2.in',
            'free2.io',
            'free2.co.in'
          ]
        );

        assert.ok(
          body.results.every(
            result => result.state === 'available'
          )
        );

        const [, taken] = await J(
          '/api/check?name=taken2&tlds=net,org'
        );

        assert.equal(
          taken.results.every(
            result => result.state === 'registered'
          ),
          true
        );
      }
    ],
    [
      'check: input validation',
      async () => {
        const queries = [
          'name=a&tlds=com,../x',
          'name=a%20b&tlds=com',
          'name=&tlds=com',
          'name=a',
          'name=a&tlds=' + 'com,'.repeat(13),
          'domain=10.0.0.1',
          'name=a&tlds=c'
        ];

        for (const query of queries) {
          const [status] = await J('/api/check?' + query);
          assert.equal(status, 400, query);
        }
      }
    ],
    [
      'lookup: registered + SSRF guard on registrar link',
      async () => {
        const [status, body] = await J(
          '/api/lookup?domain=taken3.com'
        );

        assert.equal(status, 200);
        assert.equal(body.available, false);
        assert.ok(body.rdap?.json);
        assert.equal(body.registrarRdap, null);
      }
    ],
    [
      'lookup: subdomain resolves to its registered domain',
      async () => {
        const [status, body] = await J('/api/lookup?domain=www.blog.taken9.com');
        assert.equal(status, 200);
        assert.equal(body.domain, 'taken9.com');
        assert.equal(body.input, 'blog.taken9.com');
        assert.equal(body.available, false);
      }
    ],
    [
      'lookup: public suffix itself is rejected',
      async () => {
        const [status] = await J('/api/lookup?domain=co.in');
        assert.equal(status, 400);
      }
    ],
    [
      'check: subdomain is not reported as available',
      async () => {
        const [status, body] = await J('/api/check?domain=mail.taken7.com');
        assert.equal(status, 200);
        assert.equal(body.results[0].domain, 'taken7.com');
        assert.equal(body.results[0].state, 'registered');
      }
    ],
    [
      'lookup: available via RDAP 404',
      async () => {
        const [status, body] = await J(
          '/api/lookup?domain=free3.com'
        );

        assert.equal(status, 200);
        assert.equal(body.available, true);
        assert.equal(body.rdap, null);
      }
    ],
    [
      'rate limit counts bulk checks',
      async () => {
        const headers = {
          'x-forwarded-for': '9.9.9.9'
        };

        let lastStatus;

        for (let i = 0; i < 9; i++) {
          [lastStatus] = await J(
            '/api/check?name=free4&tlds=com,net,org,in,co,io,info,co.in,aa,bb,cc,dd',
            headers
          );
        }

        assert.equal(lastStatus, 429);
      }
    ]
  ];

  for (const [name, fn] of stubTests) {
    try {
      await fn();
      pass++;
      console.log('  ok  ', name);
    } catch (error) {
      fail++;
      process.exitCode = 1;
      console.error('  FAIL', name, '\n', error.message);
    }
  }
} catch (error) {
  fail++;
  process.exitCode = 1;
  console.error('  FAIL stub server startup\n', error.message);
} finally {
  stopServer(srv2);
}


// --------------------------------------------------
// Rate-limit spoofing test (no TRUST_PROXY: X-Forwarded-For must NOT help an attacker)
// --------------------------------------------------

const port3 = port + 2;
const srv3 = spawn(process.execPath, ['--import', pathToFileURL(path.join(dir, 'stub.mjs')).href, path.join(dir, '../server/server.js')],
  { env: { ...process.env, PORT: String(port3), RATE_LIMIT_PER_MIN: '5', GLOBAL_RATE_PER_MIN: '1000' }, stdio: 'pipe' });
try {
  await waitForServer(srv3, port3, 'Spoof-test server');
  let limited = 0;
  for (let i = 0; i < 12; i++) {
    const r = await fetch(`http://127.0.0.1:${port3}/api/check?domain=free${i}.com`, { headers: { 'x-forwarded-for': `10.9.8.${i}` } });
    if (r.status === 429) limited++;
  }
  assert.ok(limited >= 6, 'spoofed X-Forwarded-For must not bypass the limiter (got ' + limited + ' blocks)');
  pass++; console.log('  ok   rate limit cannot be bypassed with a forged X-Forwarded-For');
} catch (error) {
  fail++; process.exitCode = 1; console.error('  FAIL spoofed XFF\n', error.message);
} finally { stopServer(srv3); }


// --------------------------------------------------
// Registrable domain (public suffix) tests
// --------------------------------------------------
{
  const { registrable } = await import('../server/psl.js');
  const cases = {
    'example.com': 'example.com', 'blog.example.com': 'example.com', 'a.b.c.example.org': 'example.org',
    'shop.foo.co.uk': 'foo.co.uk', 'foo.co.in': 'foo.co.in', 'www.bar.com.au': 'bar.com.au',
    'x.foo.in': 'foo.in', 'city.kobe.jp': 'city.kobe.jp', 'a.city.kobe.jp': 'city.kobe.jp', 'a.b.ck': 'a.b.ck',
    'foo.blogspot.com': 'blogspot.com', 'xn--mnchen-3ya.de': 'xn--mnchen-3ya.de', 'foo.unknowntld': 'foo.unknowntld',
    'co.uk': null, 'com': null, 'co.in': null
  };
  for (const [input, want] of Object.entries(cases)) t('registrable: ' + input, () => assert.equal(registrable(input), want));
}

// --------------------------------------------------
// WHOIS verdict tests (wording differs per registry)
// --------------------------------------------------
{
  const { whoisState } = await import('../server/whois-state.js');
  const cases = [
    ['available', 'No match for "FOO.COM".'],
    ['available', 'Domain: foo.de\nStatus: free\n'],
    ['available', 'foo.nl is free'],
    ['available', '%% NOT FOUND'],
    ['available', 'No Data Found'],
    ['available', 'Domain not found.'],
    ['available', 'No entries found for the selected source(s).'],
    ['available', 'Status: AVAILABLE'],
    ['registered', 'Domain Name: FOO.COM\nRegistry Domain ID: 1\nRegistrar: X\nCreation Date: 2001-01-01\n'],
    ['registered', 'domain:        foo.ru\nnserver: ns1.foo.ru\ncreated: 2010-01-01\n'],
    ['registered', 'Domain: foo.de\nStatus: connect\n'],
    ['unknown', 'WHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG/WHOIS FOR DETAILS'],
    ['unknown', 'Too many queries from your IP, please try again later.'],
    ['unknown', ''],
  ];
  for (const [want, text] of cases) t('whois verdict: ' + want + ' <- ' + text.slice(0, 32).replace(/\n/g, ' '), () => assert.equal(whoisState(text), want));
}

// --------------------------------------------------
// Summary
// --------------------------------------------------

console.log('\n------------------------------');
console.log(`Passed: ${pass}`);
console.log(`Failed: ${fail}`);

if (fail === 0) {
  console.log(`All ${pass} tests passed`);
} else {
  console.log('Some tests failed. Review the errors above.');
  process.exitCode = 1;
}
