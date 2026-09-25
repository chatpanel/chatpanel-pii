// The guard must answer about the ADDRESS, never about the spelling.
//
// This file exists because tests/net.test.js did not. Every case there was a dotted quad —
// 169.254.169.254, 127.0.0.1, 10.0.0.5 — so the suite asked only the questions the author had
// already answered in the code, passed 93/93, and shipped a classifier that read
// `::ffff:a9fe:a9fe` (the AWS IMDS credential endpoint, as a dual-stack socket resolves it) as
// an ordinary public website. An example-based test proves the examples; it cannot prove the
// rule. So this one generates the spellings instead of listing them.
//
// The invariant, one line: two strings that name the SAME address must get the SAME verdict
// from every classifier. Add a spelling to SPELLINGS and every address is re-checked in it;
// add an address to ADDRESSES and every spelling is re-checked against it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isLoopbackHost, isMetadataHost, isPrivateHost, isBlockedHost, assertFetchableUrl } from '../net.js';

const hex = ([a, b, c, d]) => `${(((a << 8) | b) >>> 0).toString(16)}:${(((c << 8) | d) >>> 0).toString(16)}`;
const octets = (v4) => v4.split('.').map(Number);

// Every way of writing an IPv4 address that a socket still routes to that same IPv4 host.
// `id` is what a failure prints, so it names the shape rather than the example.
const SPELLINGS = [
  { id: 'dotted',                  of: (v4) => v4 },
  { id: 'v6-mapped dotted',        of: (v4) => `::ffff:${v4}` },
  { id: 'v6-mapped hex',           of: (v4) => `::ffff:${hex(octets(v4))}` },
  { id: 'v6-mapped hex UPPER',     of: (v4) => `::FFFF:${hex(octets(v4)).toUpperCase()}` },
  { id: 'v6-mapped uncompressed',  of: (v4) => `0:0:0:0:0:ffff:${hex(octets(v4))}` },
  { id: 'v6-mapped bracketed',     of: (v4) => `[::ffff:${hex(octets(v4))}]` },
];

// `why` is the property under test, not a label: it is what the address IS.
const ADDRESSES = [
  { v4: '169.254.169.254',  why: 'AWS/GCP/Azure/DO instance metadata', metadata: true,  loopback: false, private: true  },
  { v4: '100.100.100.200',  why: 'Alibaba instance metadata',          metadata: true,  loopback: false, private: true  },
  { v4: '127.0.0.1',        why: 'loopback',                           metadata: false, loopback: true,  private: false },
  { v4: '127.0.0.53',       why: 'loopback (not just .1)',             metadata: false, loopback: true,  private: false },
  { v4: '10.0.0.5',         why: 'RFC1918',                            metadata: false, loopback: false, private: true  },
  { v4: '192.168.1.1',      why: 'RFC1918',                            metadata: false, loopback: false, private: true  },
  { v4: '172.16.0.1',       why: 'RFC1918',                            metadata: false, loopback: false, private: true  },
  { v4: '100.64.0.1',       why: 'CGNAT',                              metadata: false, loopback: false, private: true  },
  { v4: '8.8.8.8',          why: 'a genuinely public host',            metadata: false, loopback: false, private: false },
  { v4: '1.1.1.1',          why: 'a genuinely public host',            metadata: false, loopback: false, private: false },
];

test('an address classifies the same however it is spelled', () => {
  for (const a of ADDRESSES) {
    for (const s of SPELLINGS) {
      const h = s.of(a.v4);
      const at = `${a.v4} (${a.why}) written as ${s.id}: ${h}`;
      assert.equal(isMetadataHost(h), a.metadata, `isMetadataHost — ${at}`);
      assert.equal(isLoopbackHost(h), a.loopback, `isLoopbackHost — ${at}`);
      assert.equal(isPrivateHost(h), a.private, `isPrivateHost — ${at}`);
    }
  }
});

// The two policies the product actually ships: a model/API endpoint (loopback + LAN are
// legitimate, metadata never) and a web-page fetch (genuinely public only).
test('both shipped policies decide on the address, not the spelling', () => {
  const ENDPOINT = { allowLoopback: true, allowPrivate: true };
  const WEB = { allowLoopback: false, allowPrivate: false };
  for (const a of ADDRESSES) {
    const blockedEndpoint = a.metadata;                       // only metadata is refused here
    const blockedWeb = a.metadata || a.loopback || a.private;  // anything not public is refused
    for (const s of SPELLINGS) {
      const h = s.of(a.v4);
      const at = `${a.v4} (${a.why}) as ${s.id}`;
      assert.equal(isBlockedHost(h, ENDPOINT), blockedEndpoint, `endpoint policy — ${at}`);
      assert.equal(isBlockedHost(h, WEB), blockedWeb, `web policy — ${at}`);
    }
  }
});

// The URL parser rewrites a host before the guard ever sees it — [::ffff:169.254.169.254]
// arrives as [::ffff:a9fe:a9fe] — so a classifier that is right about a bare string can still
// be wrong about a URL. Assert the whole path, which is what callers actually use.
test('assertFetchableUrl agrees with the classifier after URL normalization', () => {
  const ENDPOINT = { allowLoopback: true, allowPrivate: true };
  const WEB = { allowLoopback: false, allowPrivate: false };
  for (const a of ADDRESSES) {
    for (const s of SPELLINGS) {
      const host = s.of(a.v4);
      const url = host.includes(':') ? `http://[${host.replace(/^\[|\]$/g, '')}]/p` : `http://${host}/p`;
      for (const [name, policy] of [['endpoint', ENDPOINT], ['web', WEB]]) {
        const viaUrl = (() => { try { assertFetchableUrl(url, policy); return false; } catch { return true; } })();
        assert.equal(viaUrl, isBlockedHost(host, policy),
          `${name} policy disagrees between the URL and the host for ${a.v4} as ${s.id} (${url})`);
      }
    }
  }
});

// The bug had a mirror image: the v6 rules were startsWith() on the hostname, so real domains
// beginning fc/fd/fe8-feb were refused as IPv6 ULAs and could not be fetched at all. A guard
// that blocks the wrong thing is a bug report too — it just arrives as "your app is broken".
test('a domain is never mistaken for an address', () => {
  const domains = [
    'fdic.gov', 'fcc.gov', 'fda.gov', 'fc-barcelona.com', 'feast.org', 'february.example',
    'fe80.example.com', 'example.com', 'api.openai.com', 'localhost.evil.com', '10.0.0.5.example.com',
  ];
  for (const d of domains) {
    assert.equal(isPrivateHost(d), false, `${d} is a domain, not a private range`);
    assert.equal(isMetadataHost(d), false, `${d} is a domain, not metadata`);
    assert.equal(isBlockedHost(d, { allowLoopback: false, allowPrivate: false }), false, `${d} must stay fetchable`);
  }
});

// A malformed literal must fail CLOSED. Anything unparseable is refused rather than falling
// through to "not matched, therefore public".
test('malformed and hostile literals fail closed', () => {
  const WEB = { allowLoopback: false, allowPrivate: false };
  for (const h of ['', '   ', null, undefined]) {
    assert.equal(isBlockedHost(h, WEB), true, `${JSON.stringify(h)} must be refused`);
  }
  for (const u of ['file:///etc/passwd', 'gopher://x', 'javascript:alert(1)', 'not a url', 'http://']) {
    assert.throws(() => assertFetchableUrl(u, WEB), `${u} must throw`);
  }
});
