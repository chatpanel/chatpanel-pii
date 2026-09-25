import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isLoopbackHost, isMetadataHost, isPrivateHost, isBlockedHost,
  assertEndpointUrl, assertPublicWebUrl,
} from '../net.js';

test('classifiers: loopback / metadata / private', () => {
  assert.equal(isLoopbackHost('127.0.0.1'), true);
  assert.equal(isLoopbackHost('localhost'), true);
  assert.equal(isLoopbackHost('foo.localhost'), true);
  assert.equal(isLoopbackHost('::1'), true);
  assert.equal(isLoopbackHost('8.8.8.8'), false);

  assert.equal(isMetadataHost('169.254.169.254'), true);
  assert.equal(isMetadataHost('100.100.100.200'), true); // Alibaba IMDS
  assert.equal(isMetadataHost('metadata.google.internal'), true);
  assert.equal(isMetadataHost('8.8.8.8'), false);

  assert.equal(isPrivateHost('10.0.0.5'), true);
  assert.equal(isPrivateHost('192.168.1.1'), true);
  assert.equal(isPrivateHost('172.16.0.1'), true);
  assert.equal(isPrivateHost('fd00::1'), true);
  assert.equal(isPrivateHost('printer.local'), true);
  assert.equal(isPrivateHost('8.8.8.8'), false);
});

test('endpoint policy: loopback + LAN allowed, metadata + bad scheme never', () => {
  // gateway model endpoints — the common BYO-local cases must pass
  assert.doesNotThrow(() => assertEndpointUrl('http://127.0.0.1:11434/v1')); // Ollama
  assert.doesNotThrow(() => assertEndpointUrl('http://192.168.1.50:1234'));  // homelab LAN
  assert.doesNotThrow(() => assertEndpointUrl('https://api.openai.com'));     // public

  // …but the metadata pivot is blocked even though it's link-local "private"
  assert.throws(() => assertEndpointUrl('http://169.254.169.254/latest/meta-data/'), /blocked address/);
  assert.throws(() => assertEndpointUrl('http://metadata.google.internal/'), /blocked address/);
  assert.throws(() => assertEndpointUrl('file:///etc/passwd'), /only http/);
  assert.throws(() => assertEndpointUrl('gopher://x'), /only http/);
  assert.throws(() => assertEndpointUrl('not a url'), /invalid URL/);
});

test('web-page policy: no loopback, no private, no metadata', () => {
  assert.doesNotThrow(() => assertPublicWebUrl('https://example.com/page'));
  assert.throws(() => assertPublicWebUrl('http://127.0.0.1/admin'), /blocked address/);
  assert.throws(() => assertPublicWebUrl('http://10.0.0.1/'), /blocked address/);
  assert.throws(() => assertPublicWebUrl('http://169.254.169.254/'), /blocked address/);
});

test('isBlockedHost policy knobs', () => {
  assert.equal(isBlockedHost('127.0.0.1', { allowLoopback: true }), false);
  assert.equal(isBlockedHost('127.0.0.1', { allowLoopback: false }), true);
  assert.equal(isBlockedHost('10.0.0.1', { allowPrivate: true }), false);
  assert.equal(isBlockedHost('10.0.0.1', { allowPrivate: false }), true);
  assert.equal(isBlockedHost('169.254.169.254', { allowPrivate: true }), true); // metadata overrides
});

// An IPv4-mapped IPv6 literal is the SAME host as its dotted form — and a dual-stack
// socket really does connect [::ffff:a9fe:a9fe] to 169.254.169.254. Reported against
// 0.11.1, where the classifier matched on the spelling and let the IMDS pivot through
// in every context. Note the URL parser rewrites the dotted form to hex, so the hex
// spelling is the one that actually reaches the guard.
test('IPv4-mapped IPv6 is classified as the IPv4 address it reaches', () => {
  for (const h of ['::ffff:169.254.169.254', '::ffff:a9fe:a9fe', '[::ffff:a9fe:a9fe]']) {
    assert.equal(isMetadataHost(h), true, `${h} is IMDS`);
    assert.equal(isBlockedHost(h, { allowLoopback: true, allowPrivate: true }), true, `${h} blocked in the endpoint context`);
  }
  assert.equal(isMetadataHost('::ffff:100.100.100.200'), true);   // Alibaba IMDS, mapped
  assert.equal(isLoopbackHost('::ffff:127.0.0.1'), true);
  assert.equal(isLoopbackHost('::ffff:7f00:1'), true);            // same host, hex spelling
  assert.equal(isPrivateHost('::ffff:10.0.0.1'), true);
  assert.equal(isPrivateHost('::ffff:192.168.1.1'), true);

  // …and the mapped form of a PUBLIC address stays public.
  assert.equal(isBlockedHost('::ffff:8.8.8.8', { allowLoopback: false, allowPrivate: false }), false);

  assert.throws(() => assertEndpointUrl('http://[::ffff:169.254.169.254]/latest/meta-data/iam/security-credentials/'), /blocked address/);
  assert.throws(() => assertPublicWebUrl('http://[::ffff:127.0.0.1]/admin'), /blocked address/);
});

// AWS's IPv6 IMDS sits inside the ULA range, so the private rule caught it in the web
// context but the endpoint context (where LAN is allowed) let it through — even though
// metadata is meant to be blocked "never, in any context".
test('AWS IPv6 IMDS is metadata, not merely private', () => {
  assert.equal(isMetadataHost('fd00:ec2::254'), true);
  assert.equal(isMetadataHost('fd00:0ec2:0:0:0:0:0:254'), true);
  assert.throws(() => assertEndpointUrl('http://[fd00:ec2::254]/latest/meta-data/'), /blocked address/);
  assert.equal(isMetadataHost('fd00:ec2::255'), false);           // a neighbouring ULA host is not IMDS
  assert.equal(isPrivateHost('fd00:ec2::255'), true);             // …but it is still private
});

// The v6 rules used to be startsWith() on the hostname STRING, so any domain beginning
// "fc"/"fd"/"fe8".."feb" was refused as a ULA. These are real public sites.
test('public domains are not mistaken for IPv6 ranges', () => {
  for (const h of ['fdic.gov', 'fcc.gov', 'fda.gov', 'fc-barcelona.com', 'feast.org']) {
    assert.equal(isPrivateHost(h), false, `${h} is a public domain`);
    assert.doesNotThrow(() => assertPublicWebUrl(`https://${h}/`), `${h} must be fetchable`);
  }
});

// Compressed / expanded spellings of the same v6 address must classify alike, and a
// malformed literal must not parse into something that looks public.
test('IPv6 spellings and malformed literals', () => {
  assert.equal(isLoopbackHost('0:0:0:0:0:0:0:1'), true);
  assert.equal(isPrivateHost('fe80::1'), true);
  assert.equal(isPrivateHost('fec0::1'), true);                   // site-local, deprecated
  assert.equal(isPrivateHost('64:ff9b::a9fe:a9fe'), true);        // NAT64 onto a v4 target
  assert.equal(isPrivateHost('::'), true);
  assert.equal(isPrivateHost('2001:4860:4860::8888'), false);     // public v6 resolver
  assert.equal(isBlockedHost('', { allowLoopback: true, allowPrivate: true }), true); // fail closed
});
