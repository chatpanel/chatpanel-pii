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
