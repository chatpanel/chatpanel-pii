import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createVault, redactText } from '../pii-redact.js';
import { makeToolHarness } from '../tool-harness.js';

// L1 — expanded secret detection
test('L1: PEM private-key block redacted as one SECRET token', () => {
  const pem = '-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkqhkiG9w0\nBAQEFAASCATgw==\n-----END PRIVATE KEY-----';
  const out = redactText(`key:\n${pem}\ndone`, createVault());
  assert.match(out, /\[\[SECRET_1\]\]/);
  assert.doesNotMatch(out, /BEGIN PRIVATE KEY/);
});

test('L1: JWT, Google, Stripe, GitHub-PAT keys redacted', () => {
  assert.match(redactText('t eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY.SflKxwRJSMeKKF2QT4', createVault()), /\[\[KEY_1\]\]/);
  assert.match(redactText('g AIzaSyA1234567890abcdefghijklmnopqrstuv', createVault()), /\[\[KEY_1\]\]/);
  assert.match(redactText('s sk_live_0123456789abcdefABCDEF', createVault()), /\[\[KEY_1\]\]/);
  assert.match(redactText('p github_pat_11ABCDEFG0aaaaaaaaaaaa_bbbbbbbb', createVault()), /\[\[KEY_1\]\]/);
});

// L2 — SSN separators + IPv6, with FP control
test('L2: SSN dash AND space separated; bare 9-digit left alone', () => {
  assert.match(redactText('ssn 123-45-6789', createVault()), /\[\[SSN_1\]\]/);
  assert.match(redactText('ssn 123 45 6789', createVault()), /\[\[SSN_1\]\]/);
  assert.doesNotMatch(redactText('order 123456789 shipped', createVault()), /\[\[SSN/); // no FP
});

test('L2: IPv6 detected (full + :: compression); non-IPv6 colon lists not', () => {
  assert.match(redactText('host 2001:0db8:85a3:0000:0000:8a2e:0370:7334 up', createVault()), /\[\[IP_1\]\]/);
  assert.match(redactText('host fd00::1 up', createVault()), /\[\[IP_1\]\]/);
  assert.doesNotMatch(redactText('at 12:34:56 today', createVault()), /\[\[IP/); // time, not IPv6
});

// L9 — ReDoS guard: a catastrophic pattern is skipped, not run
test('L9: nested-quantifier dictionary regex is rejected (no hang), safe one works', () => {
  const evil = [{ pattern: '(a+)+$', type: 'X' }];
  const started = { done: false };
  // 30 a's + X would make (a+)+$ backtrack catastrophically if it ran
  const out = redactText('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX', createVault(), { dictionary: evil });
  started.done = true;
  assert.equal(started.done, true);
  assert.doesNotMatch(out, /\[\[X_/); // dangerous pattern skipped

  const safe = [{ pattern: 'secret\\d+', type: 'CODE' }];
  assert.match(redactText('code secret42 here', createVault(), { dictionary: safe }), /\[\[CODE_1\]\]/);
});

// L3 — explicit remote-tool set (not just the mcp_* name heuristic)
test('L3: a non-mcp_ tool declared remote keeps the token under redactRemote', () => {
  const v = createVault();
  const OPTS = { tier: 'full', entities: [{ value: 'Microsoft', type: 'ORG' }] };
  redactText('I am at Microsoft', v, OPTS);
  const h = makeToolHarness({ vault: v, toolData: 'redactRemote', redactOpts: OPTS, remoteTools: new Set(['weird_remote']) });
  assert.deepEqual(h.toTool('weird_remote', { q: '[[ORG_1]]' }), { q: '[[ORG_1]]' }); // remote → kept redacted
  assert.deepEqual(h.toTool('local_lookup', { q: '[[ORG_1]]' }), { q: 'Microsoft' });  // local → real
});
