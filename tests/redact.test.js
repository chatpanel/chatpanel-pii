import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createVault, redactText, redactResultShape, restoreText } from '../pii-redact.js';
import { makeToolHarness } from '../tool-harness.js';

const ZWSP = String.fromCharCode(0x200B); // zero-width space (code point, not a literal invisible)

// ── H1: redactText de-steganizes BEFORE detection, in-band ──────────────────
test('H1: zero-width-split email is redacted by redactText itself', () => {
  const v = createVault();
  const out = redactText(`email jo${ZWSP}hn@example.com now`, v);
  assert.match(out, /\[\[EMAIL_1\]\]/);
  assert.doesNotMatch(out, /john@example\.com/);
  // stored (sanitized) value round-trips
  assert.equal(restoreText('[[EMAIL_1]]', v), 'john@example.com');
});

test('H1: Tag-block ASCII smuggling is stripped before the model sees it', () => {
  // U+E0041 is a Tag "A" — renders invisible, encodes ASCII. Must not survive.
  const smuggled = 'hello\u{E0041}\u{E0042}';
  const out = redactText(smuggled, createVault());
  assert.equal(out, 'hello');
});

test('H1: sanitize:false is an escape hatch (obfuscated PII stays unmatched)', () => {
  // Splitting the domain defeats the whole email match when sanitize is off…
  const raw = `john@exa${ZWSP}mple.com`;
  assert.doesNotMatch(redactText(raw, createVault(), { sanitize: false }), /\[\[EMAIL/);
  // …but the default (sanitize on) catches it.
  assert.match(redactText(raw, createVault()), /\[\[EMAIL_1\]\]/);
});

// ── Baseline deterministic-detector coverage (was untested) ─────────────────
test('deterministic detectors: email/ssn/key/ip/card(Luhn)', () => {
  assert.match(redactText('reach a@b.com', createVault()), /\[\[EMAIL_1\]\]/);
  assert.match(redactText('ssn 123-45-6789', createVault()), /\[\[SSN_1\]\]/);
  assert.match(redactText('token sk-abcdefghijklmnop0123', createVault()), /\[\[KEY_1\]\]/);
  assert.match(redactText('host 10.0.0.5', createVault()), /\[\[IP_1\]\]/);
  assert.match(redactText('card 4111 1111 1111 1111', createVault()), /\[\[CARD_1\]\]/); // valid Luhn
});

test('CARD detector rejects a non-Luhn number (no false positive)', () => {
  assert.doesNotMatch(redactText('card 1234 5678 9012 3456', createVault()), /\[\[CARD/);
});

test('stable, value-deduped tokens across turns', () => {
  const v = createVault();
  redactText('a@b.com', v);
  const second = redactText('again a@b.com', v);
  assert.match(second, /\[\[EMAIL_1\]\]/); // same value → same token, not EMAIL_2
});

// ── H5: tool-result re-redaction walks the MCP content[] shape ───────────────
function orgVault() {
  const v = createVault();
  redactText('I am at Microsoft', v, { tier: 'full', entities: [{ value: 'Microsoft', type: 'ORG' }] });
  return v;
}
const ORG_OPTS = { tier: 'full', entities: [{ value: 'Microsoft', type: 'ORG' }] };

test('H5: redactResultShape redacts { content:[{text}] } (MCP standard)', () => {
  const v = orgVault();
  const red = redactResultShape(
    { content: [{ type: 'text', text: 'Microsoft closed at $372' }], isError: false },
    v, ORG_OPTS,
  );
  assert.match(red.content[0].text, /\[\[ORG_1\]\]/);
  assert.doesNotMatch(red.content[0].text, /Microsoft/);
  assert.equal(red.isError, false); // non-text fields preserved
});

test('H5: redactResultShape redacts an embedded { resource:{text} }', () => {
  const v = orgVault();
  const red = redactResultShape(
    { content: [{ type: 'resource', resource: { uri: 'x://1', text: 'Microsoft memo' } }] },
    v, ORG_OPTS,
  );
  assert.match(red.content[0].resource.text, /\[\[ORG_1\]\]/);
  assert.equal(red.content[0].resource.uri, 'x://1'); // uri untouched
});

test('H5: harness ③ re-redacts a content[] tool result before the model', () => {
  const h = makeToolHarness({ vault: orgVault(), toolData: 'real', redactOpts: ORG_OPTS });
  const red = h.toModelResult('mcp_wiki__search', { content: [{ type: 'text', text: 'Microsoft up' }] });
  assert.match(red.content[0].text, /\[\[ORG_1\]\]/);
  assert.doesNotMatch(red.content[0].text, /Microsoft/);
});
