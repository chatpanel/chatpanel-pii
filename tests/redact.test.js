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

// A citation survives redaction — the three ways it did not (2026-09-19, a WSJ/Reuters page in
// the panel): an entity matched case-insensitively inside a URL and restored to its canonical
// case (`…-wsj-reports-…` → `…-WSJ-reports-…`, a dead link); a link bracket glued to a token
// (`[[[ORG_1]] Quiz](url)`) echoed by the model as if it were the token, and the extra `[`
// left in front of a word or inside a URL; an ISO date in a path taken for a phone.
test('an entity inside a URL restores with the case it had; a date in a path is not a phone', () => {
  const vault = createVault();
  const src = 'See [Gemini hacked | Reuters](https://www.reuters.com/business/gemini-by-google-ai-wsj-reports-2026-09-18/) and WSJ says so; call +1 (415) 555-0100.';
  const red = redactText(src, vault, { tier: 'full', entities: [{ value: 'WSJ', type: 'ORG' }, { value: 'Google', type: 'ORG' }] });
  assert.doesNotMatch(red, /wsj|WSJ|google/i, 'both casings are redacted');
  assert.match(red, /2026-09-18/, 'an ISO date is not a phone number');
  assert.match(red, /\[\[PHONE_1\]\]/, 'a phone still is');
  assert.equal(restoreText(red, vault), src, 'byte-for-byte, so the link works');
  assert.notEqual(vault.byValue.get('wsj'), vault.byValue.get('WSJ'), 'a different casing is its own token, never restored to the other');
});

test('a bracket the model echoed from `[[[TOKEN]]` is dropped; one that is markdown\'s is kept', () => {
  const vault = createVault();
  const t = (value, type = 'ORG') => { redactText(value, vault, { tier: 'full', entities: [{ value, type }] }); return vault.byValue.get(value); };
  const news = t('news'); const wsj = t('wsj'); const google = t('Google'); const News = t('News'); const WSJ = t('WSJ');
  const model = `Today's [${news} on [${WSJ}: see ([2](https://www.reuters.com/business/gemini-by-${google}-ai-[${wsj}-reports-2026-09-18/)) and www.[${wsj}.com and **[${google}'s response:** — [${News} Print Edition](https://x) and [${News} and ${WSJ}](https://y) and [see ${WSJ}](z).`;
  assert.equal(restoreText(model, vault),
    "Today's news on WSJ: see ([2](https://www.reuters.com/business/gemini-by-Google-ai-wsj-reports-2026-09-18/)) and www.wsj.com and **Google's response:** — [News Print Edition](https://x) and [News and WSJ](https://y) and [see WSJ](z).");
  // The one- and no-bracket forms a small model emits still restore (unchanged behaviour).
  assert.equal(restoreText(`${WSJ.slice(1, -1)} and ${WSJ.slice(2, -2)}`, vault), 'WSJ and WSJ');
});

// ── An unresolvable placeholder is a word, not machine syntax ────────────────
//
// The vault is in memory, so this is not rare: a reply rendered after a reload, a model
// echoing a token shape it was taught, a placeholder minted in a turn whose vault is gone.
// It used to be shown as itself, and a reader got "[[PERSON_1]] (the Ms Graph MCP server)"
// in the middle of an answer — unreadable, and alarming in a product whose whole claim is
// that it handles personal data carefully.
test('scrubPlaceholders resolves what it can and renders the rest readably', async () => {
  const { scrubPlaceholders } = await import('../pii-redact.js');
  const vault = createVault();
  vault.byToken.set('[[PERSON_2]]', 'Alex Rivera');

  const { text, unresolved } = scrubPlaceholders(
    '[[PERSON_1]] met [[PERSON_2]] about [[EMAIL_9]] on [[PHONE_3]]', vault,
  );
  // What was known restores exactly.
  assert.match(text, /met Alex Rivera about/);
  // What was not reads as a word, and the machine syntax is gone entirely.
  assert.equal(text, 'someone met Alex Rivera about an email address on a phone number');
  assert.doesNotMatch(text, /\[\[/, 'no reader ever sees a placeholder');

  // The report is what tells us a path is leaking — that was the reason for showing the
  // raw token, and it is kept.
  assert.deepEqual(unresolved, ['[[PERSON_1]]', '[[EMAIL_9]]', '[[PHONE_3]]']);

  // A type we have no word for still does not leak its shape.
  assert.equal(scrubPlaceholders('[[WIDGET_4]]', vault).text, 'redacted');
  // Nothing to do is nothing done.
  assert.deepEqual(scrubPlaceholders('', vault), { text: '', unresolved: [] });
  assert.equal(scrubPlaceholders('plain text', vault).text, 'plain text');
  // No vault at all: everything is unresolvable, and everything is still readable.
  assert.equal(scrubPlaceholders('[[PERSON_1]]', null).text, 'someone');
});

// ── A STRUCTURED MATCH OUTRANKS A STATISTICAL ONE ───────────────────────────
//
// Entities used to be substituted before the deterministic detectors had looked at the text,
// so a name the model found INSIDE a structured value destroyed it. Found on 2026-09-24 in
// the shipping extension (providers.js feeds NER output straight into redactOutbound): a
// user typing an email at full tier sent `[[PER_1]]@example.com` upstream — the address
// never tokenized, the domain in the clear, and with real NER spans the message text
// mangled as well. The detectors claim their spans first now.

test('a PERSON span inside an email does not break the email', () => {
  const v = createVault();
  const src = 'look up alex@example.com';
  const out = redactText(src, v, { tier: 'full', entities: [{ value: 'alex', type: 'PER' }] });
  assert.match(out, /\[\[EMAIL_1\]\]/, 'the whole address is one token');
  assert.doesNotMatch(out, /PER_/, 'the name inside it is not claimed separately');
  assert.doesNotMatch(out, /example\.com/, 'and the domain never goes out in the clear');
  assert.equal(restoreText(out, v), src, 'byte-for-byte');
});

test('a sloppy NER span across whitespace cannot mangle two addresses', () => {
  // Real ner-engine output for this sentence: it merged "com and mail jordan" into one ORG.
  const v = createVault();
  const src = 'look up alex@example.com and mail jordan@corp.example';
  const out = redactText(src, v, {
    tier: 'full',
    entities: [{ value: 'alex', type: 'PER' }, { value: 'com and mail jordan', type: 'ORG' }, { value: 'corp', type: 'ORG' }],
  });
  assert.equal(out, 'look up [[EMAIL_1]] and mail [[EMAIL_2]]');
  assert.equal(restoreText(out, v), src, 'byte-for-byte — the sentence is not rewritten');
});

test('the same rule protects a phone and a card from a name-shaped span', () => {
  const v = createVault();
  const src = 'call +1 (415) 555-0100 or charge 4111 1111 1111 1111';
  const out = redactText(src, v, { tier: 'full', entities: [{ value: '415', type: 'ORG' }, { value: '1111', type: 'ORG' }] });
  assert.match(out, /\[\[PHONE_1\]\]/);
  assert.match(out, /\[\[CARD_1\]\]/);
  assert.doesNotMatch(out, /ORG_/, 'neither digit run is carved out of the value around it');
  assert.equal(restoreText(out, v), src);
});

test('an entity that overlaps NOTHING structured is redacted exactly as before', () => {
  const v = createVault();
  const src = 'Alex Rivera works at Microsoft with Alex';
  const out = redactText(src, v, {
    tier: 'full',
    entities: [{ value: 'Alex Rivera', type: 'PERSON' }, { value: 'Microsoft', type: 'ORG' }, { value: 'Alex', type: 'PERSON' }],
  });
  assert.doesNotMatch(out, /Rivera|Microsoft/, 'the names are gone');
  // Longest-first still wins: "Alex Rivera" is one token, the trailing bare "Alex" another.
  assert.match(out, /\[\[PERSON_1\]\] works at \[\[ORG_1\]\] with \[\[PERSON_2\]\]/);
  assert.equal(restoreText(out, v), src);
});
