// The assistant's own name is not the person's data. A detector reads "chap" as a person and
// "chatpanel" as an organisation; a detected value is replaced everywhere, including the system
// text this product writes — so a relayed agent was told "The [[PERSON_3]] tools above are
// authoritative" and searched the web for "[[PERSON_1]] by [[ORG_3]]" (2026-10-02).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeEntities, ownName } from '../pii-detect.js';
import { redactOutbound } from '../pipeline.js';
import { createVault } from '../pii-redact.js';

// What the bundled detector returned for the reported message and for the page's title.
const SPANS = { entities: [
  { word: 'chap', entity_group: 'PER' }, { word: 'chatpanel', entity_group: 'PER' },
  { word: 'Chap', entity_group: 'ORG' }, { word: 'ChatPanel', entity_group: 'ORG' },
  { word: 'Chap by ChatPanel', entity_group: 'ORG' },
  { word: 'Jordan Blake', entity_group: 'PER' }, { word: 'Acme Robotics', entity_group: 'ORG' },
] };

test('a span made of the assistant\'s own names is not an entity — at either strictness', () => {
  for (const strictness of ['balanced', 'strict']) {
    assert.deepEqual(normalizeEntities(SPANS, null, { strictness }).map((e) => e.value), ['Jordan Blake', 'Acme Robotics'], strictness);
  }
});

test('only the name alone: a person or a company that merely holds the word stays', () => {
  for (const v of ['chap', 'Chap', 'CHATPANEL', 'Chap by ChatPanel', 'hey chap', 'Chap, ChatPanel']) assert.equal(ownName(v), true, v);
  for (const v of ['Chap Singh', 'Chapman', 'ChatPanel Labs GmbH', 'by', 'hey', '', 'Jordan Blake']) assert.equal(ownName(v), false, v);
  const kept = normalizeEntities({ entities: [{ word: 'Chap Singh', entity_group: 'PER' }, { word: 'ChatPanel Labs GmbH', entity_group: 'ORG' }] });
  assert.deepEqual(kept.map((e) => e.value), ['Chap Singh', 'ChatPanel Labs GmbH']);
});

test('the reported turn: the request and the product\'s own system text go out as written', () => {
  const vault = createVault();
  const cfg = { mode: 'model', tier: 'full' };
  const system = 'The Chap tools above are authoritative for what only Chap can reach.';
  const text = 'open new tab and search for chap by chatpanel, then mail Jordan Blake';
  const red = redactOutbound({ messages: [{ role: 'user', content: text }], system, vault, cfg, isPro: true, entities: normalizeEntities(SPANS) });
  assert.equal(red.system, system);
  assert.match(red.messages[0].content, /^open new tab and search for chap by chatpanel, then mail \[\[PERSON_\d+\]\]$/);
});

test('a person who wants the word hidden says so in their dictionary, and that still holds', () => {
  const vault = createVault();
  const cfg = { mode: 'model', tier: 'full', dictionary: [{ value: 'chap', type: 'PERSON' }] };
  const red = redactOutbound({ messages: [{ role: 'user', content: 'ask chap about it' }], vault, cfg, isPro: true, entities: normalizeEntities(SPANS) });
  assert.doesNotMatch(red.messages[0].content, /chap/);
});
