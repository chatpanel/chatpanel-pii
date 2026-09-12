import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createVault, redactText } from '../pii-redact.js';
import { makeToolHarness, placeholderToolNote } from '../tool-harness.js';

function vaultWith() {
  const v = createVault();
  // Microsoft → [[ORG_1]] (reversible), John → Twinkle (pseudonym alias)
  redactText('I am at Microsoft', v, { tier: 'full', entities: [{ value: 'Microsoft', type: 'ORG' }] });
  redactText('I am John', v, { tier: 'basic', dictionary: [{ value: 'John', alias: 'Twinkle' }] });
  return v;
}
const OPTS = { tier: 'full', entities: [{ value: 'Microsoft', type: 'ORG' }], dictionary: [{ value: 'John', alias: 'Twinkle' }] };

test('privacy ON: tool gets REAL values (tokens + pseudonyms undone)', () => {
  const h = makeToolHarness({ vault: vaultWith(), toolData: 'real', redactOpts: OPTS });
  assert.deepEqual(h.toTool('mcp_wiki__search', { q: '[[ORG_1]] stock' }), { q: 'Microsoft stock' });
  assert.deepEqual(h.toTool('history_search', { q: 'Twinkle' }), { q: 'John' }); // pseudonym → real for tools
});

test('privacy ON + redact-remote: remote MCP tool keeps the redacted token; local stays real', () => {
  const h = makeToolHarness({ vault: vaultWith(), toolData: 'redactRemote', redactOpts: OPTS });
  assert.deepEqual(h.toTool('mcp_wiki__search', { q: '[[ORG_1]] stock' }), { q: '[[ORG_1]] stock' }); // kept redacted
  assert.deepEqual(h.toTool('history_search', { q: '[[ORG_1]]' }), { q: 'Microsoft' });                // local → real
});

test('③ result is re-redacted before the model sees it; ④ reply restored for the user', () => {
  const h = makeToolHarness({ vault: vaultWith(), toolData: 'real', redactOpts: OPTS });
  assert.match(h.toModelResult('mcp_wiki__search', 'Microsoft closed at $372'), /\[\[ORG_1\]\]/);
  assert.doesNotMatch(h.toModelResult('mcp_wiki__search', 'Microsoft closed at $372'), /Microsoft/);
  assert.equal(h.toUser('[[ORG_1]] looks strong'), 'Microsoft looks strong');
});

test('privacy OFF (no vault): ②③④ pass through unchanged, but ⓪ selectTools STILL narrows', () => {
  const h = makeToolHarness({ vault: null });
  assert.equal(h.enabled, false);
  assert.deepEqual(h.toTool('mcp_wiki__search', { q: 'Microsoft' }), { q: 'Microsoft' }); // unchanged
  assert.equal(h.toModelResult('x', 'Microsoft $372'), 'Microsoft $372');                  // unchanged
  assert.equal(h.toUser('hi Microsoft'), 'hi Microsoft');                                  // unchanged
  const specs = [
    { name: 'mcp_wiki__search', description: 'search wikipedia' },
    { name: 'mcp_hn__search', description: 'search hacker news' },
    { name: 'mcp_jira__search', description: 'search jira' },
  ];
  const picked = h.selectTools(specs, 'use the wiki search', { cap: 1 });
  assert.equal(picked.length, 1);
  assert.equal(picked[0].name, 'mcp_wiki__search'); // narrowing works with privacy off
});

test('the placeholder note tells a relayed agent that only the listed tools restore placeholders', () => {
  const plain = placeholderToolNote();
  assert.doesNotMatch(plain, /ONLY THE TOOLS LISTED/);
  const own = placeholderToolNote({ ownTools: true });
  assert.match(own, /ONLY THE TOOLS LISTED IN THIS CONVERSATION restore placeholders/);
  assert.match(own, /your own web search, shell, file or code tools — receives the placeholder text literally/);
  assert.match(own, /call the listed tool \(for example `find`/);
  assert.ok(own.startsWith(plain), 'the addition is a suffix — everything the API-model note says still holds');
  assert.match(placeholderToolNote({ toolData: 'redactRemote', ownTools: true }), /REMOTE \(MCP\) tools deliberately receive the placeholder[\s\S]*ONLY THE TOOLS LISTED/);
});
