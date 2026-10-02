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
  assert.match(plain, /When you call ANY tool/, 'an API model has only the listed tools, so "any" is true for it');
  const own = placeholderToolNote({ ownTools: true });
  assert.match(own, /ONLY THE TOOLS LISTED IN THIS CONVERSATION restore placeholders/);
  assert.match(own, /your own web search, browser, shell, file or code tools — receives the placeholder text literally/);
  assert.match(own, /call the listed tool \(for example `find`/);
  // The whole note is true for an agent: it was told "ANY tool" restores a few lines above the
  // sentence saying its own do not, and it sent "[[PERSON_1]] by [[ORG_3]]" to its own browser.
  assert.doesNotMatch(own, /When you call ANY tool/);
  assert.match(own, /When you call a tool LISTED IN THIS CONVERSATION, these placeholders are AUTOMATICALLY replaced/);
  // Not lookups alone: opening, typing and saving are where a literal placeholder does harm.
  assert.match(own, /for ANYTHING that involves a placeholder — a lookup, a search, a page to open, text to type or save/);
  assert.match(own, /if no listed tool can do it, say so instead of handing a placeholder to a tool of your own/);
  assert.equal(own.replace('a tool LISTED IN THIS CONVERSATION,', 'ANY tool,').startsWith(plain), true, 'everything else the API-model note says still holds');
  assert.match(placeholderToolNote({ toolData: 'redactRemote', ownTools: true }), /REMOTE \(MCP\) tools deliberately receive the placeholder[\s\S]*ONLY THE TOOLS LISTED/);
});

test('a relayed agent with no listed tools is told its own tools get the placeholder as it is', async () => {
  const { placeholderNote } = await import('../tool-harness.js');
  assert.doesNotMatch(placeholderNote(), /tool of your own/, 'an API model with no tools has nothing to hand a placeholder to');
  const own = placeholderNote({ ownTools: true });
  assert.ok(own.startsWith(placeholderNote()));
  assert.match(own, /receives the placeholder text literally/);
  assert.match(own, /never hand a placeholder to a tool of your own/);
  assert.doesNotMatch(own, /call the listed tool/, 'none is listed');
});

test('a turn with no tools still learns what a placeholder is', async () => {
  const { placeholderNote } = await import('../tool-harness.js');
  const note = placeholderNote();
  assert.match(note, /\[\[LOCATION_1\]\]/);
  assert.match(note, /do not say it is unresolved/i);
  assert.doesNotMatch(note, /CALL THE TOOL/, 'no tool to call, no instruction to call one');
});
