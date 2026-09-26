// Redaction protects what LEAVES the device. Rewriting what comes BACK from a public web
// search buys no privacy and corrupts facts — a dictionary pseudonym renamed a public actor
// inside search results and the answer came back about "Mysore Seshaiah John Babu Naidu".
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { makeToolHarness, isPublicSourceTool } from '../tool-harness.js';
import { createVault } from '../pii-redact.js';

test('public-source results are not rewritten; local results still are', () => {
// The allowlist is explicit and narrow — being wrong in the "public" direction would send
// real PII to a model.
assert.equal(isPublicSourceTool('web_search'), true);
assert.equal(isPublicSourceTool('WEB_SEARCH'), true, 'case-insensitive');
for (const local of ['history_search', 'read_page', 'inspect_page', 'list_meetings', 'mcp_jira__issue', 'get_record']) {
  assert.equal(isPublicSourceTool(local), false, `${local} is NOT public — its output can be private`);
}

const vault = createVault();
const harness = makeToolHarness({
  vault,
  toolData: 'redactRemote',
  redactOpts: { tier: 'basic', dictionary: [{ value: 'Rivera', alias: 'Vega' }] },
});

// A public search result keeps the real public name — the answer stays factually correct.
const web = harness.toModelResult('web_search', { text: 'Ana Lucia Rivera Santos is a film director.' });
assert.match(web.text, /Rivera/, 'a public figure is not renamed in fetched results');
assert.ok(!/Vega/.test(web.text), 'the pseudonym is not applied to public content');

// A LOCAL result is still redacted — this is where a leak could actually happen.
const local = harness.toModelResult('history_search', { text: 'Meeting with Rivera about the roadmap.' });
assert.ok(!/Rivera/.test(local.text), "the user's own history is still pseudonymised");
assert.match(local.text, /Vega/, 'and the pseudonym is applied there');

});

// THROUGH A DISPATCHER the harness sees `find`, not `web_search`. `wsj` in the dictionary
// turned every result URL into `https://www.[[ORG_2]].com/…` and Codex, unable to read its
// own sources, answered that it could not verify the news (2026-09-25).
test('a public tool behind a dispatcher is still public — when the toolset says it is there', () => {
  const vault = createVault();
  const hiddenVia = new Map([['web_search', 'find'], ['history_search', 'find']]);
  const harness = makeToolHarness({ vault, redactOpts: { dictionary: [{ value: 'wsj', type: 'ORG' }] }, hiddenVia });
  const res = { text: '[1] [Latest Headlines - WSJ](https://www.wsj.com/news/latest-headlines)', note: 'ChatPanel · gateway' };

  const web = harness.toModelResult('find', res, { action: 'web_search', args: { query: 'news' } });
  assert.equal(web.text, res.text, 'find → web_search results reach the model intact, URLs included');

  const hist = harness.toModelResult('find', { text: 'Call with WSJ about the pitch.' }, { action: 'history_search', args: {} });
  assert.ok(!/WSJ/.test(hist.text), 'find → history_search is the user\'s own data: still redacted');

  // The model chooses arguments. A plain tool handed `action: 'web_search'` stays itself.
  const spoof = harness.toModelResult('get_record', { text: 'WSJ contract terms' }, { action: 'web_search' });
  assert.ok(!/WSJ/.test(spoof.text), 'an `action` arg on a non-dispatcher does not make a result public');
  const wrongVia = harness.toModelResult('page', { text: 'WSJ contract terms' }, { action: 'web_search' });
  assert.ok(!/WSJ/.test(wrongVia.text), 'nor on a dispatcher that does not reach that tool');

  // Without the map nothing is believed — the old, redacting behaviour.
  const blind = makeToolHarness({ vault, redactOpts: { dictionary: [{ value: 'wsj', type: 'ORG' }] } });
  assert.ok(!/wsj\.com/.test(blind.toModelResult('find', res, { action: 'web_search' }).text));
});

test('a remote tool behind a local-named dispatcher keeps its args redacted under "redact remote"', () => {
  const vault = createVault();
  const hiddenVia = new Map([['mcp_jira__issue', 'data']]);
  const harness = makeToolHarness({ vault, toolData: 'redactRemote', remoteTools: new Set(['mcp_jira__issue']), hiddenVia });
  const args = { action: 'mcp_jira__issue', args: { who: '[[PERSON_1]]' } };
  assert.equal(harness.isRemoteTool('data', args), true);
  assert.deepEqual(harness.toTool('data', args), args, 'the remote tool receives the placeholder');
  assert.equal(harness.realToolName('data', args), 'mcp_jira__issue');
  assert.equal(harness.realToolName('other', args), 'other');
});
