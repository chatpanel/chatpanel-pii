// The privacy layer is invisible unless you can see it: what got redacted, and how much.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createVault, redactText, redactionSummary, mergeRedactionSummaries } from '../pii-redact.js';

function seeded() {
  const v = createVault();
  redactText('Email alex@example.com and jordan@example.com about the plan.', v, { tier: 'basic' });
  redactText('Call 555-867-5309 or email alex@example.com again.', v, { tier: 'basic' });
  return v;
}

test('summarises entity types with counts, and never leaks values by default', () => {
  const s = redactionSummary(seeded());
  assert.ok(s.total > 0, 'something was redacted');
  assert.ok(s.types.length > 0);
  for (const t of s.types) {
    assert.match(t.type, /^[A-Z][A-Z0-9]*$/, 'a bare entity type');
    assert.ok(t.count >= 1);
  }
  assert.equal(s.pairs, undefined, 'no values unless explicitly requested');
  assert.ok(!JSON.stringify(s).includes('alex@example.com'), 'the summary carries no real values');
  // Most-frequent first.
  const counts = s.types.map((t) => t.count);
  assert.deepEqual(counts, [...counts].sort((a, b) => b - a));
});

test('the same value redacted twice is one entity, not two', () => {
  const s = redactionSummary(seeded());
  const email = s.types.find((t) => t.type === 'EMAIL');
  assert.equal(email.count, 2, 'two distinct addresses; the repeat reuses its token');
});

test('includeValues returns the before → after pairs, on request only', () => {
  const s = redactionSummary(seeded(), { includeValues: true });
  assert.ok(Array.isArray(s.pairs) && s.pairs.length === s.total);
  const one = s.pairs.find((p) => p.type === 'EMAIL');
  assert.match(one.token, /^\[\[EMAIL_\d+\]\]$/);
  assert.match(one.value, /@example\.com$/);
  // maxPairs bounds what a UI has to render.
  assert.equal(redactionSummary(seeded(), { includeValues: true, maxPairs: 1 }).pairs.length, 1);
});

test('summaries merge across conversations, counts only', () => {
  const merged = mergeRedactionSummaries([
    { types: [{ type: 'EMAIL', count: 2 }, { type: 'PHONE', count: 1 }] },
    { types: [{ type: 'EMAIL', count: 3 }, { type: 'PERSON', count: 4 }] },
  ]);
  assert.equal(merged.total, 10);
  assert.deepEqual(merged.types[0], { type: 'EMAIL', count: 5 }, 'summed across both, most-frequent first');
  assert.equal(merged.types.find((t) => t.type === 'PERSON').count, 4);
});

test('an empty or missing vault summarises to zero rather than throwing', () => {
  assert.deepEqual(redactionSummary(createVault()), { total: 0, types: [] });
  assert.deepEqual(redactionSummary(null), { total: 0, types: [] });
  assert.deepEqual(mergeRedactionSummaries([]), { total: 0, types: [] });
});
