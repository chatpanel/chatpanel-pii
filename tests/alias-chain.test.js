import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createVault, redactText, restoreWithAliases } from '../pii-redact.js';

// Regression: overlapping pseudonyms must not cascade. With John→Twinkle and
// Arnav→John, the token "John" is BOTH the real value behind "Twinkle" AND the
// alias for "Arnav". A per-alias restore loop walked Twinkle→John→Arnav, so a
// tool call carrying the model's pseudonym "Twinkle" reached the tool as "Arnav".
test('restoreWithAliases does not cascade through an overlapping alias chain', () => {
  const v = createVault();
  const dictionary = [
    { value: 'John', alias: 'Twinkle' },
    { value: 'Arnav', alias: 'John' },
  ];
  // The model sees the pseudonym for the real name the user typed.
  assert.equal(redactText('I am John', v, { tier: 'basic', dictionary }), 'I am Twinkle');

  // A tool arg carrying the pseudonym restores to the REAL value exactly once.
  assert.equal(restoreWithAliases('Twinkle', v), 'John');
  // The unrelated alias still restores to its own real value.
  assert.equal(restoreWithAliases('John', v), 'Arnav');
  // Mixed in a sentence, each is replaced independently — no chaining.
  assert.equal(restoreWithAliases('Twinkle met John', v), 'John met Arnav');
});

// Regression: the redact pass itself must be single-pass. Entry 1 turns 'Arnav'
// into the pseudonym 'John'; a later reversible 'John' entry must NOT then
// tokenize that freshly-produced 'John' (it never appeared in the user's input).
test('redactText does not re-match a pseudonym produced by an earlier entry', () => {
  const v = createVault();
  const dictionary = [
    { value: 'Arnav', alias: 'John' },
    { value: 'John', type: 'PERSON' },
  ];
  assert.equal(redactText('I am Arnav', v, { tier: 'basic', dictionary }), 'I am John');
  // A real 'John' in the input is still tokenized (the entry works when it matches).
  const v2 = createVault();
  assert.match(redactText('I am John', v2, { tier: 'basic', dictionary }), /\[\[PERSON_1\]\]/);
});

// Longest-alias-first: a multi-word pseudonym wins over a bare-name pseudonym.
test('restoreWithAliases prefers the longest matching alias', () => {
  const v = createVault();
  v.aliases.set('Twinkle', 'John');
  v.aliases.set('Twinkle Star', 'John Doe');
  assert.equal(restoreWithAliases('Twinkle Star', v), 'John Doe');
});
