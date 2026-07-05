import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createVault, redactText, restoreText } from '../pii-redact.js';
import { confusablesSkeleton } from '../sanitize.js';

// Build homoglyph strings from code points (no literal confusables in source).
const CYR = { a: 'а', e: 'е', o: 'о', p: 'р', c: 'с' }; // Cyrillic look-alikes

test('confusablesSkeleton folds Cyrillic/Greek/fullwidth 1:1 (length preserved)', () => {
  const s = `j${CYR.o}hn`; // "john" with a Cyrillic o
  const sk = confusablesSkeleton(s);
  assert.equal(sk, 'john');
  assert.equal(sk.length, s.length); // 1:1 so match indices align
  assert.equal(confusablesSkeleton('ＡＩｚａ'), 'AIza'); // fullwidth
});

test('L2: homoglyph email (Cyrillic o) is detected; ORIGINAL span redacted + restored', () => {
  const v = createVault();
  const raw = `mail j${CYR.o}hn@example.c${CYR.o}m now`;
  const out = redactText(raw, v);
  assert.match(out, /\[\[EMAIL_1\]\]/);
  assert.doesNotMatch(out, /@example/);
  // the stored value is the ORIGINAL bytes (with the Cyrillic o), restored verbatim
  assert.equal(restoreText('[[EMAIL_1]]', v), `j${CYR.o}hn@example.c${CYR.o}m`);
});

test('L2: fullwidth Google key is detected', () => {
  // AIza… with a fullwidth "AIza" prefix
  const key = 'ＡＩｚａSyA1234567890abcdefghijklmnopqrstuv';
  assert.match(redactText(`k ${key}`, createVault()), /\[\[KEY_1\]\]/);
});

test('L2: legitimate non-Latin text is NOT rewritten (no false positive)', () => {
  const v = createVault();
  // A Russian word (Cyrillic) that folds to gibberish but matches no detector.
  const russian = 'привет мир'; // "hello world"
  const out = redactText(`note ${russian} end`, v);
  assert.equal(out, `note ${russian} end`); // untouched — nothing matched
});

test('L2: skeleton match does not clobber surrounding original text', () => {
  const v = createVault();
  const raw = `before a@b.com after`;
  const out = redactText(raw, v);
  assert.match(out, /^before \[\[EMAIL_1\]\] after$/);
});
