import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectorBudgetMB, residentMB, recommendDetector, fitUnion } from '../detector-router.js';

const CATALOG = [
  { id: 'Xenova/bert-base-NER', label: 'English — standard', approxMB: 105, lang: 'English' },
  { id: 'Xenova/distilbert-base-multilingual-cased-ner-hrl', label: 'Multilingual — compact', approxMB: 150, lang: '10 languages' },
  { id: 'Xenova/bert-base-multilingual-cased-ner-hrl', label: 'Multilingual — large', approxMB: 180, lang: '10 languages' },
  { id: 'onnx-community/multilang-pii-ner-ONNX', label: 'PII-specialised — multilingual', approxMB: 282, lang: 'Multilingual' },
  { id: 'openai/privacy-filter', label: 'Privacy Filter', approxMB: 1620, ramMB: 1000, minRamMB: 16384 },
];

test('budget: 8% of RAM, never under the small model', () => {
  assert.equal(detectorBudgetMB(8192), 655);
  assert.equal(detectorBudgetMB(16384), 1311);
  assert.equal(detectorBudgetMB(0), 300);
  assert.equal(residentMB(CATALOG[4]), 1000);
  assert.equal(residentMB(CATALOG[0]), 241);
});

test('a 32 GB machine: Privacy Filter + the English place-finder; a note on cost', () => {
  const r = recommendDetector(CATALOG, { totalRamMB: 32768 });
  assert.equal(r.primary, 'openai/privacy-filter');
  assert.deepEqual(r.union, ['Xenova/bert-base-NER']);
  assert.match(r.reason, /finds private people/);
  assert.deepEqual(r.skipped, []);
  assert.deepEqual(r.alternatives, []);
});

test('a 32 GB machine with non-English text: the multilingual place-finder instead', () => {
  const r = recommendDetector(CATALOG, { totalRamMB: 32768, langs: ['en', 'de'] });
  assert.deepEqual(r.union, ['Xenova/bert-base-multilingual-cased-ner-hrl']);
});

test('an 8 GB machine: Privacy Filter is skipped with the reason, the place-finder runs alone, a server is offered', () => {
  const r = recommendDetector(CATALOG, { totalRamMB: 8192 });
  assert.equal(r.primary, 'Xenova/bert-base-NER');
  assert.deepEqual(r.union, []);
  assert.equal(r.skipped[0].id, 'openai/privacy-filter');
  assert.match(r.reason, /does not fit the 655 MB/);
  assert.equal(r.alternatives[0].kind, 'server');
  assert.match(r.alternatives[0].why, /hosted detector/);
});

test('an 8 GB machine with an org box that detects: that box is the alternative, by name', () => {
  const r = recommendDetector(CATALOG, { totalRamMB: 8192 }, [{ id: 'org', name: 'Org box', reach: 'trusted', capabilities: ['detect', 'embed'] }]);
  assert.deepEqual(r.alternatives, [{ kind: 'server', id: 'org', why: 'Org box can run the detection for this machine (trusted)' }]);
});

test('fitUnion: a configured union is trimmed to the machine, primary always loads, order kept', () => {
  const r = fitUnion('openai/privacy-filter', ['Xenova/bert-base-NER', 'Xenova/bert-base-multilingual-cased-ner-hrl'], CATALOG, { totalRamMB: 16384 });
  assert.deepEqual(r.load, ['Xenova/bert-base-NER'], '1000 + 241 fit in 1311; the next 414 does not');
  assert.equal(r.skipped[0].id, 'Xenova/bert-base-multilingual-cased-ner-hrl');
  const big = fitUnion('openai/privacy-filter', ['Xenova/bert-base-NER', 'Xenova/bert-base-multilingual-cased-ner-hrl'], CATALOG, { totalRamMB: 65536 });
  assert.equal(big.skipped.length, 0);
});
