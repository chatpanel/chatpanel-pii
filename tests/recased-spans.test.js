// What the re-cased NER pass may add. "best home insurance quotes in 98065 for 1M dwelling" reached
// the model as `[[ORG_1]] quotes in [[ADDRESS_2]] for [[ADDRESS_1]]` (2026-09-30): the re-cased
// copy read like a headline. The spans below are what the bundled detectors returned for twelve
// lowercase questions, measured that day.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { recasedSpanOk, allOrdinary } from '../recased-spans.js';

test('an organisation made only of ordinary words is the headline effect, not a company', () => {
  for (const v of ['best home insurance', 'cheap car insurance', 'compare state farm', 'home', 'Best Home Insurance Quotes']) assert.equal(recasedSpanOk(v, 'ORG'), false, v);
  for (const v of ['allstate', 'acme robotics', 'microsoft stock', 'Allstate']) assert.equal(recasedSpanOk(v, 'ORG'), true, v);
  assert.equal(recasedSpanOk('best home insurance', 'organization'), false, 'any vocabulary for an organisation');
});

test('an address needs a house number of its own — a quantity is not one', () => {
  assert.equal(recasedSpanOk('1M dwelling', 'private_address'), false);
  assert.equal(recasedSpanOk('1200 se maple st', 'private_address'), true);
  assert.equal(recasedSpanOk('4410 lakeview avenue', 'STREET'), true);
  assert.equal(recasedSpanOk('98065', 'ZIPCODE'), true, 'a postcode alone is still an address part');
});

test('people and places are what the pass is for — never dropped here', () => {
  for (const [v, l] of [['jordan blake', 'PER'], ['suresh', 'private_person'], ['north bend', 'LOC'], ['new york', 'GPE'], ['seattle', 'CITY']]) assert.equal(recasedSpanOk(v, l), true, v);
});

test('ordinary words, plurals included; anything else is not', () => {
  assert.equal(allOrdinary('quotes policies rates'), true);
  assert.equal(allOrdinary('acme'), false);
  assert.equal(allOrdinary(''), false);
  assert.equal(allOrdinary('1M'), false, 'no words is not "all ordinary"');
});

test('a quantity is not an address, in any pass — a postcode, a street and a city still are', async () => {
  const { quantityNotAddress, normalizeEntities } = await import('../pii-detect.js');
  for (const v of ['1M dwelling', '$1M home', '500k house', '1.2m', '20%']) assert.equal(quantityNotAddress(v), true, v);
  for (const v of ['98065', '1200 se maple st', '1200 se maple st, north bend', 'north bend', 'unit 4, 1m tower road', '10 downing street']) assert.equal(quantityNotAddress(v), false, v);
  // privacy-filter's own spans for the question that lost its coverage amount (2026-09-30).
  const kept = normalizeEntities({ entities: [{ word: '98065', entity_group: 'private_address' }, { word: '1M dwelling', entity_group: 'private_address' }] });
  assert.deepEqual(kept, [{ value: '98065', type: 'ADDRESS' }]);
});
