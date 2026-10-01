// How strict redaction is (`ui.piiRedaction.strictness`): 'balanced' second-guesses the detections
// known to be wrong; 'strict' redacts every span a detector reports. An older config has no key
// and means balanced.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeEntities, detectEntities, strictnessOf, clearDetectCache, REDACTION_STRICTNESS } from '../pii-detect.js';

const SPANS = { entities: [{ word: '98065', entity_group: 'private_address' }, { word: '1M dwelling', entity_group: 'private_address' }] };

test('balanced lets a quantity go; strict hides it with the rest', () => {
  assert.deepEqual(normalizeEntities(SPANS).map((e) => e.value), ['98065']);
  assert.deepEqual(normalizeEntities(SPANS, null, { strictness: 'strict' }).map((e) => e.value), ['98065', '1M dwelling']);
});

test('the level comes from the config, balanced when it is absent', () => {
  assert.deepEqual(REDACTION_STRICTNESS, ['balanced', 'strict']);
  assert.equal(strictnessOf({}), 'balanced');
  assert.equal(strictnessOf({ strictness: 'strict' }), 'strict');
  assert.equal(strictnessOf({ detection: { strictness: 'strict' } }), 'strict', 'a host that sets it on the detection');
  assert.equal(strictnessOf({ strictness: 'loose' }), 'balanced', 'an unknown value is not stricter or looser — it is the default');
});

test('strict reaches the detector, and the cache keeps the two levels apart', async () => {
  clearDetectCache();
  const sent = [];
  const fetchImpl = async (url, opts) => { sent.push(JSON.parse(opts.body)); return new Response(JSON.stringify(SPANS), { status: 200 }); };
  const cfg = (strictness) => ({ strictness, detection: { backend: 'endpoint', url: 'inproc:ner', transport: 'in-process', types: null } });
  const text = 'best home insurance quotes in 98065 for 1M dwelling';
  const balanced = await detectEntities(text, cfg(undefined), { fetchImpl });
  const strict = await detectEntities(text, cfg('strict'), { fetchImpl });
  assert.deepEqual(balanced.map((e) => e.value), ['98065']);
  assert.deepEqual(strict.map((e) => e.value), ['98065', '1M dwelling'], 'not the balanced answer from the cache');
  assert.deepEqual(sent, [{ text }, { text, strict: true }]);
});
