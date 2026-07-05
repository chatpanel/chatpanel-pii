// L4: detectEntities POSTs RAW (pre-redaction) text to a user-configured URL — it
// must refuse cloud-metadata / non-http(s) before sending, and never even call fetch.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectEntities } from '../pii-detect.js';

const longText = 'Alex Rivera met Jordan Blake at Example Corp in Springfield.';

test('L4: metadata detector URL is refused in strict mode, fetch never called', async () => {
  let called = false;
  const fetchImpl = async () => { called = true; return { ok: true, json: async () => [] }; };
  await assert.rejects(
    () => detectEntities(longText, { detection: { backend: 'endpoint', url: 'http://169.254.169.254/' } }, { fetchImpl, strict: true }),
    /blocked address/,
  );
  assert.equal(called, false); // guarded before the request
});

test('L4: non-strict fails open (deterministic-only) on a blocked URL', async () => {
  const fetchImpl = async () => { throw new Error('should not be called'); };
  const ents = await detectEntities(longText, { detection: { backend: 'endpoint', url: 'file:///etc/passwd' } }, { fetchImpl });
  assert.deepEqual(ents, []);
});

test('L4: a loopback detector URL is allowed through the guard', async () => {
  let called = false;
  const fetchImpl = async () => { called = true; return { ok: true, json: async () => [{ value: 'Alex Rivera', type: 'PERSON' }] }; };
  const ents = await detectEntities(longText, { detection: { backend: 'endpoint', url: 'http://127.0.0.1:9009/ner' } }, { fetchImpl, strict: true });
  assert.equal(called, true);
  assert.ok(ents.length >= 1);
});
