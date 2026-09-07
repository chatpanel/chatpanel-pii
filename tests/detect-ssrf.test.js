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

// ── The guarded egress is now also an OBSERVABLE one ─────────────────────────────
//
// The SSRF guard above stops raw text going somewhere it must not. It does not tell the user
// that raw text went somewhere it may. Detection is the ONE call that sends un-redacted
// content off the device — you cannot redact before you have detected — and `det.url` accepts
// any public http(s) host, not only loopback. It was guarded but invisible: the `agent`
// backend is metered as `surface: 'redaction'` and these two were logged nowhere, so a user
// auditing "what left my machine" would not have seen them.
test('a detector call reports the FACT of the egress, and never its content', async () => {
  const seen = [];
  const fetchImpl = async () => ({ ok: true, json: async () => ({ entities: [{ value: 'Alex Rivera', type: 'PERSON' }] }) });
  const cfg = { detection: { backend: 'endpoint', url: 'https://ner.example.com/v1/detect?token=SECRETTOKEN' } };
  const ents = await detectEntities(longText, cfg, { fetchImpl, onEgress: (e) => seen.push(e) });
  assert.equal(ents.length, 1);
  assert.equal(seen.length, 1);
  const [e] = seen;
  assert.equal(e.backend, 'endpoint');
  // The HOST, never the full URL — a detector URL can carry a token in its query string.
  assert.equal(e.host, 'ner.example.com');
  assert.equal(e.entities, 1);
  assert.equal(e.ok, true);
  assert.equal(typeof e.ms, 'number');
  assert.equal(e.chars, longText.length);
  // A record of what was redacted must not itself contain the redacted data.
  const dump = JSON.stringify(e);
  for (const secret of ['Alex Rivera', 'Jordan Blake', 'Example Corp', 'Springfield', 'SECRETTOKEN']) {
    assert.equal(dump.includes(secret), false, `the egress record leaked ${secret}`);
  }
});

test('a refused URL never reports an egress — nothing was sent', async () => {
  const seen = [];
  const fetchImpl = async () => { throw new Error('fetch must not be called'); };
  const cfg = { detection: { backend: 'endpoint', url: 'http://169.254.169.254/latest/meta-data/' } };
  await detectEntities(longText, cfg, { fetchImpl, onEgress: (e) => seen.push(e) });
  assert.deepEqual(seen, [], 'a blocked URL must not be logged as an egress — nothing left');
});

test('a failed detector still reports, and a throwing hook never breaks detection', async () => {
  const seen = [];
  const cfg = { detection: { backend: 'endpoint', url: 'https://ner.example.com/detect' } };
  const dead = async () => { throw new Error('connection refused'); };
  assert.deepEqual(await detectEntities(longText, cfg, { fetchImpl: dead, onEgress: (e) => seen.push(e) }), [],
    'detection still fails open');
  assert.equal(seen.length, 1);
  assert.equal(seen[0].ok, false);
  assert.match(seen[0].error, /connection refused/);

  // Observability must never be the reason redaction stops working.
  const boom = () => { throw new Error('the logger is broken'); };
  const ok = async () => ({ ok: true, json: async () => ({ entities: [] }) });
  await assert.doesNotReject(() => detectEntities(longText, { detection: { backend: 'endpoint', url: 'https://ner.example.com/d' } }, { fetchImpl: ok, onEgress: boom }));
});
