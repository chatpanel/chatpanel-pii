// AN IN-PROCESS DETECTOR MUST ACTUALLY DETECT.
//
// This is a regression test for a silent, total failure. A host that runs the NER model in
// its own process passes a sentinel URL and a fetchImpl that ignores it. The sentinel failed
// the SSRF scheme check, the throw was swallowed by the (correct) fail-open path, and the
// detector contributed NOTHING to any redaction — while reporting itself ready and answering
// its own health route perfectly. Names went to the model in full under a UI saying "full
// tier". Nothing in the system was in a position to notice.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectEntities } from '../pii-detect.js';

const ENTS = [
  { value: 'Alex Rivera', type: 'PER' },
  { value: 'Acme Corp', type: 'ORG' },
  { value: 'Berlin', type: 'LOC' },
];

/** Exactly the shape a host's in-process adapter has: the URL is never dialled. */
const adapter = (calls) => async (url, opts) => {
  calls.push({ url, text: JSON.parse(opts.body).text });
  return new Response(JSON.stringify({ entities: ENTS }), {
    status: 200, headers: { 'content-type': 'application/json' },
  });
};

const TEXT = 'Alex Rivera works at Acme Corp in Berlin and it has been a long day.';

const inproc = (extra = {}) => ({
  detection: {
    backend: 'endpoint', url: 'inproc:ner', transport: 'in-process',
    timeoutMs: 5000, maxChars: 8000, ...extra,
  },
});

test('a sentinel URL with an injected transport DETECTS — it is not dialled, so it is not judged', async () => {
  const calls = [];
  const ents = await detectEntities(TEXT, inproc(), { fetchImpl: adapter(calls), strict: true });
  assert.equal(ents.length, 3, 'every entity survived');
  assert.equal(calls.length, 1, 'the adapter was actually called');
  assert.equal(calls[0].url, 'inproc:ner');
});

test('WITHOUT the flag the same sentinel still fails — the guard has not been loosened', async () => {
  const calls = [];
  const cfg = { detection: { backend: 'endpoint', url: 'inproc:ner', timeoutMs: 5000 } };
  await assert.rejects(
    () => detectEntities(TEXT, cfg, { fetchImpl: adapter(calls), strict: true }),
    /only http\(s\)/,
  );
  assert.equal(calls.length, 0);
});

test('the flag cannot be used to smuggle a REAL address past the guard', async () => {
  // No injected fetch means there is no in-process anything, so the claim is refused rather
  // than believed. Otherwise a line in a config file would switch SSRF checking off.
  await assert.rejects(
    () => detectEntities(TEXT, {
      detection: {
        backend: 'endpoint', url: 'http://169.254.169.254/latest/meta-data/',
        transport: 'in-process', timeoutMs: 500,
      },
    }, { strict: true }),
    /needs an injected fetch/,
  );
});

test('an in-process detection is NOT reported as egress — nothing left the machine', async () => {
  const egress = [];
  await detectEntities(TEXT, inproc(), {
    fetchImpl: adapter([]),
    strict: true,
    onEgress: (e) => egress.push(e),
  });
  assert.equal(egress.length, 0);
});

test('a real endpoint IS still reported as egress', async () => {
  const egress = [];
  const fetchImpl = async () => new Response(JSON.stringify({ entities: ENTS }), {
    status: 200, headers: { 'content-type': 'application/json' },
  });
  await detectEntities(TEXT, {
    detection: { backend: 'endpoint', url: 'http://127.0.0.1:9/detect', timeoutMs: 5000 },
  }, { fetchImpl, strict: true, onEgress: (e) => egress.push(e) });
  assert.equal(egress.length, 1, 'text leaving for a detector is always recorded');
});
