import { test } from 'node:test';
import assert from 'node:assert/strict';
import { recaseForDetection } from '../pii-detect.js';

test('recase: capitalises the words a model might be missing, leaves common words alone, preserves length', () => {
  const src = 'hello I am john. I used to live in austin. but now i moved to seattle.';
  const { text, changed } = recaseForDetection(src);
  assert.equal(changed, true);
  assert.equal(text, 'hello I am John. I used to live in Austin. but now i moved to Seattle.', 'hello/am/used/live/moved are common words and stay');
  assert.equal(text.length, src.length, 'offsets into the copy are offsets into the original');
});

test('recase: neutral prose is not turned into names by the stop-list alone — that is the model\'s job', () => {
  const { text } = recaseForDetection('can you summarize this page about kubernetes and docker for me');
  assert.equal(text, 'can you Summarize this Page about Kubernetes and Docker for me');
});

test('recase: already-cased text is unchanged; a multi-char upper-case form is left alone', () => {
  assert.deepEqual(recaseForDetection('Hi, I am Jordan Blake.'), { text: 'Hi, I am Jordan Blake.', changed: false });
  const { text } = recaseForDetection('straße');
  assert.equal(text, 'Straße');
  assert.equal(text.length, 'straße'.length);
  const { text: t2, changed } = recaseForDetection('ßtraße');
  assert.equal(t2, 'ßtraße', 'ß → SS would change length, so it is skipped');
  assert.equal(changed, false);
});
