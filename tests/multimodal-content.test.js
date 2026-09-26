// A message carrying an image is a list of parts, not a string. Redaction must reach the text
// parts and leave the image alone — it used to turn the whole list into "[object Object]".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createVault } from '../pii-redact.js';
import { redactOutbound } from '../pipeline.js';

const cfg = { mode: 'deterministic', tier: 'basic', applyTo: 'remote', scope: { chat: true, context: true, history: true, toolResults: true } };
const image = 'data:image/jpeg;base64,AAAA';

test('OpenAI-style parts: the text is redacted, the image passes untouched', () => {
  const vault = createVault();
  const { messages } = redactOutbound({ vault, cfg, messages: [{ role: 'user', content: [
    { type: 'text', text: 'Who sent this? Reply to alex.rivera@example.com' },
    { type: 'image_url', image_url: { url: image } },
  ] }] });
  const [text, img] = messages[0].content;
  assert.equal(text.type, 'text');
  assert.doesNotMatch(text.text, /alex\.rivera@example\.com/);
  assert.match(text.text, /\[\[EMAIL_1\]\]/);
  assert.deepEqual(img, { type: 'image_url', image_url: { url: image } });
});

test('Anthropic-style parts and a plain string both still work', () => {
  const vault = createVault();
  const { messages } = redactOutbound({ vault, cfg, messages: [
    { role: 'user', content: [{ type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'AAAA' } }, { type: 'text', text: 'call 206-555-0142' }] },
    { role: 'user', content: 'call 206-555-0142' },
  ] });
  assert.equal(messages[0].content[0].type, 'image');
  assert.match(messages[0].content[1].text, /\[\[PHONE_1\]\]/);
  assert.match(messages[1].content, /\[\[PHONE_1\]\]/, 'the same value, the same token');
  assert.ok(!JSON.stringify(messages).includes('[object Object]'));
});
