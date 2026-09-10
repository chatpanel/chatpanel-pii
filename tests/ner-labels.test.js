import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeEntities } from '../pii-detect.js';

// An unmapped NER label does not degrade redaction — it TURNS IT OFF for that type, and
// says nothing. keepEntity sends anything it does not recognise to the digit-count
// fallback, where a person's name has no digits and fails, so the name goes to the model
// in plaintext while the shield in the composer still reads as on. The deterministic
// detectors keep catching emails and card numbers, which is what makes it hard to notice.
//
// That happened: the multilang-pii-ner model emits the ai4privacy vocabulary and none of it
// was mapped. This file is the guard.

const typesOf = (entities, toggles) =>
  Object.fromEntries(normalizeEntities({ entities }, toggles).map((e) => [e.value, e.type]));

test('the ai4privacy vocabulary maps — the one that silently stopped redacting names', () => {
  const got = typesOf([
    { value: 'Jordan Blake', type: 'GIVENNAME' },
    { value: 'Okonkwo', type: 'SURNAME' },
    { value: 'Oak Street', type: 'STREET' },
    { value: '12', type: 'BUILDINGNUM' },
    { value: '90210', type: 'ZIPCODE' },
    { value: 'Springfield', type: 'CITY' },
    { value: '555-0134', type: 'TELEPHONENUM' },
    { value: '123-45-6789', type: 'SOCIALNUM' },
    { value: 'jblake', type: 'USERNAME' },
    { value: 'hunter2', type: 'PASSWORD' },
  ]);
  assert.equal(got['Jordan Blake'], 'PERSON');
  assert.equal(got.Okonkwo, 'PERSON');
  // An address PART identifies a household as surely as the street does.
  assert.equal(got['Oak Street'], 'ADDRESS');
  assert.equal(got['12'], 'ADDRESS');
  assert.equal(got['90210'], 'ADDRESS');
  assert.equal(got.Springfield, 'LOCATION');
  assert.equal(got['555-0134'], 'PHONE');
  assert.equal(got['123-45-6789'], 'SSN');
  assert.equal(got.jblake, 'ID');
  assert.equal(got.hunter2, 'SECRET');
});

test('the older vocabularies still map', () => {
  const got = typesOf([
    { value: 'Alex Rivera', type: 'PER' },          // HF bert-base-NER
    { value: 'Acme Corp', type: 'ORG' },
    { value: 'Springfield', type: 'GPE' },          // spaCy / OntoNotes
    { value: 'a@example.com', type: 'EMAIL_ADDRESS' }, // Presidio
    { value: '555-0134', type: 'PHONE_NUMBER' },
  ]);
  assert.deepEqual(got, {
    'Alex Rivera': 'PERSON',
    'Acme Corp': 'ORG',
    Springfield: 'LOCATION',
    'a@example.com': 'EMAIL',
    '555-0134': 'PHONE',
  });
});

test('a secret is always redacted, whatever the category toggles say', () => {
  // Leaving it to the toggles would let "turn off numbers" switch off passwords.
  const off = { person: false, org: false, location: false, number: false };
  const got = typesOf([
    { value: 'hunter2', type: 'PASSWORD' },
    { value: 'a@example.com', type: 'EMAIL' },
    { value: 'Alex Rivera', type: 'PERSON' },
  ], off);
  assert.equal(got.hunter2, 'SECRET');
  assert.equal(got['a@example.com'], 'EMAIL');
  assert.equal(got['Alex Rivera'], undefined, 'a person is a toggle, and it was turned off');
});

test('noisy temporal labels stay out unless they look like an identifier', () => {
  // Small models tag "today" and "4". A date of birth is different — it identifies.
  const got = typesOf([
    { value: 'today', type: 'DATE' },
    { value: '4', type: 'CARDINAL' },
    { value: '1985-04-02', type: 'DATEOFBIRTH' },
  ]);
  assert.equal(got.today, undefined);
  assert.equal(got['4'], undefined);
  assert.equal(got['1985-04-02'], 'ID');
});
