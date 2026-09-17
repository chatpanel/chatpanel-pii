import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CHATPANEL_EXTENSION_IDS, classifyOrigin, callerTrust, isPaired, parseExtensionIds,
  minReach, reachCeiling, capRunOptions, engineHonoursReach,
  createPairingStore, formatPairingCode,
} from '../trust.js';

const OURS = `chrome-extension://${CHATPANEL_EXTENSION_IDS[0]}`;
const STRANGER = 'chrome-extension://mhgkkilhddnoebfbbmgocknfgfpkljih';

test('classifyOrigin: ours is pinned, a stranger is just an extension, a page is web', () => {
  assert.equal(classifyOrigin(OURS), 'pinned');
  assert.equal(classifyOrigin(`${OURS}/`), 'pinned');
  assert.equal(classifyOrigin(OURS.toUpperCase()), 'pinned');
  assert.equal(classifyOrigin(STRANGER), 'extension');
  assert.equal(classifyOrigin('moz-extension://8f3c1a2e-1111-2222-3333-444455556666'), 'extension');
  assert.equal(classifyOrigin('http://localhost:5173'), 'localhost');
  assert.equal(classifyOrigin('http://127.0.0.1'), 'localhost');
  assert.equal(classifyOrigin('https://evil.example'), 'web');
  assert.equal(classifyOrigin('http://localhost.evil.example'), 'web');
  assert.equal(classifyOrigin(''), 'none');
  assert.equal(classifyOrigin(undefined), 'none');
});

test('classifyOrigin: an operator can pin a dev build by id', () => {
  assert.equal(classifyOrigin(STRANGER, { extensionIds: parseExtensionIds(` ${STRANGER}, nope`) }), 'pinned');
  assert.deepEqual(parseExtensionIds('abc'), []); // not a 32-char [a-p] id
});

test('callerTrust: token beats origin; pinned is paired; strangers are unpaired; no-origin is local', () => {
  assert.equal(callerTrust({ origin: STRANGER, hasToken: true }), 'token');
  assert.equal(callerTrust({ origin: OURS }), 'pinned');
  assert.equal(callerTrust({ origin: STRANGER }), 'unpaired');
  assert.equal(callerTrust({ origin: 'http://localhost:3000' }), 'unpaired');
  assert.equal(callerTrust({ origin: '' }), 'local');
  assert.equal(callerTrust({ origin: 'https://evil.example' }), 'web');
  assert.equal(isPaired('token'), true);
  assert.equal(isPaired('pinned'), true);
  assert.equal(isPaired('unpaired'), false);
  assert.equal(isPaired('local'), false);
});

test('minReach picks the stricter tier and fails closed on nonsense', () => {
  assert.equal(minReach('any', 'device'), 'device');
  assert.equal(minReach('trusted', 'any'), 'trusted');
  assert.equal(minReach('any', 'any'), 'any');
  assert.equal(minReach('bogus', 'any'), 'device');
  assert.equal(minReach(undefined, 'trusted'), 'device');
});

test('capRunOptions: a paired caller keeps its options; an unpaired one loses the machine-reaching ones', () => {
  const asked = { model: 'opus', permissionMode: 'bypassPermissions', workingDir: '/', workspace: { repo: 'x' }, grants: ['push'], extraArgs: ['--x'], conversationId: 'c1' };
  assert.deepEqual(capRunOptions(asked, 'pinned'), asked);
  assert.deepEqual(capRunOptions(asked, 'token'), asked);
  const capped = capRunOptions(asked, 'unpaired');
  assert.deepEqual(capped, { model: 'opus', conversationId: 'c1', reach: 'device' });
  // A body cannot loosen the ceiling.
  assert.equal(capRunOptions({ reach: 'any' }, 'unpaired').reach, 'device');
  assert.equal(capRunOptions({ reach: 'trusted' }, 'local').reach, 'device');
  assert.equal(reachCeiling('unpaired'), 'device');
  assert.equal(reachCeiling('pinned'), null);
});

test('engineHonoursReach: only an enforcing engine may run capped', () => {
  assert.equal(engineHonoursReach('codex', 'any'), true);
  assert.equal(engineHonoursReach('codex', ''), true);
  assert.equal(engineHonoursReach('codex', 'device'), false);
  assert.equal(engineHonoursReach('claude', 'device'), true);
  assert.equal(engineHonoursReach('claude', 'trusted'), true);
});

test('pairing store: single use, attempt-capped, expiring', () => {
  let t = 1000;
  const seq = [0.123456, 0.654321];
  const store = createPairingStore({ now: () => t, random: () => seq.shift() ?? 0.5, ttlMs: 1000, maxAttempts: 3 });
  assert.equal(store.claim('123456').ok, false); // nothing issued yet
  const first = store.issue();
  assert.equal(first.code, '123456');
  assert.equal(first.display, '123-456');
  assert.equal(formatPairingCode('123456'), '123-456');
  assert.equal(store.claim('000000').ok, false);
  assert.equal(store.active().attemptsLeft, 2);
  assert.equal(store.claim('123-456').ok, true); // dashes ignored
  assert.equal(store.claim('123456').ok, false); // burnt
  assert.equal(store.active(), null);

  store.issue(); // 654321
  assert.equal(store.claim('1').ok, false);
  assert.equal(store.claim('2').ok, false);
  const third = store.claim('3');
  assert.equal(third.ok, false);
  assert.match(third.reason, /too many/);
  assert.equal(store.claim('654321').ok, false); // burnt by the attempt cap

  store.issue();
  t += 1001;
  const late = store.claim('500000');
  assert.equal(late.ok, false);
  assert.match(late.reason, /expired/);
});
