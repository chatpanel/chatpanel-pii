// The version in the file is the version the commit claims — checked, not assumed.
//
// Several sessions work these repos at once, so the number in package.json moves under you.
// A bump written as "replace 0.153.0 with 0.154.0" is a guess about what is there, and when
// the guess is wrong it matches NOTHING and says nothing: six commits once claimed 0.151.0
// through 0.156.0 while package.json said 0.150.2 the whole way. npm already had 0.150.2,
// and publish.yml is version-guarded, so the push would have skipped every publish in
// silence — the work committed, the release never made, consumers waiting on a number that
// was never going out.
//
// Three things are checked, all cheap and offline:
//   1. package.json's version matches the "(x.y.z)" in the HEAD commit subject, when it has
//      one — that is this workspace's commit convention, so it costs nothing to enforce.
//   2. A repo that also keeps its version in code (bridge/gateway: src/server.js VERSION)
//      agrees with package.json. publish.yml requires both; a mismatch publishes nothing.
//   3. The version is a plausible semver, not a leftover placeholder.
//
// Run from `npm test`, so the session that causes a drift is the session that sees it.
import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const fail = (msg) => { console.error(`✗ version check: ${msg}`); process.exit(1); };
const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const version = String(pkg.version || '');

if (!/^\d+\.\d+\.\d+(-[\w.]+)?$/.test(version)) fail(`package.json version "${version}" is not a semver`);

// Where a version also lives in code. publish.yml compares them; so do we, before a push.
for (const [file, re] of [['src/server.js', /^const VERSION = '([^']+)'/m]]) {
  const url = new URL(`../${file}`, import.meta.url);
  if (!existsSync(url)) continue;
  const found = re.exec(readFileSync(url, 'utf8'))?.[1];
  if (!found) continue;
  if (found !== version) {
    fail(`${file} says ${found} but package.json says ${version}. publish.yml requires both to match — bump BOTH or the publish silently no-ops.`);
  }
}

// The extension keeps its version of record in the MANIFEST; package.json mirrors it, and
// the `ext-v*` release reads the manifest. They must not drift: a bump that moves only one
// leaves the store version behind, and CWS rejects a re-publish at a version it already has.
{
  const url = new URL('../extension/manifest.json', import.meta.url);
  if (existsSync(url)) {
    const m = JSON.parse(readFileSync(url, 'utf8')).version;
    if (m !== version) fail(`extension/manifest.json says ${m} but package.json says ${version}. The manifest is the version of record — bump both.`);
  }
}

// The commit's own claim. Only checked when the subject carries one, so an ordinary
// message ("docs: …") is never blocked.
let subject = '';
try { subject = execFileSync('git', ['log', '-1', '--format=%s'], { encoding: 'utf8' }).trim(); } catch { /* not a repo */ }
const claimed = /\((\d+\.\d+\.\d+(?:-[\w.]+)?)\)/.exec(subject)?.[1];
if (claimed && claimed !== version) {
  fail(`the last commit says (${claimed}) but package.json says ${version}.\n`
    + `  subject: ${subject}\n`
    + '  A bump written against the number you EXPECTED matches nothing when another session has moved it,\n'
    + '  and fails silently. Read the version, then set it — tools/bump.mjs does that.');
}

console.log(`✓ version ${version}${claimed ? ' (matches the commit)' : ''}`);
