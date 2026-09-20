// Bump the version by READING it, never by guessing what is there.
//
//   node tools/bump.mjs patch|minor|major [--also src/server.js]
//
// The failure this exists to prevent: `sed s/"0.153.0"/"0.154.0"/` is a guess about the
// current value, and several sessions work these repos at once. When the guess is wrong the
// substitution matches nothing and reports success, so the commit claims a version the file
// does not have and the publish is skipped by the version guard, silently.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';

const kind = process.argv[2];
if (!['patch', 'minor', 'major'].includes(kind)) {
  console.error('usage: node tools/bump.mjs patch|minor|major');
  process.exit(2);
}
const pkgUrl = new URL('../package.json', import.meta.url);
const raw = readFileSync(pkgUrl, 'utf8');
const current = JSON.parse(raw).version;
const [maj, min, pat] = current.split('.').map(Number);
const next = kind === 'major' ? `${maj + 1}.0.0` : kind === 'minor' ? `${maj}.${min + 1}.0` : `${maj}.${min}.${pat + 1}`;

// Replace the version FIELD, anchored, and verify the file actually changed.
const out = raw.replace(/("version"\s*:\s*")[^"]+(")/, `$1${next}$2`);
if (out === raw) { console.error(`✗ package.json: no version field changed (is it "${current}"?)`); process.exit(1); }
writeFileSync(pkgUrl, out);

// Anywhere the same number lives in code. publish.yml requires these to agree.
for (const file of ['src/server.js']) {
  const url = new URL(`../${file}`, import.meta.url);
  if (!existsSync(url)) continue;
  const src = readFileSync(url, 'utf8');
  if (!/^const VERSION = '/m.test(src)) continue;
  writeFileSync(url, src.replace(/^(const VERSION = ')[^']+(')/m, `$1${next}$2`));
  console.log(`  ${file}: ${current} -> ${next}`);
}

// The extension's version of record is its MANIFEST — package.json mirrors it, and the
// `ext-v*` release reads the manifest. Bumping only package.json leaves the store version
// behind and CWS rejects a re-publish at a version it already has.
for (const file of ['extension/manifest.json']) {
  const url = new URL(`../${file}`, import.meta.url);
  if (!existsSync(url)) continue;
  const src = readFileSync(url, 'utf8');
  const out = src.replace(/("version"\s*:\s*")[^"]+(")/, `$1${next}$2`);
  if (out === src) { console.error(`✗ ${file}: no version field changed`); process.exit(1); }
  writeFileSync(url, out);
  console.log(`  ${file}: ${current} -> ${next}`);
}
console.log(`${current} -> ${next}`);
