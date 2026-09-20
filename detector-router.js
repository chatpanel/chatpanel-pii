// DETECTOR ROUTING — which detectors to run on THIS machine, and why (privacy-routing.md §4.4, §6).
//
// One model cannot cover chat text (Privacy Filter finds a lowercase name and never a city;
// a NER model the reverse), and the best model is a 1 GB resident that would swap an 8 GB
// laptop with a browser and a coding agent open. So the choice is a judgement about the
// machine: how much memory detectors may take, which of the catalogued models fit, and what
// to offer when the good ones do not — a detector on a server, which is what a hosted tier
// is too. Pure: the catalogue, the machine and what is installed come in; a primary, a union,
// the reasons and the alternatives come out. The gateway applies it; the clients draw it.

/**
 * How much resident memory detectors may take on a machine of this size: 8% of RAM, never
 * under 300 MB (the small English model must always fit). 8 GB → 655 MB; 16 GB → 1.3 GB;
 * 32 GB → 2.6 GB. The figure is a budget for the UNION, not one model: the sum of `ramMB`
 * of everything loaded.
 */
export function detectorBudgetMB(totalRamMB) {
  const total = Number(totalRamMB) || 0;
  return Math.max(300, Math.round(total * 0.08));
}

/**
 * Resident cost of a catalogue entry — `ramMB` when declared, else ~2.3× the q8 download:
 * measured 2026-09-19, bert-base-NER (105 MB on disk) added ~240 MB to the process; Privacy
 * Filter (1.6 GB int8 on disk) ~700 MB, which is why it declares `ramMB` itself.
 */
export function residentMB(model) {
  if (Number(model?.ramMB) > 0) return Number(model.ramMB);
  return Math.round((Number(model?.approxMB) || 200) * 2.3);
}

/**
 * Is this catalogue entry a general NER model — the kind that finds places and organisations?
 * Privacy Filter is not (no LOC/ORG label, by design); the PII-specialised multilingual model
 * is not either for this purpose: it tags a city but measured 0 of 7 lowercase names, so it is
 * never the model chosen to complement Privacy Filter (privacy-routing.md §3.2).
 */
function findsPlaces(m) { return !/private|privacy|pii/i.test(String(m.id)); }
function isPrivacyModel(m) { return /privacy-filter/i.test(String(m.id)); }
function multilingual(m) { return /multilingual|multilang/i.test(String(m.id)) || /multi|languages/i.test(String(m.lang || '')); }

/**
 * Recommend a primary and a union for this machine.
 *
 * @param catalog   [{ id, label, approxMB, ramMB?, minRamMB?, lang?, installed? }]
 * @param machine   { totalRamMB, langs?: ['en','de',…] (languages seen in this user's text), nonLatin?: bool }
 * @param providers optional [{ id, name, reach, capabilities: ['detect'…] }] — servers that can
 *                  detect for this machine (an org box, the hosted tier) — offered when the
 *                  good models do not fit here.
 * @returns { primary, union, budgetMB, usedMB, reason, skipped: [{ id, why }], alternatives: [{ kind, id?, why }] }
 */
export function recommendDetector(catalog = [], machine = {}, providers = []) {
  const budgetMB = detectorBudgetMB(machine.totalRamMB);
  const wantMulti = !!machine.nonLatin || (Array.isArray(machine.langs) && machine.langs.some((l) => l && l !== 'en'));
  const byId = (id) => catalog.find((m) => m.id === id);
  const small = catalog.find((m) => /Xenova\/bert-base-NER$/.test(m.id)) || catalog[0];
  const privacy = catalog.find(isPrivacyModel);
  const placesModel = catalog.filter(findsPlaces).filter((m) => wantMulti ? multilingual(m) : !multilingual(m))
    // the biggest place-finder that is not the privacy model: accuracy over size within the budget
    .sort((a, b) => residentMB(b) - residentMB(a))[0] || small;

  const chosen = [];
  const skipped = [];
  let usedMB = 0;
  const take = (m, role) => {
    if (!m || chosen.some((c) => c.id === m.id)) return false;
    const cost = residentMB(m);
    if (usedMB + cost > budgetMB) { skipped.push({ id: m.id, why: `${role}: needs ~${cost} MB, ${budgetMB - usedMB} MB of the ${budgetMB} MB detector budget left` }); return false; }
    chosen.push(m); usedMB += cost; return true;
  };
  // The privacy model first — it is the one that finds what redaction is for — then a
  // place-finder beside it; if the privacy model does not fit, the place-finder alone.
  const gotPrivacy = take(privacy, 'private people, addresses, secrets');
  take(placesModel, 'places and organisations');
  if (!chosen.length) take(small, 'the smallest model');
  if (!chosen.length && small) { chosen.push(small); usedMB += residentMB(small); } // the floor: always something

  const primary = chosen[0].id;
  const union = chosen.slice(1).map((m) => m.id);
  const reasons = [];
  if (gotPrivacy) reasons.push(`${byId(primary).label || primary} finds private people (lowercase too), addresses and secrets`);
  if (union.length) reasons.push(`${union.map((id) => byId(id)?.label || id).join(' + ')} add${union.length === 1 ? 's' : ''} places and organisations`);
  if (!gotPrivacy && privacy) reasons.push(`Privacy Filter (~${residentMB(privacy)} MB) does not fit the ${budgetMB} MB this machine can spare for detectors`);
  reasons.push(`~${usedMB} MB of ${budgetMB} MB (this machine: ${Math.round((machine.totalRamMB || 0) / 1024)} GB)`);

  const alternatives = [];
  if (!gotPrivacy && privacy) {
    const servers = (providers || []).filter((p) => (p.capabilities || p.provides || []).includes('detect'));
    for (const p of servers) alternatives.push({ kind: p.reach === 'device' ? 'local-server' : 'server', id: p.id, why: `${p.name || p.id} can run the detection for this machine (${p.reach || 'remote'})` });
    if (!servers.length) alternatives.push({ kind: 'server', why: 'run detection on a server — an engine server on a bigger machine, or a hosted detector — and add it under Models' });
  }
  return { primary, union, budgetMB, usedMB, reason: reasons.join(' · '), skipped, alternatives };
}

/**
 * Trim a CONFIGURED union to what fits this machine, in priority order — the guard a
 * gateway applies before loading, so a config copied to a smaller laptop never swaps it.
 * Returns the ids to load and the ones skipped with the reason.
 */
export function fitUnion(primaryId, unionIds, catalog = [], machine = {}) {
  const budgetMB = detectorBudgetMB(machine.totalRamMB);
  const cost = (id) => residentMB(catalog.find((m) => m.id === id) || { approxMB: 200 });
  let usedMB = cost(primaryId); // the primary always loads — the user chose it
  const load = [];
  const skipped = [];
  for (const id of unionIds || []) {
    const c = cost(id);
    if (usedMB + c > budgetMB) { skipped.push({ id, why: `needs ~${c} MB; ${Math.max(0, budgetMB - usedMB)} MB of the ${budgetMB} MB detector budget left on this machine` }); continue; }
    load.push(id); usedMB += c;
  }
  return { load, skipped, budgetMB, usedMB };
}
