// Who is calling a ChatPanel localhost server — and how far to trust it.
//
// The bridge (4319) and the gateway (4320) bind to loopback, so every caller is on this
// machine or in this machine's browser. That is not one population, it is four, and the
// server has to tell them apart from the two things a request carries: its `Origin` header
// (set honestly by every browser, absent from a native process) and a per-install bearer
// token (a file only this user can read).
//
//   token     the per-install token was presented → a process running as the user (the
//             desktop app, the CLI, `chatpanel-gateway mcp`) or a client the user PAIRED.
//   pinned    the Origin is one of ChatPanel's OWN published extension ids. A browser never
//             lets one extension send another's origin, so this is the extension itself.
//   unpaired  a browser extension we do not recognise, or a page on localhost. Sandboxed —
//             no filesystem, cannot read the token — but it CAN talk to this port, and it
//             reads whatever the reply says. Treated as a stranger at the door: allowed to
//             chat, never to reach the machine, until the user pairs it.
//   local     no Origin, no token: some native process. Fine for the open data plane, not
//             for anything that spawns an agent or reconfigures a server.
//   web       any other web origin. Refused before this classification is ever consulted;
//             it exists so the answer is never "undefined".
//
// The split matters because of what an agent can do. A capped tool policy ("read-only, no
// web tools") is a real defence when the REPLY goes somewhere safe (a paired phone) — but a
// caller that is itself the egress reads the reply, so for an unpaired caller the only cap
// that means anything is "no filesystem at all" (reach `device`). That is why `unpaired`
// maps to the conversational tier, not the read tier.
//
// Pure: no node APIs, no crypto — so the bridge can vendor it and the extension can show a
// user the same classification the server applied. The pairing-code store takes `now` and
// `random` injected for the same reason.

/** ChatPanel's published extension ids. A dev build has a different id — see EXTRA ids. */
export const CHATPANEL_EXTENSION_IDS = Object.freeze([
  'icemacffhbgnfoofclgdbcdmnlkkklem', // Chrome Web Store
  'jkmmbleapaognlonbnllpaoeibmfkjmp', // Microsoft Edge Add-ons
]);

const EXT_ID = /^[a-p]{32}$/;

/** Parse an operator's comma/space-separated extension-id list (an env var or config key). Invalid ids are dropped. */
export function parseExtensionIds(raw) {
  return String(raw || '')
    .split(/[\s,]+/)
    .map((s) => s.trim().toLowerCase().replace(/^chrome-extension:\/\//, '').replace(/\/+$/, ''))
    .filter((s) => EXT_ID.test(s));
}

/**
 * What an Origin header says about the sender.
 *   'none'      no header — a native process
 *   'pinned'    chrome-extension://<one of ours or the operator's extra ids>
 *   'extension' chrome-extension:// or moz-extension:// we do not recognise. Firefox origins are
 *               a per-profile UUID, so even ChatPanel's own Firefox build lands here — it pairs.
 *   'localhost' http://localhost / 127.0.0.1 / [::1] — a dev page
 *   'web'       anything else
 */
export function classifyOrigin(origin, { extensionIds = [] } = {}) {
  const o = String(origin || '').trim();
  if (!o) return 'none';
  const m = /^chrome-extension:\/\/([a-p]{32})\/?$/i.exec(o);
  if (m) {
    const id = m[1].toLowerCase();
    if (CHATPANEL_EXTENSION_IDS.includes(id) || (extensionIds || []).includes(id)) return 'pinned';
    return 'extension';
  }
  if (/^(chrome|moz)-extension:\/\//i.test(o)) return 'extension';
  if (/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?\/?$/i.test(o)) return 'localhost';
  return 'web';
}

/**
 * The trust level of one request. `hasToken` is the server's own (timing-safe) token check;
 * this function never sees the secret. Token beats everything: a paired Firefox extension or a
 * dev build presents the token and is trusted exactly like the pinned one.
 */
export function callerTrust({ origin, hasToken = false, extensionIds = [] } = {}) {
  if (hasToken) return 'token';
  const kind = classifyOrigin(origin, { extensionIds });
  if (kind === 'pinned') return 'pinned';
  if (kind === 'extension' || kind === 'localhost') return 'unpaired';
  if (kind === 'none') return 'local';
  return 'web';
}

/** Trusted enough to run an agent with the user's configured permissions, reconfigure a server, or mint a pairing code. */
export function isPaired(trust) {
  return trust === 'token' || trust === 'pinned';
}

// Reach tiers, least to most. `device` is conversational only; `trusted` is machine-wide
// read with no egress; `any` is "no cap here — the configured permission mode applies".
const REACH_RANK = Object.freeze({ device: 0, trusted: 1, any: 2 });

/** The stricter of two reach tiers. An unknown tier is the strictest — fail closed. */
export function minReach(a, b) {
  const ra = REACH_RANK[a] ?? 0;
  const rb = REACH_RANK[b] ?? 0;
  const pick = ra <= rb ? a : b;
  return REACH_RANK[pick] === undefined ? 'device' : pick;
}

/** The reach ceiling a caller of this trust may run an agent under, or null for "no ceiling from trust". */
export function reachCeiling(trust) {
  if (isPaired(trust)) return null;
  return 'device';
}

// Run options an unpaired caller must never choose. Each one reaches the machine directly:
// a working directory or worktree to read, credentials to hand the run, a permission mode
// to escalate, argv/env to smuggle a flag through, a sandbox grant to widen what the process
// may reach on the network or write. With reach `device` the agent has no filesystem anyway;
// stripping these is what makes that true before the engine is chosen.
const UNPAIRED_STRIP = Object.freeze([
  'workingDir', 'workspace', 'grants', 'connectionId', 'permissionMode', 'extraArgs', 'env', 'runEnv', 'reach', 'sandbox',
]);

/**
 * Apply a caller's ceiling to the run options a request asked for. A paired caller's options
 * come back untouched. An unpaired caller's come back with the machine-reaching options
 * removed and `reach` forced to the ceiling (never looser than what the body declared).
 */
export function capRunOptions(options, trust) {
  const ceiling = reachCeiling(trust);
  const src = options && typeof options === 'object' ? options : {};
  if (!ceiling) return { ...src };
  const out = {};
  for (const [k, v] of Object.entries(src)) if (!UNPAIRED_STRIP.includes(k)) out[k] = v;
  out.reach = minReach(src.reach || ceiling, ceiling);
  return out;
}

/** Engines that enforce a reach ceiling in their tool policy. A capped run may only use one of these. */
export const REACH_ENFORCING_ENGINES = Object.freeze(['claude']);

/**
 * Whether an engine may run under a capped reach. Only an engine that turns `reach` into a
 * tool policy can honour a cap; any other would silently run at its configured permission
 * mode, which is the escalation the cap exists to prevent.
 */
export function engineHonoursReach(engine, reach) {
  if (!reach || reach === 'any') return true;
  return REACH_ENFORCING_ENGINES.includes(String(engine || ''));
}

// ---------------------------------------------------------------------------------------
// Pairing codes. How a client that CANNOT read the token file (a Firefox build, a dev build,
// a browser on the far side of a sandbox) gets one: the user asks the running server for a
// code (`chatpanel-gateway pair`, admin-authorized), types it into the client, and the client
// exchanges it for the token over loopback. The code is short-lived, single-use, and a
// handful of wrong guesses burn it — 6 digits at 5 attempts in 5 minutes is not brute-forceable
// from a page, and the page cannot ask for a new one.

export const PAIRING_TTL_MS = 5 * 60 * 1000;
export const PAIRING_MAX_ATTEMPTS = 5;

/** Render a 6-digit code as `123-456` for a human; the store compares digits only. */
export function formatPairingCode(code) {
  const d = String(code || '').replace(/\D/g, '');
  return d.length === 6 ? `${d.slice(0, 3)}-${d.slice(3)}` : d;
}

/**
 * A single-slot pairing store. Creating a new code replaces the old one, so at most one code
 * is live per server. `random()` must return a float in [0, 1) — `Math.random` is fine for a
 * 6-digit code that lives five minutes behind an attempt cap; pass `crypto`-backed for taste.
 */
export function createPairingStore({ now = () => Date.now(), random = Math.random, ttlMs = PAIRING_TTL_MS, maxAttempts = PAIRING_MAX_ATTEMPTS } = {}) {
  let live = null; // { code, expiresAt, attempts }

  function issue() {
    const code = String(Math.floor(random() * 1e6)).padStart(6, '0');
    live = { code, expiresAt: now() + ttlMs, attempts: 0 };
    return { code, display: formatPairingCode(code), expiresAt: live.expiresAt };
  }

  /** Try a code. Returns { ok: true } once and burns the code; { ok: false, reason } otherwise. */
  function claim(input) {
    if (!live) return { ok: false, reason: 'no pairing code is active — ask the server for one' };
    if (now() > live.expiresAt) { live = null; return { ok: false, reason: 'pairing code expired — ask for a new one' }; }
    live.attempts += 1;
    const guess = String(input || '').replace(/\D/g, '');
    if (guess.length === 6 && guess === live.code) { live = null; return { ok: true }; }
    if (live.attempts >= maxAttempts) { live = null; return { ok: false, reason: 'too many wrong codes — ask for a new one' }; }
    return { ok: false, reason: 'wrong pairing code' };
  }

  function active() {
    if (live && now() > live.expiresAt) live = null;
    return live ? { expiresAt: live.expiresAt, attemptsLeft: maxAttempts - live.attempts } : null;
  }

  return { issue, claim, active };
}
