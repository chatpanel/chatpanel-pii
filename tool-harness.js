// THE tool harness — one interception layer shared by every orchestrator
// (ChatPanel API + agent, gateway API + relay) so tool handling can't drift. It
// owns the boundaries around a model turn:
//
//   ⓪ selectTools  — inject + narrow the tools the model is offered (MCP-auto).
//   ② toTool       — what a tool RECEIVES: real values (so on-device / remote
//                    lookups work), or the redacted token for remote MCP tools
//                    when the user chose "redact remote".
//   ③ toModelResult— what the MODEL sees back: the tool result re-redacted so it
//                    stays blinded.
//   ④ toUser       — the final reply: reversible tokens restored (pseudonyms stay).
//
// PRIVACY IS OPTIONAL. With no `vault` (redaction off), ②③④ are pass-throughs —
// no latency, no placeholder confusion — but ⓪ selectTools STILL narrows, because
// not every turn is privacy-sensitive yet every turn benefits from fewer tools.
//
// Self-contained on the SYNCED engine files (pii-redact.js, tool-rank.js), so the
// extension (browser ESM) and the gateway (npm) run the exact same code. The caller
// passes the already-gated `redactOpts` ({tier, entities, dictionary}) it computed
// from cfg+isPro — keeping tier/dictionary Pro-gating out of the harness.

import { restoreText, restoreWithAliases, redactText } from './pii-redact.js';
import { narrowSpecs } from './tool-rank.js';

// MCP / remote tools are server-prefixed (mcp_server__tool). Local tools
// (history/meeting/page, or a client's core bash/read) are not — they always get
// real values and are never narrowed away.
export const isRemoteToolName = (name) => /^mcp[_-]/i.test(String(name || ''));

// Deep restore of a tool-call argument value, undoing reversible tokens AND
// pseudonyms (tools run locally / on real data; only the model stays blinded).
export function restoreToolArgs(value, vault) {
  if (!vault) return value;
  if (typeof value === 'string') return restoreWithAliases(value, vault);
  if (Array.isArray(value)) return value.map((v) => restoreToolArgs(v, vault));
  if (value && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value)) out[k] = restoreToolArgs(value[k], vault);
    return out;
  }
  return value;
}

export function makeToolHarness({ vault = null, toolData = 'real', redactOpts = null, redactResults = true } = {}) {
  const on = !!vault;                       // privacy enabled for this turn?
  const redactRemote = toolData === 'redactRemote';
  return {
    enabled: on,
    isRemoteTool: isRemoteToolName,

    // ⓪ Always-on tool selection (privacy-independent). `available` is any spec
    // list; `opts` forwards { cap, keep, name, description } to the shared ranker.
    selectTools(available, query, opts = {}) {
      return narrowSpecs(available, query, opts);
    },

    // ② What the tool receives.
    toTool(name, args) {
      if (!on) return args;                                    // privacy off → already real
      if (redactRemote && isRemoteToolName(name)) return args;  // keep PII off remote MCP
      return restoreToolArgs(args, vault);                      // real values for the tool
    },

    // ③ What the model sees back (re-redacted). Handles a string or a { text } shape.
    toModelResult(name, raw) {
      if (!on || !redactResults || !redactOpts) return raw;
      if (typeof raw === 'string') return redactText(raw, vault, redactOpts);
      if (raw && typeof raw === 'object' && typeof raw.text === 'string') {
        return { ...raw, text: redactText(raw.text, vault, redactOpts) };
      }
      return raw;
    },

    // ④ The final reply the user sees.
    toUser(text) {
      return on ? restoreText(text, vault) : text;
    },
  };
}
