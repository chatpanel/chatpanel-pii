// Pure turn-level orchestration shared by every ChatPanel surface (extension,
// gateway, bridge). It composes the deterministic engine (pii-redact.js) into the
// message pipeline and applies the tier / scope / dictionary gating.
//
// What lives HERE (portable): redactOutbound, redactToolResult/redactResult,
// makeStreamRestorer, restore/restoreDeep, effectiveTier + gating.
//
// What stays in the EXTENSION (host glue, NOT here): reading
// settings.ui.piiRedaction, the module-level Pro entitlement, and chrome storage.
// Those wrap these pure functions with host-specific config.

import { redactText, restoreText, restoreWithAliases } from './pii-redact.js';

export function redactionEnabled(cfg) {
  return !!(cfg && cfg.mode && cfg.mode !== 'off');
}

// The entity (name/org) tier is Pro; Free silently falls back to deterministic
// regex so the feature still does something useful without the upsell breaking.
export function effectiveTier(cfg, isPro) {
  const t = cfg?.tier === 'full' ? 'full' : 'basic';
  return t === 'full' && !isPro ? 'basic' : t;
}

// Free ceiling: deterministic SECRET redaction on CHAT only, with a small
// dictionary. Names/orgs (full tier), wider scope, an unlimited dictionary, and
// the model layer are Pro. Enforced here as defense-in-depth.
export const FREE_DICT_LIMIT = 3;

export function gatedDictionary(cfg, isPro) {
  const d = Array.isArray(cfg?.dictionary) ? cfg.dictionary : [];
  return isPro ? d : d.slice(0, FREE_DICT_LIMIT);
}

export function gatedScope(cfg, isPro) {
  const s = cfg?.scope || {};
  if (isPro) return s;
  return { chat: s.chat !== false, context: false, history: false, toolResults: false };
}

export function redactOpts(cfg, isPro, entities) {
  return {
    tier: effectiveTier(cfg, isPro),
    entities: entities || [],
    dictionary: gatedDictionary(cfg, isPro),
  };
}

// Returns redacted COPIES — never mutates the stored conversation.
export function redactOutbound({ messages, system, vault, cfg, isPro = false, entities = [] }) {
  if (!redactionEnabled(cfg) || !vault) return { messages, system };
  const opts = redactOpts(cfg, isPro, entities);
  const scope = gatedScope(cfg, isPro);
  const redactMsg = (m) => {
    const copy = { ...m };
    if (scope.chat !== false && m.content) copy.content = redactText(m.content, vault, opts);
    if (Array.isArray(m.attachments)) {
      copy.attachments = m.attachments.map((a) => {
        if (a.kind === 'image' || !a.text) return a;
        const isHistory = a.kind === 'history-rag';
        if (isHistory ? scope.history === false : scope.context === false) return a;
        return { ...a, text: redactText(a.text, vault, opts) };
      });
    }
    return copy;
  };
  return {
    messages: (messages || []).map(redactMsg),
    system: system ? redactText(system, vault, opts) : system,
  };
}

export function redactToolResult(text, { vault, cfg, isPro = false, entities = [] } = {}) {
  if (!redactionEnabled(cfg) || !vault || !gatedScope(cfg, isPro).toolResults) return text;
  if (typeof text !== 'string') return text;
  return redactText(text, vault, redactOpts(cfg, isPro, entities));
}

// Streaming-safe restorer. push() returns text safe to display now; flush() the rest.
export function makeStreamRestorer(vault) {
  let buf = '';
  return {
    push(chunk) {
      if (!vault) return chunk || '';
      buf += chunk || '';
      const open = buf.lastIndexOf('[[');
      let safe;
      if (open !== -1 && !buf.slice(open).includes(']]')) {
        safe = buf.slice(0, open);
        buf = buf.slice(open);
      } else {
        safe = buf;
        buf = '';
      }
      return restoreText(safe, vault);
    },
    flush() {
      const out = vault ? restoreText(buf, vault) : buf;
      buf = '';
      return out;
    },
  };
}

export function restore(text, vault) {
  return vault ? restoreText(text, vault) : text;
}

// Deep-restore a value (tool-call args contain tokens; local tools must run on the
// REAL values). restoreWithAliases undoes pseudonyms too — local lookups hit real
// data; only the model stays blinded.
export function restoreDeep(value, vault) {
  if (!vault) return value;
  if (typeof value === 'string') return restoreWithAliases(value, vault);
  if (Array.isArray(value)) return value.map((v) => restoreDeep(v, vault));
  if (value && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value)) out[k] = restoreDeep(value[k], vault);
    return out;
  }
  return value;
}

export function redactResult(result, ctx) {
  if (typeof result === 'string') return redactToolResult(result, ctx);
  if (result && typeof result === 'object' && typeof result.text === 'string') {
    return { ...result, text: redactToolResult(result.text, ctx) };
  }
  return result;
}
