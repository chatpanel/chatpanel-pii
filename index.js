// chatpanel-pii — the canonical ChatPanel privacy engine. Single source of truth
// for reversible PII redaction + pseudonymization, shared by the extension, the
// gateway, and the bridge. Pure + dependency-free ESM.
//
//   import { createVault, redactText, restoreText, detectEntities } from 'chatpanel-pii';
//
// Submodules are also importable directly:
//   'chatpanel-pii/pii-redact.js'   deterministic redact/restore + vault
//   'chatpanel-pii/pii-detect.js'   local NER / LLM entity detection
//   'chatpanel-pii/pipeline.js'     pure turn orchestration + tier/scope gating

export * from './pii-redact.js';
export * from './pii-detect.js';
export * from './pipeline.js';
