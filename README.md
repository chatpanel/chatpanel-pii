# chatpanel-pii

The **canonical ChatPanel privacy engine** — reversible PII redaction +
pseudonymization with local entity detection. Pure, dependency-free ESM. This is
the **single source of truth** shared by the ChatPanel
[extension](https://github.com/chatpanel/chatpanel-extension),
[gateway](https://github.com/chatpanel/chatpanel-gateway), and
[bridge](https://github.com/chatpanel/chatpanel-bridge): a privacy feature added
here is picked up by all of them.

```js
import { createVault, redactText, restoreText, detectEntities } from 'chatpanel-pii';

const vault = createVault();
const safe = redactText('email alex@example.com', vault, { tier: 'basic' });
// → 'email [[EMAIL_1]]'
restoreText(safe, vault);
// → 'email alex@example.com'
```

The model only ever sees opaque, stable placeholders like `[[PERSON_1]]` /
`[[EMAIL_2]]`, so it can still reason about *who said what* without seeing the
real values — and they're reconstructed locally on the way back.

## What's inside

| Module | Exports | Role |
|--------|---------|------|
| `pii-redact.js` | `createVault`, `redactText`, `restoreText`, `restoreWithAliases`, `vaultToJSON`/`vaultFromJSON`, `hasToken` | deterministic redact/restore + the per-conversation vault |
| `pii-detect.js` | `detectEntities`, `normalizeEntities`, `EXTRACT_SYS`, … | local entity detection (any HTTP NER endpoint, or a local OpenAI-compatible LLM) |
| `pipeline.js` | `redactOutbound`, `makeStreamRestorer`, `restore`, `restoreDeep`, `redactResult`, `effectiveTier`, `gatedDictionary`, `gatedScope` | pure turn orchestration + the free/Pro tier, scope, and dictionary gating |

Import the barrel (`chatpanel-pii`) or a submodule
(`chatpanel-pii/pii-redact.js`).

## Tiers

- **`basic`** — deterministic regex: emails, phones, IPs, cards (Luhn), SSNs, API
  keys, plus a small user dictionary.
- **`full`** — basic + entity-aware: detected people / orgs / locations and an
  unlimited custom dictionary. `effectiveTier(cfg, isPro)` downgrades `full`→`basic`
  for non-Pro callers, so consumers enforce free/Pro identically.

A dictionary entry with an `alias` **pseudonymizes** (permanent substitution the
model and the user both see); without one it **redacts** to a reversible token.

## Design notes

- **Pure + dependency-free** so it unit-tests trivially and runs identically in a
  browser extension, a Node proxy, and a CLI bridge.
- **Reversibility is best-effort**: if a model paraphrases a placeholder instead
  of echoing it, that reference won't restore — but the privacy guarantee (the
  real value never left the device) always holds.

## License

Source-available under the same license as the rest of ChatPanel — see
[LICENSE](LICENSE).
