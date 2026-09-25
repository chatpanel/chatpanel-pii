// Shared host classifier + outbound-URL guard — the SSRF primitive.
//
// One implementation of "what is a loopback / cloud-metadata / private host",
// delivered the way the rest of @chatpanel/pii is: npm dependency for the
// gateway/bridge, vendorable into the browser extension (pure — only URL + string
// ops, no node APIs, so it runs in a Worker/service-worker too). Replaces the
// hand-maintained copies in the bridge (src/ssrf.js) and the extension
// (js/context.js isBlockedHost) so a security guard can't silently drift between
// the direct client path and the proxied path. See docs/secure-data-plane.md.
//
// The policy knobs cover the two legitimate trust contexts:
//   • A MODEL / API / MCP endpoint (gateway upstream, bridge MCP proxy) may live on
//     loopback (Ollama, LM Studio) or the LAN (a homelab GPU box) — so those are
//     allowed by default — but must NEVER reach cloud instance metadata.
//   • A WEB PAGE fetch (link title, page context) has no business touching loopback
//     or any private host at all — call with { allowLoopback:false, allowPrivate:false }.
// Cloud metadata (169.254.169.254 & friends) and non-http(s) schemes are blocked in
// BOTH contexts, unconditionally. Re-run the assert on every redirect hop.
//
// A host is classified on its ADDRESS, never on how it was spelled: an IPv4-mapped
// IPv6 literal is folded back to dotted v4 first, because a dual-stack socket routes
// [::ffff:a9fe:a9fe] to 169.254.169.254 and a string rule would not.

function ipv4(h) {
  const m = String(h).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  if (o.some((n) => n > 255)) return null;
  return o;
}

// Parse an IPv6 literal into its 8 hextets (null if it isn't one). The v6 rules were
// startsWith() on the host STRING, wrong both ways: it missed every compressed form,
// and it refused public domains beginning fc/fd/fe8-feb (fdic.gov, fcc.gov, fda.gov).
function ipv6(h) {
  if (!h.includes(':')) return null;
  let s = h;
  const dotted = s.match(/^(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/); // ::ffff:1.2.3.4
  if (dotted) {
    const o = ipv4(dotted[2]);
    if (!o) return null;
    s = `${dotted[1]}${(((o[0] << 8) | o[1]) >>> 0).toString(16)}:${(((o[2] << 8) | o[3]) >>> 0).toString(16)}`;
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const hextets = (part) => (part ? part.split(':') : []).map((x) => (/^[0-9a-f]{1,4}$/.test(x) ? parseInt(x, 16) : NaN));
  const head = hextets(halves[0]);
  const tail = halves.length === 2 ? hextets(halves[1]) : [];
  if (head.concat(tail).some(Number.isNaN)) return null;
  const fill = 8 - head.length - tail.length;
  if (halves.length === 2 ? fill < 0 : fill !== 0) return null;
  return head.concat(new Array(halves.length === 2 ? fill : 0).fill(0), tail);
}

// An IPv4-MAPPED address (::ffff:0:0/96) holds a v4 address in its low 32 bits and a
// dual-stack socket connects it straight there, so 169.254.169.254 was reachable as
// [::ffff:a9fe:a9fe] (the URL parser rewrites the dotted form to hex, so that is the
// spelling that arrives). Fold it back to dotted so the v4 rules decide both spellings.
function unmapIpv4(h) {
  const x = ipv6(h);
  if (!x) return h;
  if (x[0] || x[1] || x[2] || x[3] || x[4] || x[5] !== 0xffff) return h;
  return [x[6] >> 8, x[6] & 255, x[7] >> 8, x[7] & 255].join('.');
}

const norm = (hostname) => unmapIpv4(String(hostname || '').toLowerCase().replace(/^\[|\]$/g, ''));

// Loopback = this host's own services (127.0.0.0/8, ::1, localhost, *.localhost).
export function isLoopbackHost(hostname) {
  const h = norm(hostname);
  if (!h) return false;
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  const x = ipv6(h);
  if (x) return x.slice(0, 7).every((n) => n === 0) && x[7] === 1;
  const o = ipv4(h);
  return !!(o && o[0] === 127);
}

// Cloud instance metadata — the sharpest SSRF target (credential theft). Covers the
// link-local IMDS of AWS/GCP/Azure/DO (169.254.169.254), AWS's IPv6 IMDS (fd00:ec2::254),
// Alibaba's 100.100.100.200, and the name-based metadata hosts. ALWAYS blocked — and
// fd00:ec2::254 needs its own rule because "private" is allowed in the endpoint context.
export function isMetadataHost(hostname) {
  const h = norm(hostname);
  if (h === 'metadata.google.internal' || h === 'metadata') return true;
  const x = ipv6(h);
  if (x) return x[0] === 0xfd00 && x[1] === 0x0ec2 && !x[2] && !x[3] && !x[4] && !x[5] && !x[6] && x[7] === 0x254;
  const o = ipv4(h);
  if (!o) return false;
  if (o[0] === 169 && o[1] === 254) return true;                 // 169.254.169.254 (+ link-local)
  if (o[0] === 100 && o[1] === 100 && o[2] === 100 && o[3] === 200) return true; // Alibaba IMDS
  return false;
}

// Private / internal address space, EXCLUDING loopback + metadata (checked
// separately): RFC1918, CGNAT, IPv6 ULA/link-local, mDNS .local, this-host 0.x/::.
export function isPrivateHost(hostname) {
  const h = norm(hostname);
  if (!h) return true;
  if (h.endsWith('.local')) return true;
  const x = ipv6(h);
  if (x) {
    if (x.every((n) => n === 0)) return true;                    // :: unspecified
    if ((x[0] & 0xfe00) === 0xfc00) return true;                 // ULA fc00::/7
    if ((x[0] & 0xffc0) === 0xfe80) return true;                 // link-local fe80::/10
    if ((x[0] & 0xffc0) === 0xfec0) return true;                 // site-local fec0::/10 (deprecated)
    if (x.slice(0, 6).every((n) => n === 0)) return true;        // ::/96 v4-compatible (not globally routable)
    if (x[0] === 0x64 && x[1] === 0xff9b) return true;           // NAT64 64:ff9b::/96 — a v4 target behind a translator
    return false;
  }
  const o = ipv4(h);
  if (o) {
    const [a, b] = o;
    if (a === 0 || a === 10) return true;                        // this-host / RFC1918
    if (a === 169 && b === 254) return true;                     // link-local
    if (a === 172 && b >= 16 && b <= 31) return true;            // RFC1918
    if (a === 192 && b === 168) return true;                     // RFC1918
    if (a === 100 && b >= 64 && b <= 127) return true;           // CGNAT
  }
  return false;
}

// Policy-driven classifier. Returns true if `hostname` must be blocked under `policy`.
// Defaults model the ENDPOINT context (loopback + LAN allowed, metadata never).
export function isBlockedHost(hostname, { allowLoopback = true, allowPrivate = true } = {}) {
  const h = norm(hostname);
  if (!h) return true;
  if (isMetadataHost(h)) return true;                            // never, in any context
  if (isLoopbackHost(h)) return !allowLoopback;
  if (isPrivateHost(h)) return !allowPrivate;
  return false;                                                  // public host
}

// Assert a URL is fetchable under `policy`; returns the parsed URL or throws.
// Call on the initial URL AND after every redirect hop.
export function assertFetchableUrl(u, policy = {}) {
  let parsed;
  try { parsed = new URL(u); } catch { throw new Error(`invalid URL: ${u}`); }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`only http(s) URLs allowed (got "${parsed.protocol}")`);
  }
  if (isBlockedHost(parsed.hostname, policy)) {
    throw new Error(`refusing to reach a blocked address (${parsed.hostname})`);
  }
  return parsed;
}

// Endpoint context: model/API/MCP upstream — loopback + LAN OK, metadata never.
export const assertEndpointUrl = (u, opts = {}) => assertFetchableUrl(u, { allowLoopback: true, allowPrivate: true, ...opts });
// Web-page context: no loopback, no private, no metadata — genuinely public only.
export const assertPublicWebUrl = (u) => assertFetchableUrl(u, { allowLoopback: false, allowPrivate: false });
