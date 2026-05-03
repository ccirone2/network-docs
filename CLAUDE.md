# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repo at a glance

A single self-contained web app for documenting home/lab network inventories. No build step, no package manager, no test runner.

- `network-inventory.html` — the entire application (HTML + embedded CSS + embedded JS).
- `network-import.schema.json` — JSON Schema (draft 2020-12) describing the import/export file format. Living document; must stay in sync with `network-inventory.html` (see *Import / Export*).

## Repo layout

Tracked: `network-inventory.html`, `network-import.schema.json`, `fixtures/{empty,full,encrypted}.json`, `CLAUDE.md`, `.gitignore`.

Untracked but present locally:
- `evidence/` — per-device validation walk (`COLLECTION_PLAN.md` is the only file kept in git). When the user references "evidence for X", look here.
- `mockups/` — standalone HTML files that were the design exploration for the current hybrid tile pattern. **Frozen reference, not active code** — do not edit to "keep in sync" with `network-inventory.html`.
- `network-import.json` — the user's real home-lab inventory. Useful as a realistic import/export sample; never commit.

`.gitignore` includes `*.md`, so new markdown docs are silently untracked unless added with `git add -f`.

## How to "run"

Open `network-inventory.html` directly in a browser. No server, no install. To reset state during development, clear localStorage key `homenet.inventory.v1` for the file's origin, or use the in-app **Reset** button. Append `?selftest=1` to the URL to run the fixture round-trip self-test.

## Hard constraints

Non-negotiable unless the user says otherwise:

- One HTML file. No external libraries, no CDN, no build step, no backend.
- Must work from `file://`. Do not introduce APIs that require an HTTP origin.
- Vanilla JS only.

## Architecture

### `data` / `state` split

The most important thing to understand before editing.

```
data = {
  schemaVersion: 0,
  networks: { [networkId]: <network> },
  activeNetworkId: "..."
}

<network> = {
  network:     { name, description },
  vlans:       { [vlanId]:       { name, gateway, dhcp } },
  hosts:       { [hostId]:       { kind, role, vm_id, software, manufacturer, model, ..., interfaces: [...], services: [...], peripherals: [...], links: [...] } },
  credentials: { [credentialId]: { type, username, password, external_ref, notes } }
}
```

Enum values for `kind`, `role`, service `category`, `credential.type`, etc. live in `network-import.schema.json` — that file is the source of truth.

Two top-level vars in the script:

- `data` — the full multi-network store; what's persisted to localStorage.
- `state` — **a re-pointed reference** to `data.networks[data.activeNetworkId]`.

All entity CRUD reads from `state.vlans` / `state.hosts` / `state.credentials` / `state.network`. When the active network changes, the code does `state = data.networks[newId]` and re-renders. Don't introduce a separate copy of the active network — keep it as a live reference into `data`.

Notable record details:
- `software` is a structured sub-object. Empty `software.name` hides the chip; `formatSoftware` composes the display string.
- Each service has a stable per-host `id` (slug + collision suffix, readonly after creation) so refs survive name changes.
- Credential ↔ host/service linkage is **one-way in the data**: only `host.credential_ref` and `service.credential_ref` are stored. The credential edit modal renders the reverse view as multi-select checkboxes and propagates by writing/clearing those fields. Do not add a `credential.linked_hosts` field — it would create a second source of truth.

### Persistence

- Storage key: `homenet.inventory.v1` (storage-key version, independent of schema version). Files carry top-level `schemaVersion` matching `SCHEMA_VERSION` (currently `0` — frozen during in-development phase, do not change without explicit instruction). Loaders **reject** mismatches — no migration code, no legacy fallbacks. When the user authorizes a bump, change `SCHEMA_VERSION` in `network-inventory.html`, both `schemaVersion.const` values in `network-import.schema.json`, and `seedData` / `network-import.json` / `fixtures/*.json` (plus the inline `<script type="application/json">` blocks in `network-inventory.html`) in lockstep.
- `normalizeData` accepts both the multi-network and single-network shapes (used by Import). `normalizeNetwork` rebuilds each record from a fixed key list, so **unknown fields are silently dropped** (the schema doesn't set `additionalProperties: false`, but the loader is effectively that strict). Whenever you add a field to a record type, add it to the matching `normalizeNetwork` branch.
- Separate localStorage key `homenet.viz.v1` stores transient Map-tab view prefs (`{ version: 1, activeLayer }`) so a Reset doesn't clobber UI state. Not part of the schema.
- Separate localStorage key `homenet.inventory.envelope.v1` stores the encryption envelope (`{ kdf, cipher, encrypted_fields }`) when an encrypted file has been imported. Without it, any `{iv, ct}` blobs in `homenet.inventory.v1` are unrecoverable on reload — `startApp` toasts and renders read-only when blobs are present but the envelope is missing. `Reset` and a clean (non-encrypted) Import both clear this key.

### Encryption

Per-credential password encryption. The plaintext file format and SCHEMA_VERSION are unchanged — encryption is applied **per value**, in-place. A `Credential.password` field is either a string (plaintext) or a `{iv, ct}` blob (AES-GCM ciphertext + auth tag, base64). The loader detects the blob shape structurally; nothing else in the schema knows about encryption.

- **Crypto IIFE** (`network-inventory.html` near the constants): single closure holds `derivedKey` (CryptoKey, capabilities `["encrypt", "decrypt"]`) and a per-credential plaintext cache. Public surface: `unlock(pp, kdf)` → derive PBKDF2 → AES-GCM key; `decryptField(blob, cacheKey)` → plaintext (cached); `encryptField(plaintext)` → fresh-IV blob; `lock()` → drops key + clears cache; `peek(cacheKey)` / `setCache(cacheKey, pt)` / `clearCache(cacheKey?)`; `isUnlocked()` / `isEncryptedSession()` / `isEncryptedBlob(v)`.
- **Per-write fresh IV is non-negotiable.** AES-GCM nonce reuse with the same key is catastrophic. `encryptField` generates 12 bytes from `crypto.getRandomValues` every call. The self-test `edit-roundtrip` invariant guards this — two encryptions of the same plaintext must have different IVs.
- **Save flow.** In an encrypted session the credential save handler (`openCredentialForm`'s `onSave`) takes the form's plaintext, encrypts with `encryptField` if non-empty (empty stays plaintext `""` — the empty string is not a secret), assigns the resulting blob to `state.credentials[id].password`, then `setCache`s the plaintext so an immediate reveal doesn't re-decrypt. A post-save sanity loop rejects malformed shapes (`return false` keeps the modal open). Edit pre-fill (`openCredentialForm`'s opener) decrypts the existing blob into the form's input — `c` is a clone, so state isn't touched until save.
- **Lock semantics.** Lock drops the in-memory key and the plaintext cache. The data on disk is unchanged. Reveal/Copy/Edit re-prompt for the passphrase via `promptUnlockForReveal()`. The `Lock` header button is hidden in plaintext sessions (`updateLockButtonVisibility`).
- **Export.** `exportAll` and `exportCurrent` wrap the payload in `{ kdf, cipher, encrypted_fields, data }` from `readEnvelopeFromStorage()` whenever `Crypto.isEncryptedSession()`. A missing envelope aborts the download with a toast — never emit blobs unwrapped. A mixed state (some plaintext passwords, some blobs — e.g. a credential that was edited to empty) round-trips as-is; do not normalize on export.
- **`setCache` is the only public cache mutation path.** Don't poke the cache from outside the IIFE.

### Rendering

- `render()` is a full re-render of `#content`. No virtual DOM, no diffing. After any state change: `saveState(); render();` (or `switchTab(...)`, which calls render).
- Tab content lives in `renderDashboard / renderVlans / renderHosts / renderMap / renderInterfaces / renderServices / renderCredentials`.
- Entity-level button actions go through a **single delegated click listener on `#content`** driven by `data-action` attributes and the `CONTENT_ACTIONS` dispatch table. Prefer adding a `data-action` entry over per-render `addEventListener` — it survives re-renders for free. Form-internal listeners stay local to their builder.
- Map tab: single pane, four interchangeable layers (`networks`, `devices`, `hosts`, `services`). Devices uses a **two-pass layout** — pass 1 appends cards in `requestAnimationFrame`; pass 2 measures `offsetHeight` and absolutely positions with cumulative y-offsets so cards never overlap. Connectors render on a separate SVG layer underneath. Cross-layer jumps use a one-step `jumpStack` with a back-pill; transient state does not persist.

### Card / tile design philosophy

Every list tab and every Map row uses the same **hybrid** layout. Rules:

- **One primary anchor per card.** The single fact a user scans for is the visual headline — gateway CIDR for a VLAN, mgmt IP for a host, URL for a service. Everything else is supporting.
- **Foot row for secondary metadata.** Muted `font-size:12px` row, facts separated by `<span class="dot"></span>`. Wrap *values* in `<b>` (foot CSS styles `<b>` as mono + bold + full-contrast); surrounding label text stays muted. Pattern: `cred <b>prox-root</b> · hosted on <b>prox01</b> (VMID 100)`.
- **Header sub-line is mono.** Identifiers (hostnames, slugs, ids) live in `var(--font-mono)` to separate machine-facing strings from human-facing names.
- **Never repeat the same identifier across header / sub / foot.** If the title is the host name, don't also print `Host: <name>` below.
- **No `<dl>` / label-value lists for cards.** The label column wastes horizontal space and labels repeat under every card. Inline foot rows carry the same info at lower visual weight.
- **Compact line tables for nested collections.** Inside a host card, interfaces and services render as 4-column grid rows (`.hc-line` with `.name` / `.val` / `.right` / `.row-actions`), not chip-soup ribbons or framed sub-cards.
- **Per-tab class namespaces.** `.vlan-card`+`.vc-*`, `.host-card`+`.hc-*`, `.iface-card`+`.ic-*`, `.svc-card`+`.sc-*`, `.cred-card`+`.cc-*`, `.map-row.hybrid`+`.map-*`. Keeps selectors short and prevents cross-tab style bleed.
- **Dashboard tiles are minimal, not hybrid.** Four summary tiles deliberately omit the breakdown line — they're a glance, not a record.

### Modals

- One shared `<dialog id="modal">`. Open with `openModal({ title, sub, body, onSave, saveLabel, saveKind })`. Returning `false` from `onSave` keeps the modal open (validation failure).
- Separate `<dialog id="confirm">` for destructive prompts via `confirmDelete({ title, message, onConfirm, okLabel })`.
- Form helpers: `field(...)`, `buildRepeater(...)` (list-of-strings), `buildVlanMultiSelect(...)` (trunk allowed-VLANs), `buildLinkMultiSelect(...)` (generic checkbox list, used for credential ↔ host/service linkage).

### Search and filters

`searchQuery` is a single shared string. Each section calls its own `matchVlan` / `matchHost` / inline filter — extend the relevant `match*` when adding a searchable attribute, don't add parallel search state. The Map tab reuses `matchVlan` and `matchHost` across all four layers. The Services tab has a separate `serviceCategoryFilter` that composes with `searchQuery`. Both reset on network switch / import / reset.

### IDs and refs

Record IDs (vlan, host, credential, network) are user-facing stable keys. Once created they are readonly. ID helpers: `slugify`, `uniqueId`, `newCredId`, `uniqueNetworkId`.

Deletes do **not** rewrite references in other records — they leave dangling refs and the confirm prompt shows the count of dependents. Preserve this; cascading edits would surprise users.

`validateRefs(net)` is the audit pass that finds dangling refs (`host.management_vlan`, `host.hosted_on`, `host/service.credential_ref`, `interface.connected_to / access_vlan / native_vlan / allowed_vlans`). It runs after import and surfaces results via `reportDanglingRefs` (toast + `console.table`); it is **not** auto-cleanup. Extend it when adding a new ref-shaped field.

### Network switcher

The header brand is a button (`#switcher`) that toggles `#net-popover` (rebuilt each open by `buildPopover`). "Manage all networks…" opens a modal with full per-network CRUD (`openManageNetworksModal`). All three entry points call the same `switchNetwork / createNetworkAndSwitch / deleteNetwork` functions — keep that single source of truth.

### Import / Export

- **Export** chooses full multi-network backup or just the current network (single-network shape).
- **Import** sniffs the file: multi → replace all (confirm); single → "add as new network" (recommended) or "replace current network".
- Both paths run through `normalizeData` / `normalizeNetwork`. Adding a field means updating those normalizers.
- `network-import.schema.json` is the canonical description of both shapes plus all enum constants. Whenever you add/remove/rename a field, change a default, or change an enum in `network-inventory.html`, update the schema in the same change.

### Fixtures and `?selftest=1`

`fixtures/empty.json` (single-network), `fixtures/full.json` (multi-network), and `fixtures/encrypted.json` (envelope wrapping a copy of `full.json` with all `credential.password` values encrypted) exercise the full record surface plus the encryption path. All three are inlined into `network-inventory.html` as `<script type="application/json">` blocks (`id="fixture-empty"`, `id="fixture-full"`, `id="fixture-encrypted"`) so the self-test can read them under `file://` (where `fetch` of siblings fails).

**Sync rule:** inline blocks and standalone `fixtures/*.json` must stay byte-identical. No automated guard — edit both. `fixtures/encrypted.json` is the byte-for-byte encrypted form of `fixtures/full.json` under passphrase `"selftest"` — its KDF (`{ name: "PBKDF2", salt: "c2VsZnRlc3Qtc2FsdCEhIQ==", iterations: 1000, hash: "SHA-256" }`) and the matching plaintext reference must stay aligned, otherwise the encrypted-fixture invariant fails.

`?selftest=1` runs `runSelfTest()` after first paint and checks four invariants:
- **fidelity** (per plaintext fixture) — `normalizeData(fixture)` equals the fixture (modulo single→multi wrap). Catches dropped/transformed fields.
- **idempotency** (per plaintext fixture) — re-stringifying and re-normalizing yields the same value. Catches non-stable defaults, non-deterministic ids.
- **encrypted fixture (envelope round-trip)** — unlock with `SELFTEST_PASSPHRASE`, walk every `credentials.*.password` blob, decrypt, and compare against the matching plaintext from `fixtures/full.json`. Locks the live session at start AND end (Phase 1 has no way to restore prior unlocked state without the original passphrase) — if the live session was unlocked, the user is re-prompted on next reveal.
- **edit-roundtrip (per-write fresh IV)** — encrypt `"new-password-123"` twice, assert both decrypt back, assert the two IVs differ. Skipped (with `SKIP (crypto.subtle unavailable)`) when `crypto.subtle.encrypt` isn't available.

Fixtures are written in *post-normalize* shape, which is what makes fidelity work — every key the normalizer produces is already present, so a missing key in the output = the normalizer dropped it. The runner does NOT touch `data` / `state` / localStorage. If you add a field to a record type, extend BOTH `normalizeNetwork` AND `fixtures/full.json` (and the inline block) — otherwise fidelity fails. Touching `fixtures/full.json` also requires regenerating `fixtures/encrypted.json` (and its inline block) so the encrypted-fixture invariant keeps passing — they share a plaintext reference.

## Editing conventions

- File order in CSS: tokens → base → components → buttons → search → cards → modal → forms → toasts → responsive. In JS: constants → seed → helpers → state → switcher → modals → form builders → tabs → render dispatcher → per-section renderers → per-section forms → import/export → first paint. New code slots into the matching section.
- CSS uses `:root` custom properties (`--space-*`, `--radius-*`, `--shadow-*`, color tokens). Reuse them; don't hardcode.
- All user-supplied strings in template literals go through `escapeHtml`. Don't introduce raw interpolation.
- The codebase is comment-free by convention. Add a comment only when the WHY is non-obvious (subtle invariant, workaround, surprising behavior). No section dividers, no what-the-code-does comments.
