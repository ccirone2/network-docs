# network-docs

A single-file web app for documenting home/lab network inventories. No build, no backend, no external dependencies. Open the HTML file in a browser; that's it.

## Live app

Deployed to GitHub Pages from `main`. After the first deploy, the URL will be:

> `https://<your-github-username>.github.io/network-docs/`

You can also clone this repo and open `network-inventory.html` directly from `file://` — same app, same behavior.

## What's tracked here

| File | Purpose |
|---|---|
| `network-inventory.html` | The app — HTML, CSS, JS, all in one file. |
| `network-import.schema.json` | JSON Schema (draft 2020-12) for the import/export format. |
| `encrypt_hosts.py` | CLI helper for first-time bulk encryption of a plaintext export. |
| `bin/verify-no-leaks.py` | Pre-commit hook used by both this repo and the private data repo. |
| `fixtures/` | Reference fixtures used by `?selftest=1`. |
| `.githooks/` | Tracked pre-commit / pre-push hooks. |

## Privacy model

The app is intended for use with sensitive home-lab data. The privacy story is built on three layers:

1. **No backend.** The hosted page is plain static HTML/CSS/JS. View source to verify; nothing is hidden.
2. **CSP lockdown.** A `Content-Security-Policy` meta tag pins `connect-src` to `'self'`, so the page is provably unable to make outbound network requests. Open the browser DevTools network tab during use — you should see zero requests after the page loads.
3. **In-browser AES-GCM encryption.** Sensitive fields are encrypted per-value using a passphrase you supply. Encryption and decryption happen in the browser via Web Crypto. The passphrase is never persisted; lock the session and the in-memory key is dropped.

The encrypted file is safe to host anywhere — encryption is the access control. We recommend keeping it in a separate private repo (see "Suggested workflow" below) for defense-in-depth (hides metadata like file size and update cadence), but the cipher is what protects the data.

## Encryption tiers

Currently the app encrypts:

- **Tier 1:** `credentials.*.password` — credential passwords.

Tier 2 (planned, see `restructuring/03-tier2-encryption.md`): IPs, hostnames, names, URLs, MACs, and other identifying values. Topology (IDs, refs, enums, schema shape) stays plaintext at every tier.

## Suggested workflow

Two repos:

- **This one (`network-docs`)** — public; the app and dev tooling.
- **`homelab-data`** — private; contains only `network-import-encrypted.json` (your inventory). Initialized as a sibling directory; see its README for setup.

Editing flow on Chrome / Edge:

1. Visit the live URL or open `network-inventory.html` from `file://`.
2. Click **Open…**, pick `homelab-data/network-import-encrypted.json`.
3. Unlock with your passphrase.
4. Edit.
5. Click **Save**. The File System Access API writes back to the same file in place.
6. From the terminal: `cd ~/Code_Projects/homelab-data && git commit -am "update" && git push`.

On Firefox / Safari (no File System Access API), Open/Save fall back to import + download.

## Bootstrapping the encrypted file

If you have a plaintext inventory JSON and want to produce the initial encrypted file:

```bash
python encrypt_hosts.py network-import.json network-import-encrypted.json --tier1
```

Then move that file to your `homelab-data` clone. After Tier-2 lands, `--tier2` extends the encryption to additional fields.

## Running the self-test

Append `?selftest=1` to the page URL. The four invariants (fidelity, idempotency, encrypted-fixture, edit-roundtrip) run after first paint and report to the console.

## Hooks setup (per clone)

```bash
git config core.hooksPath .githooks
```

Without that step, the pre-commit hook doesn't fire and the leak guards are inert. Documented here because tracked hooks need an opt-in.

## Constraints

- One HTML file. No external libraries, no CDN, no build step, no backend.
- Must work from `file://`. Do not introduce APIs that require an HTTP origin.
- Vanilla JS only.
