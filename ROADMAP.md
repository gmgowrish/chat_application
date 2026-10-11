# 🗺️ Roadmap: from demo chat to a secure messenger (2026 → 2036)

## Telegram vs Signal: pick the right target

Telegram is famous, but its **default chats are not end-to-end encrypted**. Telegram's servers can read normal chats and every group. Only the opt-in 1:1 "Secret Chats" are E2EE. If you want "secure on both ends", the model to copy is **Signal**: everything is E2EE by default, groups included, with as little metadata as possible.

This app is already E2EE by default for everyone (Phase 0 below). The phases after that close the remaining gaps, in order of value.

---

## Phase 0: done (this upgrade)

- [x] E2EE in the browser: ECDH P-256, then HKDF, then AES-256-GCM, with a per-recipient fan-out
- [x] AAD binding (no reflection or re-routing) and sequence numbers (no replay)
- [x] Safety numbers for manual verification against a MITM server
- [x] Server only routes ciphertext; random public IDs instead of socket IDs
- [x] Strict CSP (no inline JS, no `eval`), clickjacking and sniffing headers, same-origin WebSockets
- [x] Input validation, unique usernames, token-bucket rate limiting, message size caps
- [x] Removed third-party avatar service (it leaked usernames to DiceBear)
- [x] Dropped deprecated `eventlet`; upgraded Flask 3.1, Flask-SocketIO 5.7, Socket.IO client 4.8.4
- [x] Server tests (`pytest`)

---

## Phase 1: production basics (next 1–3 months)

| Task | How |
|---|---|
| HTTPS everywhere | Caddy (automatic Let's Encrypt) in front of gunicorn; set `BEHIND_PROXY=1` |
| Containerise | `Dockerfile` (non-root user, slim image) + `docker-compose.yml` with Caddy |
| CI | GitHub Actions: `pytest`, `ruff`, `pip-audit`, plus a Playwright browser test of encryption |
| Dependency hygiene | Dependabot or Renovate; pin hashes with `pip-compile --generate-hashes` |
| Self-host the Socket.IO client | Serve it from `/static` so no CDN is trusted; tighten CSP to `script-src 'self'` |
| Security policy | `SECURITY.md` + `/.well-known/security.txt` so researchers can report bugs |
| Threat model | Write down who you defend against (server operator, network, other users) and what is out of scope |

## Phase 2: accounts and persistent identity (3–9 months)

Today keys die with the tab, so users must re-verify after every reload. Fix that first:

1. **Accounts with passkeys (WebAuthn)**: no passwords to leak. Library: `webauthn` (py_webauthn).
2. **Persistent identity key per device**: generate a *non-extractable* key and store the `CryptoKey` object in **IndexedDB**. The browser keeps it, and JavaScript cannot export it.
3. **"Safety number changed" warnings**: remember each contact's key, and warn loudly if it changes (like Signal does).
4. **Mark contacts as verified**: show a ✅ badge once safety numbers have been compared, or offer a **QR code** to scan in person.
5. **1:1 chats and rooms**: Socket.IO rooms; invite-only rooms.
6. **Offline delivery and history**: store **only ciphertext** in PostgreSQL, keyed by recipient device, and delete it after delivery. The server must never need plaintext.
7. **Encrypted attachments**: encrypt files client-side with a random AES key, upload the blob, and send the key inside the E2EE message.
8. **Disappearing messages**: timer inside the encrypted payload, enforced by clients; server deletes ciphertext on schedule.

## Phase 3: Signal-grade cryptography (9–24 months)

| Gap today | Upgrade | Tooling |
|---|---|---|
| A stolen key decrypts the whole session | **Double Ratchet**: new key for every message (forward secrecy + post-compromise security) | `libsignal` (official Signal library, Rust with TypeScript bindings) |
| Both users must be online to set up keys | **X3DH / PQXDH** prekeys uploaded to the server | `libsignal` |
| Group cost grows O(n) per message | **MLS (RFC 9420)** for groups: efficient, with forward secrecy and post-compromise security | OpenMLS (Rust → WASM), `ts-mls` |
| Server sees who sends to whom | **Sealed sender**: the sender identity goes inside the ciphertext | Design per Signal's sealed sender |
| One device per user | **Multi-device**: each device has its own keys; send to all of a user's devices | Comes with libsignal/MLS |

> **Rule:** never invent your own ratchet or protocol. Use audited libraries and only write glue code.

## Phase 4: scale and native apps (2–4 years)

- **Horizontal scaling**: Redis message queue (`SocketIO(message_queue="redis://…")`) plus sticky sessions; or move the realtime layer to an async stack (FastAPI/Quart, or Go/Elixir for very large loads).
- **Native mobile and desktop apps** (Flutter, React Native, or Tauri). Native apps also solve the biggest web-E2EE weakness: the server can't silently swap the code on you.
- **Push notifications without content**: the push only says "you have a message"; the app fetches and decrypts it.
- **E2EE voice and video**: WebRTC with SFrame / Insertable Streams so even the SFU can't see the media.
- **Private contact discovery**: never upload raw phone numbers or emails (use hashing with rate limits, or secure enclaves as Signal does).

## Phase 5: future-proofing (4–10 years)

| Threat | Response |
|---|---|
| **Quantum computers** ("harvest now, decrypt later") | Hybrid post-quantum key exchange now: **X25519 + ML-KEM (FIPS 203)**, as in Signal's PQXDH and its post-quantum ratchet work, and MLS PQ ciphersuites as they standardise |
| Users never verify safety numbers | **Key transparency**: an append-only, publicly auditable key directory (like WhatsApp's AKD or Apple's Contact Key Verification) so clients check keys automatically |
| Backdoored builds | **Reproducible builds**, signed releases, and a browser extension or [WEBCAT](https://github.com/freedomofpress/webcat)-style integrity check for the web app |
| Undiscovered bugs | Independent **security audits**, a bug bounty, and formal verification of the protocol (ProVerif or Tamarin models) |
| Metadata surveillance | Padding of message sizes, cover traffic, and onion routing or mixnets for transport |
| Regulation and interoperability | Track the EU DMA messaging-interop rules; MLS is the likely common ground |
| Algorithm ageing | **Crypto agility**: the protocol string (`e2ee-chat-v1`) is already versioned; keep a negotiated version on every message so you can migrate without breaking old chats |

---

## Yearly maintenance checklist (every year, all 10 years)

- [ ] Upgrade Python, Flask, Socket.IO and the JS client; re-run tests and `pip-audit`
- [ ] Re-check browser support for Web Crypto (e.g. adopt **X25519**, now in all major browsers, in place of P-256)
- [ ] Review the threat model and roadmap against what Signal and the IETF (MLS, PQ) have shipped
- [ ] Rotate secrets and TLS config; re-score with [Mozilla Observatory](https://observatory.mozilla.org) and SSL Labs
- [ ] Re-read the "What it does *not* protect" section of the README and remove items only when they are truly fixed
