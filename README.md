<div align="center">

# 💬 Secure Real-Time Chat App

**A live group chat built with Flask and Socket.IO, with end-to-end encryption. The server only relays ciphertext and never sees what you write.**

![Python](https://img.shields.io/badge/Python-3.13-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.1-000000?style=flat-square&logo=flask&logoColor=white)
![Socket.IO](https://img.shields.io/badge/Socket.IO-4.8-010101?style=flat-square&logo=socketdotio&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-optional-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![E2EE](https://img.shields.io/badge/E2EE-ECDH%20P--256%20%2B%20AES--256--GCM-2ea44f?style=flat-square)

</div>

---

## ✨ Features

- 🔒 **End-to-end encryption**: messages, photos and files are encrypted in the browser with the Web Crypto API; the server cannot read them
- 🙂 **Emoji verification** (like Telegram calls): tap someone and compare 8 emoji, or the 60-digit safety number. Verified people get a green shield, and you're warned if their key ever changes
- 🛡️ **Verified only** (optional switch): your messages are encrypted only for people you've verified; everyone else gets a blurred placeholder and never receives the content or key
- 💬 **Newcomers see recent messages**: an online member's browser shares the last 100 messages with them, encrypted just for them; your own history stays on your device across refreshes
- 👤 **Stable identity**: on the first visit you choose a name and gender, remembered with your encryption key on your device. Refreshing or switching the screen off doesn't create a "new" person, and nobody sees left/joined spam
- 📬 **Never miss a message**: every message waits on the server (still encrypted) until the recipient's device confirms it, for up to an hour; ✓ sent / ✓✓ delivered
- 📷 **Encrypted photos and files**: take a photo with the camera, upload photos, videos or any file (up to 15 MB), drag and drop or paste; recipients save them to their device. Files are deleted from the server after 1 hour
- 🟢 **Presence**: who's online, "recently active" (2 hours) with last seen, typing indicators
- ♂ ♀ ⚧ **Gender-themed avatars**, light and dark mode, mobile drawer layout
- 🧱 **Hardened server**: strict Content-Security-Policy (`script-src 'self'`, no third-party scripts), rate limiting, input validation, same-origin WebSockets
- 🗄️ **Private analytics, encrypted at rest**: connection metadata only (never message content), in SQLite or PostgreSQL (e.g. a free [Neon](https://neon.tech) database). IP addresses are stored as keyed fingerprints plus encrypted copies; browser strings, referrers and names are encrypted, so a copy of the database alone reveals none of them
- ⚡ **Fast**: content-hashed static files cached for a year, ~1–3 ms server responses, ~30 ms message delivery locally; analytics are written in the background so a slow database never delays the chat

---

## 🔐 How the encryption works

```
 Alice's browser                       Server                       Bob's browser
 ───────────────                       ──────                       ─────────────
 ECDH key pair (private key            stores public keys           ECDH key pair
 never leaves the browser)  ──pubA──▶  routes ciphertext   ◀──pubB──
                                       (cannot decrypt)
 K_AB = HKDF(ECDH(privA, pubB))                                     K_AB = HKDF(ECDH(privB, pubA))
 AES-256-GCM(K_AB, msg) ─────────────▶ only to Bob ────────────────▶ decrypt + verify
                        ◀──────────── delivery receipt ◀─────────── ack
```

| Building block | Purpose |
|---|---|
| **ECDH P-256**, one key pair per browser (non-extractable, kept in IndexedDB) | Agree on a shared secret with each member; survives refreshes |
| **HKDF-SHA-256** bound to both public keys | Turn the shared secret into a per-pair AES key |
| **AES-256-GCM**, random 96-bit IV per message | Confidentiality and integrity |
| **AAD = protocol + sender key + recipient key** | Server cannot reflect or re-route a message |
| **Random message id + timestamp window** inside the ciphertext | Replayed or very old messages are dropped |
| **Emoji / safety number** (SHA-512 of both public keys) | Detects a server that swaps in its own keys |
| **Key pinning per name** | Warns when someone's key changes |

A group message is encrypted separately for each recipient, and the server delivers each copy only to its addressee. Files are encrypted once with a random key; the ciphertext goes to `POST /files` (one-time token, 1 hour lifetime) and the key travels inside the encrypted message.

### What it does *not* protect (yet)

Each item is addressed in [ROADMAP.md](ROADMAP.md).

- **Unverified keys.** If people don't compare emoji, a malicious server could still intercept messages. "Verified only" mode closes this for your own messages.
- **Metadata.** The server sees who is online, names, who messages whom, when, and message sizes.
- **The JavaScript itself.** A web app's code is delivered by the server, so a compromised server could ship a backdoored `chat.js`.
- **Forward secrecy.** Each browser keeps one long-lived key. There is no ratchet yet.
- **Shared history** is vouched for by the member who shared it, which is why it's labelled "shared by …".

---

## 🗄️ Analytics and privacy at rest

The server keeps **connection metadata only** (page visits, chat sessions, security events, approximate city), for 30 days, and the chat page tells users so. Message content never reaches the server in readable form.

| Stored field | How |
|---|---|
| IP address | **Keyed fingerprint** (HMAC-SHA-256), for unique counts, admin lockouts and the city cache, plus an **AES-256-GCM** encrypted copy |
| Browser string, forwarding chain, referrer, chat name | **AES-256-GCM** encrypted |
| Time, browser name, OS, device type, language, city, counts | Readable (not identifying on their own; needed for statistics) |

Both keys are derived (HKDF) from `SECRET_KEY`, which lives only in the app's environment, never in the database. A plain hash isn't used for IPs because the IPv4 space is small enough to brute-force. Rows written by older versions are encrypted automatically on start, and the startup log reports it:

```
[analytics] storage: PostgreSQL @ <host>
[analytics] privacy: IPs fingerprinted + encrypted, details encrypted (AES-256-GCM), key from SECRET_KEY
```

> Keep `SECRET_KEY` stable once data is stored: rows saved with an older key can't be decrypted (statistics still work).

---

## 🔌 Socket events

| Direction | Event | Payload |
|---|---|---|
| Client → server | `connect` (auth) | `{ public_key, token, username, gender, returning }`: refused without a valid P-256 key and identity token |
| Server → client | `welcome` | `{ me, members: [{ id, username, gender, public_key, online, last_seen }], max_file_bytes, file_ttl }` |
| Server → others | `user_joined` | a new person (announced once) |
| Server → others | `presence` | online / offline / key changes (silent, no chat message) |
| Client → server | `send_message` (ack) | `{ msg_id, envelopes: { <id>: { iv, ct } } }` → `{ ok, recipients }` |
| Server → recipient | `new_message` | `{ mid, from, iv, ct }` (kept in the mailbox until acknowledged) |
| Client → server | `ack` | `{ mids: [...] }`: the device has the messages |
| Server → sender | `delivered` | `{ mid, by }`: delivery receipt (✓✓) |
| Client → server | `file_upload_token` (ack) | → `{ token }` for one `POST /files` of ciphertext |
| Client → server | `update_profile` (ack) | `{ username?, gender? }` |
| Both | `typing` | `{ id }` |
| Both | `history_received` | `{ id }`: a newcomer got shared history, backups stand down |
| Server → all / one | `user_removed` / `removed` | someone was removed from the list / you were |

---

## 🚀 Run locally

```bash
git clone https://github.com/gmgowrish/chat_application.git
cd chat_application

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

python app.py                   # or: gunicorn wsgi:app
```

Open **http://127.0.0.1:5000/** in two browser windows (or one normal and one private window) and start chatting.

> Web Crypto only works in a **secure context**: `localhost` or **HTTPS**. Over plain `http://<lan-ip>` the chat stays disabled on purpose.

### Tests

```bash
pip install -r requirements-dev.txt
pytest                                                    # 46 server tests (SQLite)
TEST_DATABASE_URL=postgres://user:pw@localhost/db pytest  # same tests against PostgreSQL
python tests/e2e/browser_check.py                         # 20 real-browser checks (app running + playwright)
```

The browser check covers onboarding, refresh/offline behaviour, emoji verification, "Verified only", encrypted photos, files and camera, shared history, and that no plaintext ever appears in WebSocket traffic.

### Deploy on Render

| Setting | Value |
|---|---|
| Build command | `pip install -r requirements.txt` |
| Start command | `gunicorn wsgi:app` (settings come from `gunicorn.conf.py`: 1 worker, 100 threads, binds `$PORT`) |
| Python | 3.13 (from `.python-version`) |

> **Deploy fails with `Entry point ('gunicorn.workers', 'eventlet') not found`?** The service still has an old start command. Change it to `gunicorn wsgi:app` (Settings → Build & Deploy → Start Command).

Render terminates HTTPS for you; the app detects Render automatically (`RENDER=true`), trusts its proxy headers, marks cookies `Secure`, and works with Render's `gunicorn --preload`. A `render.yaml` blueprint is included for new services. Keep **one instance**: online users are held in memory.

| Variable | Meaning |
|---|---|
| `SECRET_KEY` | **Required in production.** Signs sessions and derives the analytics encryption keys; keep it stable |
| `DATABASE_URL` | PostgreSQL URL for analytics (e.g. free Neon, same region as the app). Without it, SQLite is used, which Render wipes on every restart or deploy |
| `ANALYTICS_RETENTION_DAYS` | How long connection metadata is kept (default 30) |
| `IPINFO_TOKEN` | Optional: higher limits for approximate city lookups |
| `ALLOWED_ORIGINS` | Comma-separated origins allowed to open WebSockets (default: same origin only) |
| `BEHIND_PROXY=1` | Trust one proxy's `X-Forwarded-*` headers when self-hosting behind nginx/Caddy |
| `FLASK_DEBUG=1` | Debug mode for `python app.py` (never in production) |

An optional operator dashboard exists and stays completely disabled unless configured through private environment variables.

---

## 📁 Project Structure

```
chat_application/
├── app.py                 # Flask app, security headers, identities, Socket.IO relay, encrypted file store
├── analytics.py           # metadata storage (SQLite/PostgreSQL), encryption at rest, city lookups
├── admin.py               # optional operator dashboard (disabled unless configured)
├── wsgi.py                # entry point for Gunicorn
├── gunicorn.conf.py       # 1 worker, 100 threads, binds $PORT
├── pyproject.toml         # pytest settings
├── render.yaml            # Render blueprint
├── templates/
│   ├── index.html         # chat page (no inline scripts or styles, so CSP stays strict)
│   ├── 404.html
│   └── admin.html
├── static/
│   ├── css/chat.css, css/base.css
│   ├── img/icon.svg
│   └── js/chat.js         # UI + all end-to-end encryption (Web Crypto API)
│       js/socket.io.min.js  (self-hosted Socket.IO client)
├── tests/                 # server tests + tests/e2e/browser_check.py
├── requirements.txt
├── requirements-dev.txt
└── ROADMAP.md             # long-term upgrade plan
```

## 🛠️ Tech Stack

**Python** · **Flask** · **Flask-SocketIO** · **Socket.IO (self-hosted client)** · **Web Crypto API** · **IndexedDB** · **SQLAlchemy** · **PostgreSQL / SQLite** · **cryptography (AES-GCM, HKDF)** · **Gunicorn**

> The server never stores readable messages: only ciphertext waiting for delivery (up to 1 hour) and encrypted files (1 hour). Connection metadata is kept for 30 days for security and abuse prevention, with identifying fields encrypted at rest.

---

<div align="center">

Made by **[G M Gowrish](https://github.com/gmgowrish)** · ⭐ Star the repo if you find it useful!

</div>
