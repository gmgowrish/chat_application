<div align="center">

# 💬 Secure Real-Time Chat App

**A live group chat built with Flask and Socket.IO, with end-to-end encryption. The server only relays ciphertext and never sees what you write.**

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.1-000000?style=flat-square&logo=flask&logoColor=white)
![Socket.IO](https://img.shields.io/badge/Socket.IO-4.8-010101?style=flat-square&logo=socketdotio&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black)
![E2EE](https://img.shields.io/badge/E2EE-ECDH%20P--256%20%2B%20AES--256--GCM-2ea44f?style=flat-square)

</div>

---

## ✨ Features

- 🔒 **End-to-end encryption**: messages, photos and files are encrypted in the browser with the Web Crypto API; the server cannot read them
- 🙂 **Emoji verification** (like Telegram calls): tap someone and compare 8 emoji, or the 60-digit safety number. Verified people get a green shield, and you're warned if their key ever changes
- 👤 **Stable identity**: your name, gender and encryption key are remembered on your device. Refreshing or switching the screen off doesn't create a "new" person, and nobody sees left/joined spam
- 📬 **Never miss a message**: messages sent while your screen is off wait on the server (still encrypted) for up to an hour
- 📷 **Encrypted photos and files**: take a photo with the camera, upload photos, videos or any file (up to 15 MB), drag and drop or paste; recipients save them to their device. Files are deleted from the server after 1 hour
- 🟢 **Presence**: who's online, "recently active" with last seen, typing indicators, ✓ sent / ✓✓ delivered
- ♂ ♀ ⚧ **Gender-themed avatars**, light and dark mode, mobile drawer layout
- 🧱 **Hardened server**: strict Content-Security-Policy, rate limiting, input validation, same-origin WebSockets

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
```

| Building block | Purpose |
|---|---|
| **ECDH P-256** (one key pair per tab, private key non-extractable) | Agree on a shared secret with each member |
| **HKDF-SHA-256** bound to both public keys | Turn the shared secret into a per-pair AES key |
| **AES-256-GCM**, random 96-bit IV per message | Confidentiality and integrity |
| **AAD = protocol + sender key + recipient key** | Server cannot reflect or re-route a message |
| **Per-sender sequence number** inside the ciphertext | Server cannot replay old messages |
| **Safety number** (SHA-512 of both public keys) | Detects a server that swaps in its own keys |

A group message is encrypted separately for each recipient, and the server delivers each copy only to its addressee. Files are encrypted once with a random key; the ciphertext goes to `POST /files` (one-time token, 1 hour lifetime) and the key travels inside the encrypted message.

### What it does *not* protect (yet)

Be honest with your users about these. Each one is addressed in [ROADMAP.md](ROADMAP.md).

- **Unverified keys.** If people don't compare safety numbers, a malicious server could still intercept messages.
- **Metadata.** The server sees who is online, usernames, who messages whom, when, and message sizes.
- **The JavaScript itself.** A web app's code is delivered by the server, so a compromised server could ship a backdoored `chat.js`.
- **Forward secrecy.** Each browser keeps one long-lived key (non-extractable, in IndexedDB). There is no ratchet yet.

---

## 🔌 Socket events

| Direction | Event | Payload |
|---|---|---|
| Client → server | `connect` (auth) | `{ public_key, token, username, gender, returning }`: refused without a valid P-256 key and identity token |
| Server → client | `welcome` | `{ me, members: [{ id, username, gender, public_key, online, last_seen }] }` |
| Server → others | `user_joined` | a new person (shown once) |
| Server → others | `presence` | online/offline/key changes (silent, no chat message) |
| Client → server | `send_message` (ack) | `{ envelopes: { <id>: { iv, ct } } }` → `{ ok, delivered, queued }` |
| Server → recipient | `new_message` | `{ from, iv, ct }` |
| Client → server | `file_upload_token` (ack) | → `{ token }` for one `POST /files` of ciphertext |
| Client → server | `update_profile` (ack) | `{ username?, gender? }` |
| Both | `typing` | `{ id }` |

---|---|---|
| Client → server | `connect` (auth) | `{ public_key }` (connection is refused without a valid P-256 key) |
| Server → client | `welcome` | `{ id, username, members: [{ id, username, public_key }] }` |
| Server → others | `user_joined` / `user_left` | `{ id, username, public_key }` / `{ id }` |
| Client → server | `send_message` | `{ envelopes: { <recipient id>: { iv, ct } } }` |
| Server → recipient | `new_message` | `{ from, iv, ct }` |
| Client → server | `update_username` | `{ username }` |
| Server → all | `username_updated` | `{ id, username }` |
| Server → client | `error_message` | `{ error }` |

---

## 🚀 Run locally

```bash
git clone https://github.com/gmgowrish/chat_application.git
cd chat_application

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

python app.py
```

Open **http://127.0.0.1:5000/** in two browser tabs and start chatting.

> Web Crypto only works in a **secure context**: `localhost` or **HTTPS**. Over plain `http://<lan-ip>` the chat stays disabled on purpose.

### Tests

```bash
pip install -r requirements-dev.txt
pytest                                   # server tests
python tests/e2e/browser_check.py        # real-browser check (needs the app running + playwright)
```

### Deploy on Render

| Setting | Value |
|---|---|
| Build command | `pip install -r requirements.txt` |
| Start command | `gunicorn wsgi:app` (settings come from `gunicorn.conf.py`: 1 worker, 100 threads, binds `$PORT`) |
| Python | 3.13 (from `.python-version`) |

> **Deploy fails with `Entry point ('gunicorn.workers', 'eventlet') not found`?** The service still has the old start command. Change it to `gunicorn wsgi:app` (Settings → Build & Deploy → Start Command). eventlet is no longer used.

Render terminates HTTPS for you; the app detects Render automatically (`RENDER=true`), trusts its proxy headers and marks cookies `Secure`. A `render.yaml` blueprint is included for new services.

Keep **one instance**: online users are held in memory.

| Variable | Meaning |
|---|---|
| `SECRET_KEY` | Flask secret key. **Set it** so sessions survive restarts |
| `DATABASE_URL` | Optional PostgreSQL URL for analytics. Without it, SQLite is used, and Render wipes it on every restart or deploy |
| `ANALYTICS_RETENTION_DAYS` | How long connection metadata is kept (default 30) |
| `ALLOWED_ORIGINS` | Comma-separated origins allowed to open WebSockets (default: same origin only) |
| `BEHIND_PROXY=1` | Trust one proxy's `X-Forwarded-*` headers when self-hosting behind nginx/Caddy |
| `FLASK_DEBUG=1` | Debug mode for `python app.py` (never in production) |

Operator analytics (connection metadata only, never message content) are optional and stay disabled unless configured through private environment variables (`ADMIN_PATH` plus `ADMIN_PASSWORD` or `ADMIN_PASSWORD_HASH`).

---

## 📁 Project Structure

```
chat_application/
├── app.py                 # Flask app, security headers, Socket.IO relay + validation
├── analytics.py           # connection-metadata storage (SQLite or PostgreSQL)
├── admin.py               # optional operator dashboard (disabled unless configured)
├── wsgi.py                # entry point for Gunicorn
├── gunicorn.conf.py       # 1 worker, 100 threads, binds $PORT
├── render.yaml            # Render blueprint
├── templates/
│   ├── index.html         # chat page (no inline scripts or styles, so CSP stays strict)
│   ├── 404.html
│   └── admin.html
├── static/
│   ├── css/chat.css
│   └── js/chat.js         # UI + all end-to-end encryption (Web Crypto API)
├── tests/                 # server tests (routing, validation, rate limits, headers, admin)
├── requirements.txt
├── requirements-dev.txt
└── ROADMAP.md             # long-term upgrade plan
```

## 🛠️ Tech Stack

**Python** · **Flask** · **Flask-SocketIO** · **Socket.IO (JS client)** · **Web Crypto API** · **SQLAlchemy** · **Gunicorn**

> Online users are kept in memory and messages are never stored. The server keeps connection metadata (IP, browser, times, message counts) for 30 days for security and abuse prevention; the chat page says so.

---

<div align="center">

Made by **[G M Gowrish](https://github.com/gmgowrish)** · ⭐ Star the repo if you find it useful!

</div>
