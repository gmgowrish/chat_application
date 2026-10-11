"""Real-time chat with end-to-end encryption.

The server never sees message text. Each browser generates an ECDH key pair,
publishes only the public key, and encrypts every message separately for each
recipient (AES-256-GCM). The server just validates the shape of the encrypted
envelopes and routes each one to its recipient.
"""
import base64
import binascii
import logging
import os
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone

from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from werkzeug.middleware.proxy_fix import ProxyFix

import analytics
from admin import init_admin

log = logging.getLogger(__name__)
ON_RENDER = bool(os.environ.get("RENDER"))  # Render sets RENDER=true on every service

USERNAME_RE = re.compile(r"^[A-Za-z0-9_\- ]{2,24}$")
MAX_RECIPIENTS = 50
MAX_CIPHERTEXT_B64 = 16_384   # per recipient; client caps plaintext at 2000 chars
RATE_BURST = 10               # token bucket: up to 10 events at once...
RATE_PER_SECOND = 1.0         # ...refilled at 1 event per second

app = Flask(__name__)
# Set SECRET_KEY in production, otherwise the admin login is lost on every restart.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_NAME="s",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=ON_RENDER or os.environ.get("COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
)
BEHIND_PROXY = ON_RENDER or os.environ.get("BEHIND_PROXY") == "1"
# Render sits behind Cloudflare, which sets True-Client-IP to the real visitor IP.
# (Render appends to X-Forwarded-For without stripping spoofed values, so that is not trusted.)
CLIENT_IP_HEADER = os.environ.get("CLIENT_IP_HEADER", "True-Client-IP" if ON_RENDER else "")

# None = same-origin only. Set ALLOWED_ORIGINS="https://chat.example.com" if needed.
allowed_origins = os.environ.get("ALLOWED_ORIGINS")
socketio = SocketIO(
    app,
    cors_allowed_origins=allowed_origins.split(",") if allowed_origins else None,
    max_http_buffer_size=1_000_000,
)
if BEHIND_PROXY:
    # Wrap after SocketIO so WebSocket requests also see the proxy-corrected scheme and IP.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# sid -> {"id", "username", "public_key", "tokens", "last_refill", + analytics metadata}
# "id" is a random public identifier; the socket sid is never shared with other clients,
# and the analytics metadata (IP, browser, counters) is only shown on the admin page.
users = {}
sid_by_id = {}
users_lock = threading.Lock()


@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdnjs.cloudflare.com; "
        "style-src 'self'; img-src 'self' data:; connect-src 'self'; "
        "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


def client_ip():
    if CLIENT_IP_HEADER and request.headers.get(CLIENT_IP_HEADER):
        return request.headers[CLIENT_IP_HEADER].strip()
    return request.remote_addr or ""


def safely(fn, *args):
    """Analytics must never break the chat."""
    try:
        return fn(*args)
    except Exception:
        log.exception("analytics write failed")
        return None


def online_users():
    with users_lock:
        return sorted(
            ({key: u[key] for key in ("username", "ip", "browser", "os", "device", "user_agent",
                                      "connected_at", "messages", "recipients")} for u in users.values()),
            key=lambda u: u["connected_at"],
        )


init_admin(app, client_ip, online_users)


@app.route("/")
def index():
    safely(analytics.purge_old_rows)
    safely(
        analytics.record_visit, client_ip(), request.headers.get("X-Forwarded-For"),
        request.headers.get("User-Agent"), request.referrer, request.headers.get("Accept-Language"), "/",
    )
    return render_template("index.html")


def decode_b64(value, max_len):
    if not isinstance(value, str) or len(value) > max_len:
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None


def is_valid_public_key(value):
    # Uncompressed P-256 point: 0x04 || X (32 bytes) || Y (32 bytes)
    raw = decode_b64(value, 100)
    return raw is not None and len(raw) == 65 and raw[0] == 0x04


def take_token(user):
    """Token-bucket rate limit. Returns False when the client is sending too fast."""
    now = time.monotonic()
    user["tokens"] = min(RATE_BURST, user["tokens"] + (now - user["last_refill"]) * RATE_PER_SECOND)
    user["last_refill"] = now
    if user["tokens"] < 1:
        return False
    user["tokens"] -= 1
    return True


def public_view(user):
    return {"id": user["id"], "username": user["username"], "public_key": user["public_key"]}


def reject(reason):
    emit("error_message", {"error": reason})


@socketio.on("connect")
def handle_connect(auth):
    public_key = auth.get("public_key") if isinstance(auth, dict) else None
    if not is_valid_public_key(public_key):
        return False  # refuse the connection: E2EE is mandatory

    with users_lock:
        taken = {u["username"] for u in users.values()}
        username = f"User_{secrets.randbelow(9000) + 1000}"
        while username in taken:
            username = f"User_{secrets.randbelow(9000) + 1000}"
        user_agent = request.headers.get("User-Agent", "")
        browser, system, device = analytics.parse_user_agent(user_agent)
        user = {
            "id": secrets.token_urlsafe(12),
            "username": username,
            "public_key": public_key,
            "tokens": float(RATE_BURST),
            "last_refill": time.monotonic(),
            # metadata for the admin page only
            "ip": client_ip(),
            "user_agent": user_agent,
            "browser": browser,
            "os": system,
            "device": device,
            "connected_at": datetime.now(timezone.utc),
            "messages": 0,
            "recipients": 0,
            "renames": 0,
            "row_id": None,
        }
        members = [public_view(u) for u in users.values()]
        users[request.sid] = user
        sid_by_id[user["id"]] = request.sid

    user["row_id"] = safely(analytics.start_chat_session, user["id"], username, user["ip"], user_agent)
    emit("welcome", {"id": user["id"], "username": username, "members": members})
    emit("user_joined", public_view(user), broadcast=True, include_self=False)


@socketio.on("disconnect")
def handle_disconnect(*_):
    with users_lock:
        user = users.pop(request.sid, None)
        if user:
            sid_by_id.pop(user["id"], None)
    if user:
        emit("user_left", {"id": user["id"]}, broadcast=True)
        if user["row_id"] is not None:
            safely(analytics.end_chat_session, user["row_id"], user["username"],
                   user["messages"], user["recipients"], user["renames"])


@socketio.on("send_message")
def handle_message(data):
    with users_lock:
        user = users.get(request.sid)
        if not user:
            return
        if not take_token(user):
            return reject("You are sending messages too fast.")

        envelopes = data.get("envelopes") if isinstance(data, dict) else None
        if not isinstance(envelopes, dict) or not 0 < len(envelopes) <= MAX_RECIPIENTS:
            return reject("Malformed message.")

        deliveries = []
        for recipient_id, envelope in envelopes.items():
            recipient_sid = sid_by_id.get(recipient_id)
            if recipient_sid is None or recipient_sid == request.sid:
                continue  # recipient left in the meantime; skip silently
            if not isinstance(envelope, dict):
                return reject("Malformed message.")
            iv = decode_b64(envelope.get("iv"), 24)
            ciphertext = decode_b64(envelope.get("ct"), MAX_CIPHERTEXT_B64)
            # AES-GCM: 12-byte IV, ciphertext is at least the 16-byte auth tag
            if iv is None or len(iv) != 12 or ciphertext is None or len(ciphertext) < 17:
                return reject("Malformed message.")
            deliveries.append((recipient_sid, envelope["iv"], envelope["ct"]))
        sender_id = user["id"]
        if deliveries:
            user["messages"] += 1
            user["recipients"] += len(deliveries)

    for recipient_sid, iv, ciphertext in deliveries:
        emit("new_message", {"from": sender_id, "iv": iv, "ct": ciphertext}, to=recipient_sid)


@socketio.on("update_username")
def handle_update_username(data):
    new_username = data.get("username") if isinstance(data, dict) else None
    with users_lock:
        user = users.get(request.sid)
        if not user:
            return
        if not take_token(user):
            return reject("Slow down a little.")
        if not isinstance(new_username, str) or not USERNAME_RE.fullmatch(new_username.strip()):
            return reject("Usernames are 2-24 letters, digits, spaces, _ or -.")
        new_username = new_username.strip()
        if any(u["username"].lower() == new_username.lower() for u in users.values()):
            return reject("That username is already taken.")
        user["username"] = new_username
        user["renames"] += 1
        user_id = user["id"]

    emit("username_updated", {"id": user_id, "username": new_username}, broadcast=True)


if __name__ == "__main__":
    # Development server; use gunicorn in production (see README). Honors $PORT so that a
    # `python app.py` start command also works on Render.
    socketio.run(
        app,
        host="0.0.0.0" if os.environ.get("PORT") else "127.0.0.1",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_DEBUG") == "1",
        allow_unsafe_werkzeug=True,
    )
