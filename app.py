"""Real-time chat with end-to-end encryption.

The server never sees message text or file contents. Each browser keeps an ECDH
key pair, publishes only the public key, and encrypts every message separately
for each recipient (AES-256-GCM). Files are encrypted in the browser with a
fresh key; the server only stores the ciphertext briefly so recipients can
download it. The key travels inside the end-to-end encrypted message.
"""
import base64
import binascii
import functools
import hashlib
import logging
import os
import re
import secrets
import shutil
import threading
import time
from datetime import datetime, timedelta, timezone

from flask import Flask, abort, jsonify, render_template, request, send_file, url_for
from flask_socketio import ConnectionRefusedError, SocketIO, emit
from werkzeug.middleware.proxy_fix import ProxyFix

import analytics
from admin import init_admin

log = logging.getLogger(__name__)
ON_RENDER = bool(os.environ.get("RENDER"))  # Render sets RENDER=true on every service

USERNAME_RE = re.compile(r"^[A-Za-z0-9_\- ]{2,24}$")
FILE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{32}$")
MAX_RECIPIENTS = 50
MAX_CIPHERTEXT_B64 = 16_384   # per recipient; client caps plaintext at 2000 chars
RATE_BURST = 10               # token bucket: up to 10 events at once...
RATE_PER_SECOND = 1.0         # ...refilled at 1 event per second
MAX_FILE_BYTES = 15 * 1024 * 1024 + 16   # 15 MB file + AES-GCM tag
FILE_TTL_SECONDS = 3600                  # encrypted files are deleted after an hour
FILES_TOTAL_CAP = 300 * 1024 * 1024      # never hold more than 300 MB of ciphertext
UPLOAD_TOKEN_TTL = 120
TYPING_INTERVAL = 1.0

DATA_DIR = os.environ.get("DATA_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
FILES_DIR = os.path.join(DATA_DIR, "files")
# Files are only kept for an hour and the index lives in memory, so start clean.
shutil.rmtree(FILES_DIR, ignore_errors=True)
os.makedirs(FILES_DIR, mode=0o700, exist_ok=True)

app = Flask(__name__)
# Set SECRET_KEY in production, otherwise the admin login is lost on every restart.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "").strip().strip("'\"") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_NAME="s",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=ON_RENDER or os.environ.get("COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    MAX_CONTENT_LENGTH=MAX_FILE_BYTES,
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

# sid -> one connection: {"identity", rate-limit state, + analytics metadata}
# Identities (below) carry a random public id; socket sids are never shared with other
# clients, and the analytics metadata (IP, browser, counters) is only shown on the admin page.
users = {}
users_lock = threading.Lock()

# Encrypted file store: file_id -> {"path", "size", "expires"}; upload_tokens: token -> expiry
files = {}
upload_tokens = {}
files_lock = threading.Lock()


@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self'; "
        "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    # The camera is only usable by this site, and only after the user allows it.
    response.headers["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=()"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    if request.path.startswith("/static/") and request.args.get("v") and response.status_code == 200:
        # Versioned asset URLs change whenever the file changes, so browsers may keep them for a year.
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return response


@functools.lru_cache(maxsize=None)
def _asset_version(filename):
    with open(os.path.join(app.static_folder, filename), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()[:12]


@app.template_global()
def asset(filename):
    """URL for a static file with a content hash, e.g. /static/js/chat.js?v=3f2a9c1b0d4e."""
    return url_for("static", filename=filename, v=_asset_version(filename))


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
            ({"username": c["identity"]["username"], **{key: c[key] for key in (
                "ip", "browser", "os", "device", "user_agent", "connected_at", "messages", "recipients")}}
             for c in users.values()),
            key=lambda u: u["connected_at"],
        )


# Lambdas: the roster helpers are defined further down.
init_admin(app, client_ip, online_users, lambda: roster_for_admin(), lambda ident_id: remove_person(ident_id))


@app.route("/")
def index():
    safely(analytics.purge_old_rows)
    safely(
        analytics.record_visit, client_ip(), request.headers.get("X-Forwarded-For"),
        request.headers.get("User-Agent"), request.referrer, request.headers.get("Accept-Language"), "/",
    )
    return render_template("index.html")


# ------------------------------------------------------------------ encrypted files

def purge_files():
    now = time.monotonic()
    with files_lock:
        expired = [fid for fid, f in files.items() if f["expires"] <= now]
        removed = [files.pop(fid) for fid in expired]
        for token in [t for t, exp in upload_tokens.items() if exp <= now]:
            upload_tokens.pop(token, None)
    for entry in removed:
        try:
            os.remove(entry["path"])
        except FileNotFoundError:
            pass


@app.post("/files")
def upload_file():
    """Store an already-encrypted file. Requires a one-time token issued to a connected chat user."""
    token = request.headers.get("X-Upload-Token", "")
    with files_lock:
        expires = upload_tokens.pop(token, None)
    if expires is None or expires <= time.monotonic():
        abort(403)
    data = request.get_data(cache=False)
    if len(data) < 17:
        abort(400)
    purge_files()
    with files_lock:
        if sum(f["size"] for f in files.values()) + len(data) > FILES_TOTAL_CAP:
            abort(507)
        file_id = secrets.token_urlsafe(24)
        path = os.path.join(FILES_DIR, file_id)
        files[file_id] = {"path": path, "size": len(data), "expires": time.monotonic() + FILE_TTL_SECONDS}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return jsonify(id=file_id, expires_in=FILE_TTL_SECONDS)


@app.get("/files/<file_id>")
def download_file(file_id):
    if not FILE_ID_RE.fullmatch(file_id):
        abort(404)
    with files_lock:
        entry = files.get(file_id)
    if entry is None or entry["expires"] <= time.monotonic() or not os.path.exists(entry["path"]):
        abort(404)
    response = send_file(entry["path"], mimetype="application/octet-stream", max_age=0)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return response


# ------------------------------------------------------------------ identities
#
# A browser keeps a secret random token (localStorage). The server stores only its
# SHA-256 and maps it to a stable identity: public id, name, gender and public key.
# Refreshing or switching the screen off therefore keeps the same person, name and
# key. Nobody is announced as "left"; they just turn offline after a short grace
# period. Every message waits (still encrypted) in the recipient's mailbox until
# their device acknowledges it, so a phone whose screen switched off, which the
# server may still think is connected, never loses messages.

TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,64}$")
MSG_ID_RE = re.compile(r"^[A-Za-z0-9_-]{12,40}$")
GENDERS = {"male", "female", "transgender", "unspecified"}
PRESENCE_GRACE = float(os.environ.get("PRESENCE_GRACE_SECONDS", "20"))
ROSTER_TTL = 2 * 3600           # offline people stay listed (and keep their name) for 2 hours
MAILBOX_TTL = 3600              # undelivered ciphertext is kept for an hour...
MAILBOX_MAX = 200               # ...and at most this many messages per person

identities = {}        # public id -> identity dict
id_by_token = {}       # sha256(token) -> public id


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def public_view(ident):
    return {
        "id": ident["id"], "username": ident["username"], "gender": ident["gender"],
        "public_key": ident["public_key"], "online": ident["online"], "last_seen": ident["last_seen"],
    }


def name_taken(name, exclude_id=None):
    return any(i["username"].lower() == name.lower() for i in identities.values() if i["id"] != exclude_id)


def prune_roster():
    """Forget people who have been offline for a day, and expire old mailbox entries."""
    now = time.time()
    for ident in list(identities.values()):
        ident["mailbox"] = [m for m in ident["mailbox"] if m["expires"] > now]
        if not ident["sids"] and not ident["online"] and now - ident["last_seen"] / 1000 > ROSTER_TTL:
            identities.pop(ident["id"], None)
            id_by_token.pop(ident["token_hash"], None)


def roster_for_admin():
    with users_lock:
        prune_roster()
        people = [{
            "id": i["id"], "username": i["username"], "gender": i["gender"], "online": i["online"],
            "connections": len(i["sids"]), "pending": len(i["mailbox"]),
            "last_seen": datetime.fromtimestamp(i["last_seen"] / 1000, timezone.utc) if i["last_seen"] else None,
        } for i in identities.values()]
    return sorted(people, key=lambda p: (not p["online"], p["username"].lower()))


def remove_person(ident_id):
    """Admin action: take someone off everyone's list, disconnect them and free their name."""
    with users_lock:
        ident = identities.pop(ident_id, None)
        if ident is None:
            return False
        id_by_token.pop(ident["token_hash"], None)
        sids = list(ident["sids"])
    for sid in sids:
        socketio.emit("removed", {}, to=sid)
        socketio.server.disconnect(sid, namespace="/")
    socketio.emit("user_removed", {"id": ident_id})
    return True


def mark_offline_later(ident_id, generation):
    """Runs in the background: after the grace period, flip a still-disconnected person to offline."""
    socketio.sleep(PRESENCE_GRACE)
    with users_lock:
        ident = identities.get(ident_id)
        if not ident or ident["sids"] or ident["generation"] != generation or not ident["online"]:
            return
        ident["online"] = False
        ident["last_seen"] = int(time.time() * 1000)
        view = public_view(ident)
    socketio.emit("presence", view)


# ------------------------------------------------------------------ helpers

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


def take_token(conn):
    """Token-bucket rate limit. Returns False when the client is sending too fast."""
    now = time.monotonic()
    conn["tokens"] = min(RATE_BURST, conn["tokens"] + (now - conn["last_refill"]) * RATE_PER_SECOND)
    conn["last_refill"] = now
    if conn["tokens"] < 1:
        return False
    conn["tokens"] -= 1
    return True


def fail(reason):
    return {"ok": False, "error": reason}


# ------------------------------------------------------------------ Socket.IO

@socketio.on("connect")
def handle_connect(auth):
    auth = auth if isinstance(auth, dict) else {}
    public_key = auth.get("public_key")
    token = auth.get("token")
    if not is_valid_public_key(public_key) or not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
        raise ConnectionRefusedError("bad_auth")  # E2EE and an identity token are mandatory
    wanted = auth.get("username").strip() if isinstance(auth.get("username"), str) else ""
    gender = auth.get("gender") if auth.get("gender") in GENDERS else "unspecified"
    returning = auth.get("returning") is True

    with users_lock:
        prune_roster()
        ident_id = id_by_token.get(token_hash(token))
        ident = identities.get(ident_id) if ident_id else None
        is_new = ident is None
        if is_new:
            # First connection of this browser (or the server restarted): claim the name.
            if not USERNAME_RE.fullmatch(wanted):
                raise ConnectionRefusedError("bad_name")
            if name_taken(wanted):
                raise ConnectionRefusedError("name_taken")
            ident = {
                "id": secrets.token_urlsafe(12), "token_hash": token_hash(token), "username": wanted,
                "gender": gender, "public_key": public_key, "online": False, "last_seen": 0,
                "sids": set(), "mailbox": [], "generation": 0,
            }
            identities[ident["id"]] = ident
            id_by_token[ident["token_hash"]] = ident["id"]
        was_online = ident["online"]
        key_changed = ident["public_key"] != public_key
        ident["public_key"] = public_key
        ident["online"] = True
        ident["generation"] += 1
        ident["sids"].add(request.sid)
        pending = list(ident["mailbox"])  # stays until acknowledged

        user_agent = request.headers.get("User-Agent", "")
        browser, system, device = analytics.parse_user_agent(user_agent)
        conn = {
            "identity": ident,
            "tokens": float(RATE_BURST),
            "last_refill": time.monotonic(),
            "last_typing": 0.0,
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
        users[request.sid] = conn
        me = public_view(ident)
        roster = [public_view(i) for i in identities.values() if i["id"] != ident["id"]]

    conn["row_id"] = safely(analytics.start_chat_session, ident["id"], ident["username"], conn["ip"], user_agent)
    emit("welcome", {"me": me, "members": roster, "max_file_bytes": MAX_FILE_BYTES - 16,
                     "file_ttl": FILE_TTL_SECONDS})
    for entry in pending:
        emit("new_message", entry["payload"])
    if is_new and not returning:
        emit("user_joined", me, broadcast=True, include_self=False)
    elif not was_online or key_changed or is_new:
        emit("presence", me, broadcast=True, include_self=False)


@socketio.on("disconnect")
def handle_disconnect(*_):
    with users_lock:
        conn = users.pop(request.sid, None)
        if not conn:
            return
        ident = conn["identity"]
        ident["sids"].discard(request.sid)
        schedule = not ident["sids"]
        generation = ident["generation"]
    if schedule:
        # Don't announce anything yet: a refresh reconnects within the grace period.
        socketio.start_background_task(mark_offline_later, ident["id"], generation)
    if conn["row_id"] is not None:
        safely(analytics.end_chat_session, conn["row_id"], ident["username"],
               conn["messages"], conn["recipients"], conn["renames"])


@socketio.on("send_message")
def handle_message(data):
    with users_lock:
        conn = users.get(request.sid)
        if not conn:
            return fail("Not connected.")
        if not take_token(conn):
            return fail("You are sending messages too fast.")

        data = data if isinstance(data, dict) else {}
        msg_id, envelopes = data.get("msg_id"), data.get("envelopes")
        if not isinstance(msg_id, str) or not MSG_ID_RE.fullmatch(msg_id):
            return fail("Malformed message.")
        if not isinstance(envelopes, dict) or not 0 < len(envelopes) <= MAX_RECIPIENTS:
            return fail("Malformed message.")

        sender = conn["identity"]
        deliveries = []
        for recipient_id, envelope in envelopes.items():
            recipient = identities.get(recipient_id)
            if recipient is None or recipient is sender:
                continue  # unknown or forgotten recipient; skip silently
            if not isinstance(envelope, dict):
                return fail("Malformed message.")
            iv = decode_b64(envelope.get("iv"), 24)
            ciphertext = decode_b64(envelope.get("ct"), MAX_CIPHERTEXT_B64)
            # AES-GCM: 12-byte IV, ciphertext is at least the 16-byte auth tag
            if iv is None or len(iv) != 12 or ciphertext is None or len(ciphertext) < 17:
                return fail("Malformed message.")
            deliveries.append((recipient, envelope))

        live = []
        for recipient, envelope in deliveries:
            payload = {"mid": msg_id, "from": sender["id"], "iv": envelope["iv"], "ct": envelope["ct"]}
            # Kept until the recipient's device acknowledges it (see handle_ack).
            recipient["mailbox"] = (recipient["mailbox"] + [
                {"payload": payload, "sender": sender["id"], "expires": time.time() + MAILBOX_TTL}])[-MAILBOX_MAX:]
            live.extend((sid, payload) for sid in recipient["sids"])
        if deliveries:
            conn["messages"] += 1
            conn["recipients"] += len(deliveries)

    for sid, payload in live:
        emit("new_message", payload, to=sid)
    return {"ok": True, "recipients": len(deliveries)}


@socketio.on("ack")
def handle_ack(data):
    """The recipient's device has the message: drop it from the mailbox and tell the sender."""
    mids = data.get("mids") if isinstance(data, dict) else None
    if not isinstance(mids, list) or len(mids) > MAILBOX_MAX:
        return
    mids = {m for m in mids if isinstance(m, str) and MSG_ID_RE.fullmatch(m)}
    receipts = []
    with users_lock:
        conn = users.get(request.sid)
        if not conn:
            return
        ident = conn["identity"]
        keep = []
        for entry in ident["mailbox"]:
            if entry["payload"]["mid"] in mids:
                sender = identities.get(entry["sender"])
                if sender:
                    receipts.extend((sid, entry["payload"]["mid"]) for sid in sender["sids"])
            else:
                keep.append(entry)
        ident["mailbox"] = keep
        reader = ident["id"]
    for sid, mid in receipts:
        emit("delivered", {"mid": mid, "by": reader}, to=sid)


@socketio.on("typing")
def handle_typing():
    with users_lock:
        conn = users.get(request.sid)
        if not conn or time.monotonic() - conn["last_typing"] < TYPING_INTERVAL:
            return
        conn["last_typing"] = time.monotonic()
        ident_id = conn["identity"]["id"]
    emit("typing", {"id": ident_id}, broadcast=True, include_self=False)


@socketio.on("history_received")
def handle_history_received():
    """A newcomer got the shared history: tell the other members to cancel their backup shares."""
    with users_lock:
        conn = users.get(request.sid)
        if not conn or not take_token(conn):
            return
        ident_id = conn["identity"]["id"]
    emit("history_received", {"id": ident_id}, broadcast=True, include_self=False)


@socketio.on("file_upload_token")
def handle_file_upload_token():
    """Hand a connected user a single-use token for one encrypted upload."""
    with users_lock:
        conn = users.get(request.sid)
        if not conn:
            return fail("Not connected.")
        if not take_token(conn):
            return fail("You are sending too fast.")
    purge_files()
    token = secrets.token_urlsafe(24)
    with files_lock:
        upload_tokens[token] = time.monotonic() + UPLOAD_TOKEN_TTL
    return {"ok": True, "token": token}


@socketio.on("update_profile")
def handle_update_profile(data):
    data = data if isinstance(data, dict) else {}
    with users_lock:
        conn = users.get(request.sid)
        if not conn:
            return fail("Not connected.")
        if not take_token(conn):
            return fail("Slow down a little.")
        ident = conn["identity"]
        new_name = data.get("username", ident["username"])
        new_gender = data.get("gender", ident["gender"])
        if not isinstance(new_name, str) or not USERNAME_RE.fullmatch(new_name.strip()):
            return fail("Names are 2-24 letters, digits, spaces, _ or -.")
        if new_gender not in GENDERS:
            return fail("Choose one of the listed options.")
        new_name = new_name.strip()
        if name_taken(new_name, exclude_id=ident["id"]):
            return fail("That name is already taken.")
        old_name = ident["username"]
        ident["username"], ident["gender"] = new_name, new_gender
        if new_name != old_name:
            conn["renames"] += 1
        view = public_view(ident)

    emit("profile_updated", {**view, "old_username": old_name}, broadcast=True)
    return {"ok": True, "me": view}


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
