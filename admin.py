"""Hidden admin dashboard.

* The dashboard lives at a secret path taken from the ADMIN_PATH env var. It is
  never linked, listed or committed anywhere. Without ADMIN_PATH the dashboard
  does not exist at all.
* Without a valid admin session, the secret path returns exactly the same 404
  page as any unknown URL, so nobody can tell it exists.
* The owner logs in by typing the password into the invisible field on that 404
  page. Wrong passwords, typing on any other 404 page and well-known probe URLs
  (/admin, /wp-login.php, /.env, ...) are logged and redirected to FUNNY_URL.
  Three strikes within 24 hours block the IP from the secret path.
"""
import hmac
import os
import re
import secrets
from datetime import datetime, timedelta, timezone

from flask import abort, redirect, render_template, request, session
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

import analytics

def _setting(name):
    """Env value with stray whitespace/quotes removed (easy to paste in by accident)."""
    return os.environ.get(name, "").strip().strip("'\"").strip()


ADMIN_PATH = _setting("ADMIN_PATH").strip("/")
def _looks_like_hash(value):
    return bool(re.fullmatch(r"(scrypt|pbkdf2)(:[\w-]+)*\$[^$]+\$[0-9a-f]+", value))


def _password_setting():
    """Returns (hash, source). ADMIN_PASSWORD (plain) wins; a plain password pasted into
    ADMIN_PASSWORD_HASH by mistake is also accepted and hashed here."""
    plain = _setting("ADMIN_PASSWORD")
    if plain:
        return generate_password_hash(plain), "ADMIN_PASSWORD"
    value = _setting("ADMIN_PASSWORD_HASH")
    if not value:
        return "", "none"
    if _looks_like_hash(value):
        return value, "ADMIN_PASSWORD_HASH (hash)"
    return generate_password_hash(value), "ADMIN_PASSWORD_HASH (plain password, accepted)"


ADMIN_PASSWORD_HASH, PASSWORD_SOURCE = _password_setting()
ADMIN_ALLOWED_IPS = {ip.strip() for ip in os.environ.get("ADMIN_ALLOWED_IPS", "").split(",") if ip.strip()}
FUNNY_URL = os.environ.get("FUNNY_URL", "https://www.youtube.com/watch?v=dQw4w9WgXcQ")
MAX_STRIKES = 3

DECOY_PATHS = {
    "/admin", "/admin/", "/administrator", "/admin.php", "/admin/login", "/login", "/dashboard",
    "/wp-admin", "/wp-admin/", "/wp-login.php", "/xmlrpc.php", "/phpmyadmin", "/pma",
    "/.env", "/.git/config", "/.git/HEAD", "/config.php", "/server-status", "/cpanel",
}


def startup_report():
    """One log line so the owner can check the setup in Render's logs (never prints secrets)."""
    source = PASSWORD_SOURCE
    state = "ENABLED" if enabled() else "DISABLED"
    print(f"[admin] dashboard {state} | ADMIN_PATH length={len(ADMIN_PATH)} (needs >= 16) | "
          f"password from {source} | ADMIN_PATH starts with {ADMIN_PATH[:4]!r}", flush=True)


def enabled():
    return len(ADMIN_PATH) >= 16 and bool(ADMIN_PASSWORD_HASH)


def is_admin_path(path):
    return enabled() and hmac.compare_digest(path.strip("/").encode(), ADMIN_PATH.encode())


def no_store(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    return response


def init_admin(app, client_ip, online_users, roster=lambda: [], remove_person=lambda _id: False):
    """Wire the hidden admin into `app`.

    client_ip() -> the visitor's IP; online_users() -> list of live connection dicts;
    roster() -> everyone in the chat (online + recently active); remove_person(id).
    """

    startup_report()

    def strike(kind):
        # Never store the secret path itself, even in the private database.
        path = "(admin)" if is_admin_path(request.path) else request.path
        analytics.record_security_event(kind, client_ip(), path, request.headers.get("User-Agent"))
        if request.method == "POST":
            # CSP form-action blocks cross-site redirects after a form POST, so use a meta refresh.
            page = f'<!DOCTYPE html><meta http-equiv="refresh" content="0;url={escape(FUNNY_URL)}">'
            return no_store(app.make_response((page, 200)))
        return redirect(FUNNY_URL, code=302)

    def is_logged_in():
        epoch = session.get("admin_epoch")
        return epoch is not None and epoch == analytics.admin_epoch()

    def not_found_page():
        return no_store(app.make_response((render_template("404.html"), 404)))

    @app.before_request
    def guard_admin():
        path = request.path
        if path in DECOY_PATHS:
            return strike("decoy_hit")
        if not is_admin_path(path):
            return None

        ip = client_ip()
        since = datetime.now(timezone.utc) - timedelta(hours=24)
        if analytics.failed_admin_logins_since(ip, since) >= MAX_STRIKES:
            return strike("admin_blocked")
        if ADMIN_ALLOWED_IPS and ip not in ADMIN_ALLOWED_IPS:
            return strike("admin_ip_denied")

        if request.method == "POST":
            return handle_post()
        if not is_logged_in():
            return not_found_page()
        response = app.make_response(render_template(
            "admin.html", data=analytics.dashboard_data(), online=online_users(), people=roster(),
            csrf=session["csrf"], now=datetime.now(timezone.utc),
        ))
        return no_store(response)

    def handle_post():
        action = request.form.get("action")
        if action == "remove_person":
            if not is_logged_in() or not hmac.compare_digest(request.form.get("csrf", ""), session.get("csrf", "")):
                abort(404)
            remove_person(request.form.get("person_id", ""))
            return redirect(request.path, code=303)
        if action in ("logout", "logout_all"):
            if not is_logged_in() or not hmac.compare_digest(request.form.get("csrf", ""), session.get("csrf", "")):
                abort(404)
            if action == "logout_all":
                analytics.bump_admin_epoch()
            session.clear()
            return redirect("/", code=303)

        password = request.form.get("q", "")
        if not password or not check_password_hash(ADMIN_PASSWORD_HASH, password):
            return strike("admin_login_failed")
        session.clear()
        session.permanent = True
        session["admin_epoch"] = analytics.admin_epoch()
        session["csrf"] = secrets.token_urlsafe(24)
        analytics.record_security_event("admin_login_ok", client_ip(), "(admin)", request.headers.get("User-Agent"))
        return redirect(request.path, code=303)

    @app.errorhandler(404)
    @app.errorhandler(405)
    def page_not_found(_error):
        # Typing into the hidden field on a non-admin 404 page behaves exactly like
        # a wrong admin password, so the real admin path can't be told apart.
        if request.method == "POST":
            return strike("hidden_form_probe")
        return not_found_page()
