import base64

import pytest
from sqlalchemy import delete

import analytics
from admin import FUNNY_URL
import app as server
from app import app, flush_analytics, socketio

ADMIN = "/test-secret-panel-path-0123456789"
PASSWORD = "correct horse battery staple"


@pytest.fixture(autouse=True)
def clean_db():
    with analytics.engine.begin() as conn:
        for table in (analytics.visits, analytics.chat_sessions, analytics.security_events, analytics.admin_state,
                      analytics.ip_locations):
            conn.execute(delete(table))
    server.users.clear()
    server.identities.clear()
    server.id_by_token.clear()
    yield


@pytest.fixture
def client():
    return app.test_client()


def funny(response):
    """GET strikes redirect; POST strikes answer with a meta refresh (CSP-safe)."""
    if response.status_code == 302:
        return response.location == FUNNY_URL
    return response.status_code == 200 and f'url={FUNNY_URL}"'.encode() in response.data


def login(client, ip="10.0.0.5"):
    return client.post(ADMIN, data={"q": PASSWORD}, environ_base={"REMOTE_ADDR": ip})


def test_admin_path_looks_exactly_like_any_404(client):
    hidden = client.get(ADMIN)
    random = client.get("/some-page-that-does-not-exist")
    assert hidden.status_code == random.status_code == 404
    assert hidden.data == random.data
    assert ADMIN.strip("/").encode() not in client.get("/").data


def test_decoy_paths_redirect_to_funny_site_and_are_logged(client):
    for path in ("/admin", "/wp-login.php", "/.env"):
        response = client.get(path)
        assert funny(response)
    kinds = [e["kind"] for e in analytics.dashboard_data()["security"]]
    assert kinds.count("decoy_hit") == 3


def test_wrong_password_redirects_and_three_strikes_block_the_ip(client):
    for _ in range(3):
        response = client.post(ADMIN, data={"q": "guess"}, environ_base={"REMOTE_ADDR": "6.6.6.6"})
        assert funny(response)
    # Even the right password is refused from a blocked IP...
    assert funny(login(client, ip="6.6.6.6"))
    # ...while the owner's IP is unaffected.
    assert login(client).status_code == 303
    events = analytics.dashboard_data()["security"]
    assert all(e["path"] != ADMIN for e in events)  # secret path never stored


def test_typing_on_a_normal_404_page_acts_like_a_wrong_password(client):
    response = client.post("/nope", data={"q": "anything"})
    assert funny(response)


def test_login_shows_dashboard_with_visits_and_chat_sessions(client):
    client.get("/", headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/140.0 Safari/537.36"})
    key = base64.b64encode(b"\x04" + b"\x01" * 64).decode()
    chatter = socketio.test_client(
        app, auth={"public_key": key, "token": "t" * 43, "username": "Chatter", "gender": "female"},
        headers={"User-Agent": "Mozilla/5.0 (iPhone) Safari/604.1"})
    assert chatter.is_connected()

    response = login(client)
    assert response.status_code == 303
    flush_analytics()
    page = client.get(ADMIN)
    assert page.status_code == 200
    assert page.headers["Cache-Control"] == "no-store"
    html = page.get_data(as_text=True)
    assert "Chat analytics" in html and "Windows" in html and "iOS" in html
    assert "Chatting now" in html and "Chatter" in html


def test_logout_all_devices_invalidates_every_session(client):
    login(client)
    other_device = app.test_client()
    login(other_device, ip="10.0.0.6")
    with client.session_transaction() as sess:
        csrf = sess["csrf"]
    client.post(ADMIN, data={"action": "logout_all", "csrf": csrf})
    assert other_device.get(ADMIN).status_code == 404


def test_user_agent_parsing():
    assert analytics.parse_user_agent(
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/140.0 Mobile Safari/537.36"
    ) == ("Chrome", "Android", "Mobile")
    assert analytics.parse_user_agent("curl/8.9")[2] == "Bot"


def test_admin_can_remove_a_person_from_the_chat(client):
    def join(seed, name):
        return socketio.test_client(app, auth={
            "public_key": base64.b64encode(b"\x04" + bytes([seed]) * 64).decode(),
            "token": f"{name}-token".ljust(40, "x"), "username": name, "gender": "male"})

    alice, bob = join(1, "Alice"), join(2, "Bob")
    bob_id = [e for e in alice.get_received() if e["name"] == "user_joined"][0]["args"][0]["id"]

    login(client)
    page = client.get(ADMIN).get_data(as_text=True)
    assert "People in the chat" in page and "Remove" in page and "Bob" in page
    with client.session_transaction() as sess:
        csrf = sess["csrf"]

    # without the CSRF token nothing happens
    client.post(ADMIN, data={"action": "remove_person", "person_id": bob_id})
    assert bob_id in server.identities

    response = client.post(ADMIN, data={"action": "remove_person", "person_id": bob_id, "csrf": csrf})
    assert response.status_code == 303
    assert bob_id not in server.identities
    assert not bob.is_connected()
    assert {"id": bob_id} in [e["args"][0] for e in alice.get_received() if e["name"] == "user_removed"]
    # the name is free again
    assert join(3, "Bob").is_connected()


def test_recently_active_window_is_two_hours():
    assert server.ROSTER_TTL == 2 * 3600


def test_settings_tolerate_pasted_quotes_and_spaces(monkeypatch):
    import importlib
    import admin as admin_module
    monkeypatch.setenv("ADMIN_PATH", "  '/abc-secret-path-1234567890'\n")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", ' "scrypt:1$2$3" ')
    reloaded = importlib.reload(admin_module)
    assert reloaded.ADMIN_PATH == "abc-secret-path-1234567890"
    assert reloaded.ADMIN_PASSWORD_HASH == "scrypt:1$2$3"
    monkeypatch.undo()
    importlib.reload(admin_module)


def test_plain_admin_password_setting(monkeypatch):
    import importlib
    from werkzeug.security import check_password_hash
    import admin as admin_module
    monkeypatch.setenv("ADMIN_PASSWORD", " 70199@gMg ")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "broken")
    reloaded = importlib.reload(admin_module)
    assert check_password_hash(reloaded.ADMIN_PASSWORD_HASH, "70199@gMg")
    monkeypatch.undo()
    importlib.reload(admin_module)


@pytest.mark.parametrize("value, source", [
    ("70199@gMg", "ADMIN_PASSWORD_HASH (plain password, accepted)"),
    (None, "ADMIN_PASSWORD_HASH (hash)"),
])
def test_password_hash_setting_accepts_plain_text_by_mistake(monkeypatch, value, source):
    import importlib
    from werkzeug.security import check_password_hash, generate_password_hash
    import admin as admin_module
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", value or generate_password_hash("70199@gMg"))
    reloaded = importlib.reload(admin_module)
    assert reloaded.PASSWORD_SOURCE == source
    assert check_password_hash(reloaded.ADMIN_PASSWORD_HASH, "70199@gMg")
    monkeypatch.undo()
    importlib.reload(admin_module)


def test_bots_are_hidden_by_default(client):
    bot = {"User-Agent": "Go-http-client/1.1"}
    human = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/141.0 Safari/537.36"}
    client.get("/", headers=bot)
    client.get("/", headers=human)
    flush_analytics()
    hidden = analytics.dashboard_data()
    assert hidden["stats"]["visits_24h"] == 1
    assert [v["device"] for v in hidden["recent_visits"]] == ["Desktop"]
    assert hidden["hidden_bot_visits_7d"] == 1
    shown = analytics.dashboard_data(include_bots=True)
    assert shown["stats"]["visits_24h"] == 2

    login(client)
    page = client.get(ADMIN).get_data(as_text=True)
    assert "Show bots (1 hidden this week)" in page and "Go-http-client" not in page
    page = client.get(ADMIN + "?bots=1").get_data(as_text=True)
    assert "Hide bots" in page and "Go-http-client" in page


def test_ip_locations_are_city_level_cached_and_shown(client, monkeypatch):
    calls = []

    def fake_lookup(ip):
        calls.append(ip)
        return "Chennai, Tamil Nadu, IN", "13.0878,80.2785"

    monkeypatch.setattr(analytics, "_lookup", fake_lookup)
    monkeypatch.setattr(analytics.threading, "Thread",
                        lambda target, args, daemon: type("T", (), {"start": lambda self: target(*args)})())
    assert analytics.locations(["49.204.1.1"]) == {}           # first time: looked up in the background
    assert analytics.locations(["49.204.1.1"]) == {"49.204.1.1": {"label": "Chennai, Tamil Nadu, IN",
                                                                  "loc": "13.0878,80.2785"}}
    assert calls == ["49.204.1.1"]                              # cached afterwards

    client.get("/", headers={"User-Agent": "Mozilla/5.0 Chrome/141.0", "X-Forwarded-For": "x"},
               environ_base={"REMOTE_ADDR": "49.204.1.1"})
    flush_analytics()
    login(client)
    page = client.get(ADMIN).get_data(as_text=True)
    assert "📍 Chennai, Tamil Nadu, IN" in page and "openstreetmap.org/?mlat=13.0878" in page


def test_private_addresses_are_not_sent_anywhere():
    assert analytics._lookup("127.0.0.1") == ("Local network", "")
    assert analytics._lookup("10.30.173.133") == ("Local network", "")


def _raw_dump():
    """Every stored value, as someone reading the database directly would see it."""
    with analytics.engine.connect() as conn:
        return " ".join(str(v) for table in (analytics.visits, analytics.chat_sessions, analytics.security_events,
                                              analytics.ip_locations)
                        for row in conn.execute(table.select()) for v in row)


def test_identifying_data_is_unreadable_in_the_database_but_shown_on_the_dashboard(client):
    ua = "Mozilla/5.0 (X11; Linux x86_64) Chrome/141.0 PrivacyProbe"
    client.get("/", headers={"User-Agent": ua, "Referer": "https://secret-referrer.example/"},
               environ_base={"REMOTE_ADDR": "203.0.113.77"})
    chatter = socketio.test_client(app, auth={
        "public_key": base64.b64encode(b"\x04" + b"\x07" * 64).decode(), "token": "p" * 43,
        "username": "SecretName", "gender": "female"}, headers={"User-Agent": ua})
    assert chatter.is_connected()
    chatter.disconnect()
    client.post("/admin", environ_base={"REMOTE_ADDR": "203.0.113.77"}, headers={"User-Agent": ua})
    flush_analytics()

    raw = _raw_dump()
    for secret in ("203.0.113.77", "PrivacyProbe", "SecretName", "secret-referrer"):
        assert secret not in raw, f"{secret} stored readably"

    data = analytics.dashboard_data()
    assert data["recent_visits"][0]["ip"] == "203.0.113.77"
    assert data["recent_visits"][0]["user_agent"] == ua
    assert data["recent_sessions"][0]["username"] == "SecretName"
    assert data["security"][0]["ip"] == "203.0.113.77"
    assert data["stats"]["unique_ips_24h"] == 1


def test_lockout_still_works_with_fingerprinted_ips(client):
    for _ in range(3):
        client.post(ADMIN, data={"q": "nope"}, environ_base={"REMOTE_ADDR": "198.51.100.9"})
    assert funny(login(client, ip="198.51.100.9"))
    assert login(client).status_code == 303


def test_older_plain_rows_are_encrypted_on_start():
    from sqlalchemy import insert
    with analytics.engine.begin() as conn:
        conn.execute(insert(analytics.visits).values(ts=analytics.now(), ip="192.0.2.5", user_agent="LegacyUA/1.0",
                                                     forwarded_for="192.0.2.5, 10.0.0.1", device="Desktop"))
        conn.execute(insert(analytics.chat_sessions).values(public_id="x", username="LegacyName", ip="192.0.2.5",
                                                            connected_at=analytics.now(), device="Desktop"))
        conn.execute(insert(analytics.ip_locations).values(ip="192.0.2.5", label="Testville", loc="",
                                                           fetched_at=analytics.now()))
    assert analytics._migrate() == 3
    raw = _raw_dump()
    assert "192.0.2.5" not in raw and "LegacyUA" not in raw and "LegacyName" not in raw
    data = analytics.dashboard_data()
    assert data["recent_visits"][0]["ip"] == "192.0.2.5" and data["recent_visits"][0]["user_agent"] == "LegacyUA/1.0"
    assert data["recent_sessions"][0]["username"] == "LegacyName"
    assert analytics.locations(["192.0.2.5"]) == {"192.0.2.5": {"label": "Testville", "loc": ""}}
    assert analytics._migrate() == 0  # idempotent


def test_ip_fingerprint_is_keyed_not_a_plain_hash():
    import hashlib
    fingerprint = analytics.ip_hash("8.8.8.8")
    assert len(fingerprint) == 64 and fingerprint != hashlib.sha256(b"8.8.8.8").hexdigest()
    assert analytics.unseal(analytics.seal("hello")) == "hello"
    assert analytics.unseal("v1:" + base64.b64encode(b"x" * 40).decode()) is None  # tampered/foreign → None
