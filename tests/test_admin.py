import base64

import pytest
from sqlalchemy import delete

import analytics
from admin import FUNNY_URL
import app as server
from app import app, socketio

ADMIN = "/test-secret-panel-path-0123456789"
PASSWORD = "correct horse battery staple"


@pytest.fixture(autouse=True)
def clean_db():
    with analytics.engine.begin() as conn:
        for table in (analytics.visits, analytics.chat_sessions, analytics.security_events, analytics.admin_state):
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
