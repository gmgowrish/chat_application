import base64

import pytest
from sqlalchemy import delete

import analytics
from admin import FUNNY_URL
from app import app, socketio, users, sid_by_id

ADMIN = "/test-secret-panel-path-0123456789"
PASSWORD = "correct horse battery staple"


@pytest.fixture(autouse=True)
def clean_db():
    with analytics.engine.begin() as conn:
        for table in (analytics.visits, analytics.chat_sessions, analytics.security_events, analytics.admin_state):
            conn.execute(delete(table))
    users.clear()
    sid_by_id.clear()
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
    chatter = socketio.test_client(app, auth={"public_key": key}, headers={"User-Agent": "Mozilla/5.0 (iPhone) Safari/604.1"})
    assert chatter.is_connected()

    response = login(client)
    assert response.status_code == 303
    page = client.get(ADMIN)
    assert page.status_code == 200
    assert page.headers["Cache-Control"] == "no-store"
    html = page.get_data(as_text=True)
    assert "Chat analytics" in html and "Windows" in html and "iOS" in html
    assert "Chatting now" in html and "User_" in html


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
