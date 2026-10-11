import base64
import os
import secrets
import time

import pytest

import app as server
from app import app, socketio


def fake_public_key(seed):
    return base64.b64encode(b"\x04" + bytes([seed]) * 64).decode()


def envelope(size=40):
    return {
        "iv": base64.b64encode(os.urandom(12)).decode(),
        "ct": base64.b64encode(os.urandom(size)).decode(),
    }


def connect(seed, name=None, token=None, gender="male", returning=False):
    auth = {
        "public_key": fake_public_key(seed),
        "token": token or secrets.token_urlsafe(32),
        "username": name or f"user{seed}",
        "gender": gender,
        "returning": returning,
    }
    client = socketio.test_client(app, auth=auth)
    client.token = auth["token"]
    return client


def events(client, name):
    return [e["args"][0] for e in client.get_received() if e["name"] == name]


def welcome(client):
    return events(client, "welcome")[0]


@pytest.fixture(autouse=True)
def clean_state(monkeypatch):
    server.users.clear()
    server.identities.clear()
    server.id_by_token.clear()
    server.files.clear()
    server.upload_tokens.clear()
    monkeypatch.setattr(server, "PRESENCE_GRACE", 0.05)
    yield


# ------------------------------------------------------------------ identity

def test_connection_needs_key_token_and_valid_name():
    assert not socketio.test_client(app).is_connected()
    assert not socketio.test_client(app, auth={"public_key": fake_public_key(1)}).is_connected()  # no token
    assert not socketio.test_client(app, auth={"public_key": "nope", "token": "x" * 40}).is_connected()
    assert not connect(1, name="<script>").is_connected()
    assert connect(1, name="Alice").is_connected()


def test_names_are_unique():
    assert connect(1, name="Alice").is_connected()
    assert not connect(2, name="alice").is_connected()


def test_welcome_contains_profile_and_roster_without_socket_ids():
    alice = connect(1, name="Alice", gender="female")
    me = welcome(alice)["me"]
    assert me["username"] == "Alice" and me["gender"] == "female" and me["online"] is True
    bob = connect(2, name="Bob")
    roster = welcome(bob)["members"]
    assert [m["id"] for m in roster] == [me["id"]]
    assert all(m["id"] not in server.users for m in roster)  # public ids are not socket sids
    assert events(alice, "user_joined")[0]["username"] == "Bob"


def test_invalid_gender_falls_back_to_unspecified():
    alice = connect(1, name="Alice", gender="robot")
    assert welcome(alice)["me"]["gender"] == "unspecified"


def test_refresh_keeps_identity_and_announces_nothing():
    alice = connect(1, name="Alice")
    alice_id = welcome(alice)["me"]["id"]
    bob = connect(2, name="Bob")
    welcome(bob)
    alice.get_received()

    # Bob refreshes: disconnect + reconnect with the same token, before the grace period ends.
    bob.disconnect()
    bob2 = connect(2, name="Bob", token=bob.token, returning=True)
    data = welcome(bob2)
    assert data["me"]["username"] == "Bob"
    assert [m["id"] for m in data["members"]] == [alice_id]
    time.sleep(0.15)
    received = {e["name"] for e in alice.get_received()}
    assert "user_left" not in received and "user_joined" not in received


def test_going_away_is_silent_presence_not_a_left_message():
    alice = connect(1, name="Alice")
    welcome(alice)
    bob = connect(2, name="Bob")
    bob_id = welcome(bob)["me"]["id"]
    alice.get_received()
    bob.disconnect()
    time.sleep(0.2)
    presence = events(alice, "presence")
    assert presence and presence[-1]["id"] == bob_id and presence[-1]["online"] is False
    assert presence[-1]["last_seen"] > 0


def test_name_is_reserved_while_away_and_kept_on_return():
    bob = connect(2, name="Bob")
    welcome(bob)
    bob.disconnect()
    time.sleep(0.2)
    assert not connect(3, name="bob").is_connected()  # someone else can't grab it
    back = connect(2, name="whatever", token=bob.token, returning=True)
    assert welcome(back)["me"]["username"] == "Bob"  # the name sticks to the token


def test_messages_wait_in_mailbox_while_screen_is_off():
    alice = connect(1, name="Alice")
    alice_id = welcome(alice)["me"]["id"]
    bob = connect(2, name="Bob")
    bob_id = welcome(bob)["me"]["id"]
    bob.disconnect()

    payload = envelope()
    result = alice.emit("send_message", {"envelopes": {bob_id: payload}}, callback=True)
    assert result == {"ok": True, "delivered": 0, "queued": 1}

    bob2 = connect(2, name="Bob", token=bob.token, returning=True)
    received = bob2.get_received()
    assert [e["name"] for e in received][:2] == ["welcome", "new_message"]
    assert received[1]["args"][0] == {"from": alice_id, **payload}


# ------------------------------------------------------------------ messages

def test_ciphertext_is_routed_only_to_its_recipient():
    alice, bob, carol = connect(1), connect(2), connect(3)
    alice_id = welcome(alice)["me"]["id"]
    bob_id = welcome(bob)["me"]["id"]
    welcome(carol)
    for client in (alice, bob, carol):
        client.get_received()

    payload = envelope()
    result = alice.emit("send_message", {"envelopes": {bob_id: payload}}, callback=True)
    assert result == {"ok": True, "delivered": 1, "queued": 0}
    assert events(bob, "new_message") == [{"from": alice_id, **payload}]
    assert events(carol, "new_message") == []
    assert events(alice, "new_message") == []


@pytest.mark.parametrize("data", [None, "hello", {"message": "plaintext is not accepted"}, {"envelopes": {}},
                                  {"envelopes": "x"}])
def test_malformed_messages_are_rejected(data):
    alice, bob = connect(1), connect(2)
    welcome(alice)
    welcome(bob)
    bob.get_received()
    assert alice.emit("send_message", data, callback=True)["ok"] is False
    assert events(bob, "new_message") == []


def test_bad_envelope_fields_are_rejected():
    alice, bob = connect(1), connect(2)
    welcome(alice)
    bob_id = welcome(bob)["me"]["id"]
    bad_iv = {"iv": base64.b64encode(b"short").decode(), "ct": envelope()["ct"]}
    for bad in (bad_iv, envelope(20_000), {"iv": "!!", "ct": "!!"}):
        assert alice.emit("send_message", {"envelopes": {bob_id: bad}}, callback=True)["ok"] is False
    assert events(bob, "new_message") == []


def test_profile_update_validation_uniqueness_and_broadcast():
    alice, bob = connect(1, name="Alice"), connect(2, name="Bob")
    alice_id = welcome(alice)["me"]["id"]
    welcome(bob)
    bob.get_received()

    assert alice.emit("update_profile", {"username": "<script>"}, callback=True)["ok"] is False
    assert alice.emit("update_profile", {"gender": "robot"}, callback=True)["ok"] is False
    assert alice.emit("update_profile", {"username": "bob"}, callback=True)["error"] == "That name is already taken."

    result = alice.emit("update_profile", {"username": "Alicia", "gender": "transgender"}, callback=True)
    assert result["ok"] and result["me"]["username"] == "Alicia"
    update = events(bob, "profile_updated")[0]
    assert update["id"] == alice_id and update["old_username"] == "Alice" and update["gender"] == "transgender"


def test_typing_is_broadcast_and_throttled():
    alice, bob = connect(1), connect(2)
    alice_id = welcome(alice)["me"]["id"]
    welcome(bob)
    bob.get_received()
    alice.emit("typing")
    alice.emit("typing")
    assert events(bob, "typing") == [{"id": alice_id}]


def test_rate_limit_blocks_floods():
    alice, bob = connect(1), connect(2)
    welcome(alice)
    bob_id = welcome(bob)["me"]["id"]
    bob.get_received()
    results = [alice.emit("send_message", {"envelopes": {bob_id: envelope()}}, callback=True)["ok"]
               for _ in range(30)]
    assert 10 <= results.count(True) < 15
    assert results[-1] is False


# ------------------------------------------------------------------ encrypted files

def test_file_upload_needs_a_one_time_token():
    alice = connect(1)
    welcome(alice)
    http = app.test_client()
    data = os.urandom(5000)

    assert http.post("/files", data=data).status_code == 403
    grant = alice.emit("file_upload_token", callback=True)
    assert grant["ok"]
    response = http.post("/files", data=data, headers={"X-Upload-Token": grant["token"]})
    assert response.status_code == 200
    file_id = response.get_json()["id"]
    # the token cannot be reused
    assert http.post("/files", data=data, headers={"X-Upload-Token": grant["token"]}).status_code == 403

    download = http.get(f"/files/{file_id}")
    assert download.data == data
    assert download.headers["Content-Type"] == "application/octet-stream"
    assert download.headers["Cache-Control"] == "no-store"


def test_files_expire_and_size_is_capped():
    alice = connect(1)
    welcome(alice)
    http = app.test_client()
    token = alice.emit("file_upload_token", callback=True)["token"]
    file_id = http.post("/files", data=os.urandom(100), headers={"X-Upload-Token": token}).get_json()["id"]

    server.files[file_id]["expires"] = time.monotonic() - 1
    server.purge_files()
    assert http.get(f"/files/{file_id}").status_code == 404

    token = alice.emit("file_upload_token", callback=True)["token"]
    too_big = b"x" * (server.MAX_FILE_BYTES + 1)
    assert http.post("/files", data=too_big, headers={"X-Upload-Token": token}).status_code == 413


def test_security_headers():
    response = app.test_client().get("/")
    assert response.status_code == 200
    csp = response.headers["Content-Security-Policy"]
    assert "script-src 'self' https://cdnjs.cloudflare.com" in csp
    assert "'unsafe-inline'" not in csp
    assert "img-src 'self' blob: data:" in csp
    assert response.headers["Permissions-Policy"].startswith("camera=(self)")
    assert response.headers["X-Frame-Options"] == "DENY"
