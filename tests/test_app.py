import base64
import os

import pytest

from app import app, socketio, users, sid_by_id


def fake_public_key(seed):
    return base64.b64encode(b"\x04" + bytes([seed]) * 64).decode()


def envelope(size=40):
    return {
        "iv": base64.b64encode(os.urandom(12)).decode(),
        "ct": base64.b64encode(os.urandom(size)).decode(),
    }


def connect(seed):
    return socketio.test_client(app, auth={"public_key": fake_public_key(seed)})


def events(client, name):
    return [e["args"][0] for e in client.get_received() if e["name"] == name]


@pytest.fixture(autouse=True)
def clean_state():
    users.clear()
    sid_by_id.clear()
    yield
    users.clear()
    sid_by_id.clear()


def welcome(client):
    return events(client, "welcome")[0]


def test_connection_without_valid_public_key_is_refused():
    assert not socketio.test_client(app).is_connected()
    assert not socketio.test_client(app, auth={"public_key": "not-base64!"}).is_connected()
    short_key = base64.b64encode(b"\x04" + b"a" * 10).decode()
    assert not socketio.test_client(app, auth={"public_key": short_key}).is_connected()


def test_welcome_lists_existing_members_without_socket_ids():
    alice = connect(1)
    alice_id = welcome(alice)["id"]
    bob = connect(2)
    data = welcome(bob)
    assert [m["id"] for m in data["members"]] == [alice_id]
    assert data["members"][0]["public_key"] == fake_public_key(1)
    assert alice_id not in sid_by_id.values()  # public id is not the socket sid
    joined = events(alice, "user_joined")
    assert joined[0]["id"] == data["id"]


def test_ciphertext_is_routed_only_to_its_recipient():
    alice, bob, carol = connect(1), connect(2), connect(3)
    alice_id = welcome(alice)["id"]
    bob_id = welcome(bob)["id"]
    welcome(carol)
    for client in (alice, bob, carol):
        client.get_received()

    payload = envelope()
    alice.emit("send_message", {"envelopes": {bob_id: payload}})

    assert events(bob, "new_message") == [{"from": alice_id, **payload}]
    assert events(carol, "new_message") == []
    assert events(alice, "new_message") == []


@pytest.mark.parametrize(
    "data",
    [
        None,
        "hello",
        {"message": "plaintext is not accepted"},
        {"envelopes": {}},
        {"envelopes": "x"},
    ],
)
def test_malformed_messages_are_rejected(data):
    alice, bob = connect(1), connect(2)
    welcome(alice)
    welcome(bob)
    bob.get_received()
    alice.emit("send_message", data)
    assert events(alice, "error_message")
    assert events(bob, "new_message") == []


def test_bad_envelope_fields_are_rejected():
    alice, bob = connect(1), connect(2)
    welcome(alice)
    bob_id = welcome(bob)["id"]
    bad_iv = {"iv": base64.b64encode(b"short").decode(), "ct": envelope()["ct"]}
    huge_ct = envelope(20_000)
    for bad in (bad_iv, huge_ct, {"iv": "!!", "ct": "!!"}):
        alice.emit("send_message", {"envelopes": {bob_id: bad}})
    assert len(events(alice, "error_message")) == 3
    assert events(bob, "new_message") == []


def test_username_validation_and_uniqueness():
    alice, bob = connect(1), connect(2)
    alice_id = welcome(alice)["id"]
    welcome(bob)
    bob.get_received()

    alice.emit("update_username", {"username": "<script>"})
    alice.emit("update_username", {"username": "x" * 50})
    assert len(events(alice, "error_message")) == 2

    alice.emit("update_username", {"username": "Alice"})
    assert events(bob, "username_updated") == [{"id": alice_id, "username": "Alice"}]

    bob.emit("update_username", {"username": "alice"})
    assert events(bob, "error_message") == [{"error": "That username is already taken."}]


def test_rate_limit_blocks_floods():
    alice, bob = connect(1), connect(2)
    welcome(alice)
    bob_id = welcome(bob)["id"]
    bob.get_received()
    for _ in range(30):
        alice.emit("send_message", {"envelopes": {bob_id: envelope()}})
    delivered = events(bob, "new_message")
    assert 10 <= len(delivered) < 15
    assert events(alice, "error_message")


def test_disconnect_announces_public_id():
    alice, bob = connect(1), connect(2)
    welcome(alice)
    bob_id = welcome(bob)["id"]
    alice.get_received()
    bob.disconnect()
    assert events(alice, "user_left") == [{"id": bob_id}]
    assert bob_id not in sid_by_id


def test_security_headers():
    response = app.test_client().get("/")
    assert response.status_code == 200
    csp = response.headers["Content-Security-Policy"]
    assert "script-src 'self' https://cdnjs.cloudflare.com" in csp
    assert "'unsafe-inline'" not in csp
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
