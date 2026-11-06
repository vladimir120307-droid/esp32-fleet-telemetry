import json
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server"))
from app import create_app, sign  # noqa: E402

TS = 1_780_000_000


def reading(seq, ts=TS, temp=20.0, **kw):
    return {"seq": seq, "ts": ts + seq * 60, "temp_c": temp, **kw}


@pytest.fixture()
def api(tmp_path):
    app = create_app(tmp_path / "t.db", admin_key="root")
    store = app.state.store
    store.add_customer("c1", "One", "key-1")
    store.add_customer("c2", "Two", "key-2")
    store.add_device("d1", "c1", "secret-1")
    store.add_device("d2", "c2", "secret-2")
    return TestClient(app), store


def post(client, did, secret, readings, ts=None, tamper=False):
    body = json.dumps({"firmware": "1.0", "readings": readings}).encode()
    ts = str(ts or int(time.time()))
    sig = sign(secret, did, ts, body)
    if tamper:
        body = body.replace(b"20.0", b"99.0")
    return client.post("/v1/ingest", content=body,
                       headers={"X-Device-Id": did, "X-Timestamp": ts, "X-Signature": sig})


def bearer(key):
    return {"Authorization": f"Bearer {key}"}


def test_stores_a_batch_and_acks_it(api):
    client, _ = api
    r = post(client, "d1", "secret-1", [reading(i) for i in range(5)])
    assert r.status_code == 200
    assert r.json() == {"accepted": 5, "duplicates": 0, "ack_seq": 4}


def test_resend_does_not_create_rows_or_skew_rollups(api):
    client, store = api
    batch = [reading(i, temp=10.0) for i in range(3)]
    post(client, "d1", "secret-1", batch)
    r = post(client, "d1", "secret-1", batch)
    assert r.json() == {"accepted": 0, "duplicates": 3, "ack_seq": 2}
    assert store.db.execute("SELECT COUNT(*) FROM readings").fetchone()[0] == 3
    assert store.db.execute("SELECT SUM(n), SUM(temp_sum) FROM rollup_1m").fetchone()[:] == (3, 30.0)


def test_ack_stops_at_the_first_hole_until_it_is_filled(api):
    client, _ = api
    assert post(client, "d1", "secret-1", [reading(0), reading(1), reading(3)]).json()["ack_seq"] == 1
    assert post(client, "d1", "secret-1", [reading(2)]).json()["ack_seq"] == 3


def test_wrong_key_unknown_device_and_tampered_body_are_refused(api):
    client, store = api
    assert post(client, "d1", "wrong", [reading(0)]).status_code == 401
    assert post(client, "ghost", "secret-1", [reading(0)]).status_code == 401
    assert post(client, "d1", "secret-1", [reading(0)], tamper=True).status_code == 401
    assert store.db.execute("SELECT COUNT(*) FROM readings").fetchone()[0] == 0


def test_one_device_cannot_write_as_another(api):
    client, _ = api
    assert post(client, "d2", "secret-1", [reading(0)]).status_code == 401


def test_captured_request_cannot_be_replayed_later(api):
    client, _ = api
    assert post(client, "d1", "secret-1", [reading(0)], ts=int(time.time()) - 3600).status_code == 401


def test_revoked_device_is_blocked_and_others_keep_working(api):
    client, _ = api
    assert client.post("/admin/devices/d1/revoke", headers={"X-Admin-Key": "bad"}).status_code == 403
    assert client.post("/admin/devices/d1/revoke", headers={"X-Admin-Key": "root"}).status_code == 200
    assert post(client, "d1", "secret-1", [reading(0)]).status_code == 403
    assert post(client, "d2", "secret-2", [reading(0)]).status_code == 200


@pytest.mark.parametrize("bad", [
    {"seq": -1, "ts": TS, "temp_c": 1},
    {"seq": 0, "ts": 1000, "temp_c": 1},
    {"seq": 0, "ts": TS, "temp_c": 900},
    {"seq": 0, "ts": TS, "temp_c": 1, "rssi": 5},
])
def test_invalid_values_are_refused(api, bad):
    client, _ = api
    assert post(client, "d1", "secret-1", [bad]).status_code == 422


def test_oversized_batch_is_refused(api):
    client, _ = api
    assert post(client, "d1", "secret-1", [reading(i) for i in range(501)]).status_code == 422


def test_customers_only_see_their_own_devices(api):
    client, _ = api
    post(client, "d1", "secret-1", [reading(0)])
    post(client, "d2", "secret-2", [reading(0)])
    assert client.get("/api/fleet").status_code == 401
    assert client.get("/api/fleet", headers=bearer("nope")).status_code == 401
    fleet = client.get("/api/fleet", headers=bearer("key-1")).json()
    assert [d["id"] for d in fleet["devices"]] == ["d1"]
    assert client.get("/api/devices/d2/series", headers=bearer("key-1")).status_code == 404
    assert client.get("/api/devices/d1/series", headers=bearer("key-1")).status_code == 200


def test_fleet_counts_gaps_duplicates_and_status(api):
    client, _ = api
    now = int(time.time())
    fresh = [{"seq": i, "ts": now - 60 + i, "temp_c": 20.0, "rssi": -60} for i in (0, 1, 3)]
    post(client, "d1", "secret-1", fresh)
    post(client, "d1", "secret-1", fresh[:1])
    device = client.get("/api/fleet", headers=bearer("key-1")).json()["devices"][0]
    assert (device["status"], device["stored"], device["duplicates_rejected"], device["gaps"]) == ("online", 3, 1, 1)
    assert device["rssi"] == -60


def test_demo_login_is_off_unless_explicitly_enabled(tmp_path):
    app = create_app(tmp_path / "t.db")
    app.state.store.add_customer("c1", "One", "key-1")
    assert TestClient(app, client=("127.0.0.1", 5000)).get("/api/fleet").status_code == 401
