"""Device ingest API, customer API and dashboard for a fleet of ESP32 modules on customer WiFi.

Devices sign every upload with their own key. A resend never creates a duplicate row,
because (device_id, seq) is unique. Customers only ever see their own devices.
SQLite keeps the demo self-contained. The schema uses standard SQL and maps directly to MySQL.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, ValidationError

REPLAY_WINDOW_S = 300
MAX_BODY_BYTES = 256 * 1024
MIN_VALID_TS = 1_577_836_800  # 2020-01-01, rejects devices that have not synced their clock
ONLINE_WITHIN_S = 15 * 60

SCHEMA = """
CREATE TABLE IF NOT EXISTS customers (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, api_key_sha256 TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id), label TEXT,
    secret TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, firmware TEXT,
    last_ts INTEGER, last_rssi INTEGER, contiguous_seq INTEGER NOT NULL DEFAULT -1,
    accepted INTEGER NOT NULL DEFAULT 0, duplicates INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS readings (
    device_id TEXT NOT NULL REFERENCES devices(id), seq INTEGER NOT NULL, ts INTEGER NOT NULL,
    temp_c REAL NOT NULL, humidity REAL, rssi INTEGER,
    PRIMARY KEY (device_id, seq));
CREATE TABLE IF NOT EXISTS rollup_1m (
    device_id TEXT NOT NULL, bucket INTEGER NOT NULL, n INTEGER NOT NULL, temp_sum REAL NOT NULL,
    temp_min REAL NOT NULL, temp_max REAL NOT NULL,
    PRIMARY KEY (device_id, bucket));
"""


def sign(secret: str, device_id: str, timestamp: str, body: bytes) -> str:
    message = f"{device_id}.{timestamp}.".encode() + hashlib.sha256(body).hexdigest().encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


class Reading(BaseModel):
    seq: int = Field(ge=0)
    ts: int = Field(ge=MIN_VALID_TS)
    temp_c: float = Field(ge=-60, le=150)
    humidity: float | None = Field(default=None, ge=0, le=100)
    rssi: int | None = Field(default=None, ge=-120, le=0)


class Batch(BaseModel):
    firmware: str | None = None
    readings: list[Reading] = Field(max_length=500)


class Store:
    def __init__(self, path: str | Path):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(SCHEMA)
        self.lock = threading.Lock()

    def add_customer(self, cid: str, name: str, api_key: str) -> None:
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO customers VALUES (?,?,?)",
                            (cid, name, hashlib.sha256(api_key.encode()).hexdigest()))

    def add_device(self, did: str, cid: str, secret: str, label: str | None = None) -> None:
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO devices (id, customer_id, secret, label) VALUES (?,?,?,?)",
                            (did, cid, secret, label or did))

    def revoke(self, did: str) -> None:
        with self.lock, self.db:
            self.db.execute("UPDATE devices SET revoked=1 WHERE id=?", (did,))

    def device(self, did: str):
        return self.db.execute("SELECT * FROM devices WHERE id=?", (did,)).fetchone()

    def customer_by_key(self, api_key: str):
        digest = hashlib.sha256(api_key.encode()).hexdigest()
        return self.db.execute("SELECT * FROM customers WHERE api_key_sha256=?", (digest,)).fetchone()

    def ingest(self, did: str, batch: Batch) -> dict:
        accepted = duplicates = 0
        with self.lock, self.db:
            for r in batch.readings:
                cur = self.db.execute(
                    "INSERT OR IGNORE INTO readings (device_id, seq, ts, temp_c, humidity, rssi) VALUES (?,?,?,?,?,?)",
                    (did, r.seq, r.ts, r.temp_c, r.humidity, r.rssi))
                if cur.rowcount != 1:
                    duplicates += 1
                    continue
                accepted += 1
                # Rollups only move for rows that were really new, so a resend cannot skew a chart.
                self.db.execute(
                    "INSERT INTO rollup_1m VALUES (?,?,1,?,?,?) ON CONFLICT(device_id, bucket) DO UPDATE SET"
                    " n=n+1, temp_sum=temp_sum+excluded.temp_sum,"
                    " temp_min=MIN(temp_min, excluded.temp_min), temp_max=MAX(temp_max, excluded.temp_max)",
                    (did, r.ts - r.ts % 60, r.temp_c, r.temp_c, r.temp_c))
            row = self.db.execute("SELECT contiguous_seq FROM devices WHERE id=?", (did,)).fetchone()
            ack = row[0]
            while self.db.execute("SELECT 1 FROM readings WHERE device_id=? AND seq=?", (did, ack + 1)).fetchone():
                ack += 1
            newest = max(batch.readings, key=lambda r: r.ts, default=None)
            self.db.execute(
                "UPDATE devices SET contiguous_seq=?, accepted=accepted+?, duplicates=duplicates+?,"
                " firmware=COALESCE(?, firmware),"
                " last_ts=MAX(COALESCE(last_ts,0), ?), last_rssi=COALESCE(?, last_rssi) WHERE id=?",
                (ack, accepted, duplicates, batch.firmware, newest.ts if newest else 0,
                 newest.rssi if newest else None, did))
        return {"accepted": accepted, "duplicates": duplicates, "ack_seq": ack}

    def fleet(self, cid: str, now: int) -> dict:
        rows = self.db.execute(
            "SELECT d.*, (SELECT COUNT(*) FROM readings r WHERE r.device_id=d.id) AS stored,"
            " (SELECT MAX(seq) FROM readings r WHERE r.device_id=d.id) AS max_seq"
            " FROM devices d WHERE d.customer_id=? ORDER BY d.id", (cid,)).fetchall()
        devices = []
        for d in rows:
            status = "revoked" if d["revoked"] else (
                "online" if d["last_ts"] and now - d["last_ts"] < ONLINE_WITHIN_S else "offline")
            devices.append({
                "id": d["id"], "label": d["label"], "status": status, "firmware": d["firmware"],
                "last_ts": d["last_ts"], "rssi": d["last_rssi"], "stored": d["stored"],
                "duplicates_rejected": d["duplicates"],
                "gaps": (d["max_seq"] + 1 - d["stored"]) if d["max_seq"] is not None else 0,
            })
        return {
            "devices": devices,
            "summary": {
                "devices": len(devices),
                "online": sum(x["status"] == "online" for x in devices),
                "readings": sum(x["stored"] for x in devices),
                "duplicates_rejected": sum(x["duplicates_rejected"] for x in devices),
                "gaps": sum(x["gaps"] for x in devices),
            },
        }

    def series(self, did: str, hours: int, now: int, points: int = 240) -> list[dict]:
        since = now - hours * 3600
        step = max(60, (hours * 3600 // points) // 60 * 60)
        rows = self.db.execute(
            "SELECT bucket - bucket % ? AS t, SUM(temp_sum)/SUM(n) AS avg, MIN(temp_min) AS lo, MAX(temp_max) AS hi"
            " FROM rollup_1m WHERE device_id=? AND bucket>=? GROUP BY t ORDER BY t", (step, did, since)).fetchall()
        return [dict(r) for r in rows]


def create_app(db_path: str | Path = ":memory:", admin_key: str | None = None, demo_customer: str | None = None) -> FastAPI:
    app = FastAPI(title="Fleet telemetry", docs_url=None, redoc_url=None)
    store = Store(db_path)
    app.state.store = store

    async def signed_device(request: Request, x_device_id: str = Header(), x_timestamp: str = Header(),
                            x_signature: str = Header()):
        body = await request.body()
        if len(body) > MAX_BODY_BYTES:
            raise HTTPException(413, "batch too large")
        device = store.device(x_device_id)
        # The same answer for an unknown device and a wrong signature gives nothing away.
        if device is None or not hmac.compare_digest(sign(device["secret"], x_device_id, x_timestamp, body), x_signature):
            raise HTTPException(401, "bad signature")
        try:
            sent_at = int(x_timestamp)
        except ValueError:
            raise HTTPException(401, "bad signature")
        if abs(time.time() - sent_at) > REPLAY_WINDOW_S:
            raise HTTPException(401, "stale request")
        if device["revoked"]:
            raise HTTPException(403, "device revoked")
        return device

    def customer(request: Request, authorization: str | None = Header(default=None)):
        if authorization and authorization.startswith("Bearer "):
            found = store.customer_by_key(authorization[7:])
            if found:
                return found
        # Used only to take screenshots of a local demo. Off unless explicitly set at start.
        if demo_customer and request.client and request.client.host == "127.0.0.1":
            found = store.db.execute("SELECT * FROM customers WHERE id=?", (demo_customer,)).fetchone()
            if found:
                return found
        raise HTTPException(401, "API key required")

    @app.post("/v1/ingest")
    async def ingest(request: Request, device=Depends(signed_device)):
        try:
            batch = Batch.model_validate_json(await request.body())
        except ValidationError as exc:
            raise HTTPException(422, json.loads(exc.json(include_url=False, include_context=False))) from None
        return store.ingest(device["id"], batch)

    @app.get("/api/fleet")
    def fleet(cust=Depends(customer)):
        return {"customer": cust["name"], **store.fleet(cust["id"], int(time.time()))}

    @app.get("/api/devices/{device_id}/series")
    def series(device_id: str, hours: int = 24, cust=Depends(customer)):
        device = store.device(device_id)
        if device is None or device["customer_id"] != cust["id"]:
            raise HTTPException(404, "device not found")  # never reveals another customer's device
        return {"device": device_id, "points": store.series(device_id, min(hours, 24 * 31), int(time.time()))}

    @app.post("/admin/devices/{device_id}/revoke")
    def revoke(device_id: str, x_admin_key: str = Header()):
        if not admin_key or not hmac.compare_digest(x_admin_key, admin_key):
            raise HTTPException(403, "forbidden")
        if store.device(device_id) is None:
            raise HTTPException(404, "device not found")
        store.revoke(device_id)
        return {"revoked": device_id}

    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        return (Path(__file__).parent / "dashboard.html").read_text(encoding="utf-8")

    return app


def app_from_env() -> FastAPI:
    return create_app(os.environ.get("TELEMETRY_DB", "telemetry.db"), os.environ.get("TELEMETRY_ADMIN_KEY"),
                      os.environ.get("TELEMETRY_DEMO_CUSTOMER"))
