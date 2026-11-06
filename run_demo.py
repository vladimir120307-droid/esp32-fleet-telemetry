"""Starts the real server, pushes 24 simulated hours through it, then checks every reading."""
from __future__ import annotations

import asyncio
import json
import sqlite3
import sys
import threading
import time
from pathlib import Path

import uvicorn

ROOT = Path(__file__).parent
sys.path[:0] = [str(ROOT / "server"), str(ROOT / "simulator")]
from app import create_app  # noqa: E402
from device_sim import SimDevice, simulate  # noqa: E402

RESULTS = ROOT / "results"
DB = RESULTS / "demo.db"
PORT = 8099


def main(keep_running: bool) -> None:
    RESULTS.mkdir(exist_ok=True)
    for suffix in ("", "-wal", "-shm"):
        Path(str(DB) + suffix).unlink(missing_ok=True)
    app = create_app(DB, admin_key="demo-admin", demo_customer="cust-a")
    store = app.state.store
    store.add_customer("cust-a", "Customer A (demo data)", "demo-key-a")
    store.add_customer("cust-b", "Customer B (demo data)", "demo-key-b")

    now = int(time.time())
    minutes = 24 * 60
    start = now - minutes * 60
    devices = []
    for i in range(40):
        cid = "cust-a" if i < 28 else "cust-b"
        did = f"{'A' if i < 28 else 'B'}-{i:03d}"
        secret = f"demo-secret-{i}"
        store.add_device(did, cid, secret, f"Module {did}")
        stop = 190 if i in (9, 21) else 0  # two modules lost power about three hours ago
        devices.append(SimDevice(did, secret, start, minutes, seed=100 + i, stop_early_min=stop))

    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)

    result = asyncio.run(simulate(f"http://127.0.0.1:{PORT}", devices))
    store.revoke("A-014")

    db = sqlite3.connect(DB)
    stored = db.execute("SELECT COUNT(*) FROM readings").fetchone()[0]
    distinct = db.execute("SELECT COUNT(*) FROM (SELECT DISTINCT device_id, seq FROM readings)").fetchone()[0]
    duplicates = db.execute("SELECT SUM(duplicates) FROM devices").fetchone()[0]
    gaps = db.execute("SELECT SUM(m + 1 - c) FROM (SELECT MAX(seq) m, COUNT(*) c FROM readings GROUP BY device_id)").fetchone()[0]
    rollup_n = db.execute("SELECT SUM(n) FROM rollup_1m").fetchone()[0]
    db.close()
    result.update(readings_stored=stored, distinct_device_seq=distinct, duplicates_rejected=duplicates,
                  missing_readings=gaps, rollup_row_count_matches=rollup_n == stored)
    (RESULTS / "run.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    assert stored == result["readings_generated"], "lost readings"
    assert gaps == 0, "gaps"
    if keep_running:
        print(f"READY http://127.0.0.1:{PORT}/", flush=True)
        time.sleep(float(sys.argv[2]) if len(sys.argv) > 2 else 60)
    server.should_exit = True


if __name__ == "__main__":
    main("--serve" in sys.argv)
