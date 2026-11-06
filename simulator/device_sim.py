"""Simulated fleet: real HTTP against the real server, with the failures customer WiFi produces.

Each device behaves like the firmware: it buffers locally, uploads batches, and only drops a
reading from its buffer after the server's ack passes that sequence number. Outages stop
uploads for a while. Lost answers mean the server stored the batch but the device never heard
back, so it sends the same batch again.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import math
import random
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server"))
from app import sign  # noqa: E402


class SimDevice:
    def __init__(self, did: str, secret: str, start_ts: int, minutes: int, seed: int, stop_early_min: int = 0):
        self.did, self.secret, self.start_ts, self.minutes = did, secret, start_ts, minutes
        self.rng = random.Random(seed)
        self.stop_at = minutes - stop_early_min
        self.base = self.rng.uniform(4.0, 22.0)
        self.phase = self.rng.uniform(0, 2 * math.pi)
        self.buffer: list[dict] = []
        self.generated = 0
        self.lost_answers = self.outage_minutes = self.requests = 0
        self.latencies: list[float] = []
        outages = self.rng.randint(1, 4)
        self.outages = [(s := self.rng.randint(0, minutes - 1), s + self.rng.randint(5, 150)) for _ in range(outages)]

    def offline(self, minute: int) -> bool:
        return any(a <= minute < b for a, b in self.outages)

    def sample(self, minute: int) -> dict:
        ts = self.start_ts + minute * 60
        temp = self.base + 3.2 * math.sin(2 * math.pi * minute / 1440 + self.phase) + self.rng.gauss(0, 0.12)
        return {"seq": self.generated, "ts": ts, "temp_c": round(temp, 2),
                "humidity": round(self.rng.uniform(38, 62), 1), "rssi": self.rng.randint(-82, -48)}

    async def upload(self, client: httpx.AsyncClient, batch_size: int, lost_answer_rate: float) -> None:
        while self.buffer:
            batch = self.buffer[:batch_size]
            body = json.dumps({"firmware": "1.4.2", "readings": batch}).encode()
            ts = str(int(time.time()))
            headers = {"X-Device-Id": self.did, "X-Timestamp": ts, "X-Signature": sign(self.secret, self.did, ts, body),
                       "Content-Type": "application/json"}
            started = time.perf_counter()
            r = await client.post("/v1/ingest", content=body, headers=headers)
            self.latencies.append((time.perf_counter() - started) * 1000)
            self.requests += 1
            r.raise_for_status()
            if self.rng.random() < lost_answer_rate:
                self.lost_answers += 1  # stored on the server, but the device never hears back
                continue
            ack = r.json()["ack_seq"]
            self.buffer = [x for x in self.buffer if x["seq"] > ack]

    async def run(self, client: httpx.AsyncClient, batch_size: int, lost_answer_rate: float) -> None:
        for minute in range(self.minutes):
            if minute >= self.stop_at:
                return
            self.buffer.append(self.sample(minute))
            self.generated += 1
            if self.offline(minute):
                self.outage_minutes += 1
            elif len(self.buffer) >= batch_size or minute == self.stop_at - 1:
                await self.upload(client, batch_size, lost_answer_rate)
            if minute % 40 == 0:
                await asyncio.sleep(0)
        if self.buffer:  # the last minutes of the run fell inside an outage that has now ended
            await self.upload(client, batch_size, lost_answer_rate)


async def simulate(base_url: str, devices: list[SimDevice], batch_size=5, lost_answer_rate=0.03, concurrency=16) -> dict:
    sem = asyncio.Semaphore(concurrency)

    async def one(device, client):
        async with sem:
            await device.run(client, batch_size, lost_answer_rate)

    started = time.perf_counter()
    limits = httpx.Limits(max_connections=concurrency)
    async with httpx.AsyncClient(base_url=base_url, limits=limits, timeout=30) as client:
        await asyncio.gather(*(one(d, client) for d in devices))
    wall = time.perf_counter() - started
    lat = sorted(x for d in devices for x in d.latencies)
    return {
        "devices": len(devices),
        "readings_generated": sum(d.generated for d in devices),
        "http_requests": sum(d.requests for d in devices),
        "lost_answers_simulated": sum(d.lost_answers for d in devices),
        "device_minutes_offline": sum(d.outage_minutes for d in devices),
        "wall_seconds": round(wall, 1),
        "readings_per_second": round(sum(d.generated for d in devices) / wall),
        "ingest_ms_p50": round(lat[len(lat) // 2], 1),
        "ingest_ms_p95": round(lat[int(len(lat) * 0.95)], 1),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8099")
    ap.add_argument("--fleet", required=True, help="fleet.json written by run_demo.py")
    args = ap.parse_args()
    fleet = json.loads(Path(args.fleet).read_text())
    devices = [SimDevice(**d) for d in fleet]
    print(json.dumps(asyncio.run(simulate(args.url, devices)), indent=2))


if __name__ == "__main__":
    main()
