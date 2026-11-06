"""Streaming robot agent for long-running capture (no ROS dependency).

Unlike `cursiv_sim.robot.RobotAgent`, which keeps every envelope in memory, this agent keeps a
constant amount of state: the chain head, the record count, a Merkle frontier and how far the
station has acknowledged (count and byte offset into the outbox). Signed records are appended
to `outbox.jsonl` and fsynced per batch. Attachments (raw message payloads) are written to
`blobs/` first and uploaded before the records that cite them, so nothing depends on the link
being up when a message arrives.

Restart-safe: on start the outbox is re-read once to rebuild the head and frontier; a torn final
line (power loss mid-write) is cut off, as the station does.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from cursiv_sim.client import LinkDown
from cursiv_sim.identity import CHECKPOINT_TYPE, RECORD_TYPE, Identity, payload_hash, sha256_hex


def utc_from_ns(ns: int) -> str:
    dt = datetime.fromtimestamp(ns / 1e9, timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def utc_now() -> str:
    return utc_from_ns(int(datetime.now(timezone.utc).timestamp() * 1e9))


class Frontier:
    """Incremental Merkle root, identical to crates/cursiv-evidence/src/merkle.rs::Frontier."""

    def __init__(self):
        self.stack: list[tuple[int, bytes]] = []
        self.count = 0

    def push(self, hash_hex: str) -> None:
        node, size = hashlib.sha256(b"\x00" + hash_hex.encode("ascii")).digest(), 1
        while self.stack and self.stack[-1][0] == size:
            _, left = self.stack.pop()
            node, size = hashlib.sha256(b"\x01" + left + node).digest(), size * 2
        self.stack.append((size, node))
        self.count += 1

    def root(self) -> str:
        if not self.stack:
            return hashlib.sha256(b"").hexdigest()
        acc = self.stack[-1][1]
        for _, h in reversed(self.stack[:-1]):
            acc = hashlib.sha256(b"\x01" + h + acc).digest()
        return acc.hex()


class StreamingAgent:
    def __init__(self, robot_id: str, state_dir: Path, client, *, mission_id: str):
        self.robot_id, self.mission_id, self.client = robot_id, mission_id, client
        self.dir = Path(state_dir) / robot_id
        (self.dir / "blobs").mkdir(parents=True, exist_ok=True)
        self.identity = Identity.load_or_create(self.dir / "robot.key")
        self.outbox = self.dir / "outbox.jsonl"
        self.head, self.count, self.frontier = "genesis", 0, Frontier()
        self.acked, self.acked_offset = 0, 0
        self.recovered: list[str] = []
        self._load()
        self._fh = open(self.outbox, "ab")
        self._pending_lines: list[bytes] = []
        self._lock = threading.RLock()   # the capture worker records while the sync thread sends

    # --- durable state -----------------------------------------------------
    def _load(self) -> None:
        good = 0
        if self.outbox.exists():
            with open(self.outbox, "rb") as f:
                for line in f:
                    if not line.endswith(b"\n"):
                        break
                    try:
                        env = json.loads(line)
                    except ValueError:
                        break
                    h = payload_hash(env)
                    self.head, self.count = h, self.count + 1
                    self.frontier.push(h)
                    good += len(line)
            if good != self.outbox.stat().st_size:
                with open(self.outbox, "r+b") as f:
                    f.truncate(good)
                self.recovered.append(f"outbox: removed an incomplete final line (interrupted write) after record {self.count}")
        ack = self.dir / "acked.json"
        if ack.exists():
            a = json.loads(ack.read_text())
            self.acked, self.acked_offset = min(a["count"], self.count), min(a["offset"], good)

    def _save_ack(self) -> None:
        tmp = self.dir / "acked.json.tmp"
        tmp.write_text(json.dumps({"count": self.acked, "offset": self.acked_offset}))
        os.replace(tmp, self.dir / "acked.json")

    # --- recording -----------------------------------------------------------
    def store_blob(self, data: bytes) -> str:
        """Keep an attachment locally until it is uploaded. Returns its SHA-256."""
        sha = sha256_hex(data)
        p = self.dir / "blobs" / sha
        if not p.exists():
            tmp = p.with_suffix(".tmp")
            tmp.write_bytes(data)
            os.replace(tmp, p)
        return sha

    def record(self, observation: dict, written_time: str | None = None) -> dict:
        """Sign a record and queue it for the next flush (call flush() to make it durable)."""
        with self._lock:
            rec = {"schema": "cursiv-record-1", "robot_id": self.robot_id, "seq": self.count + 1, "prev": self.head,
                   "written_time": written_time or utc_now(), "observation": observation}
            env = self.identity.sign(rec, RECORD_TYPE)
            h = payload_hash(env)
            self.head, self.count = h, self.count + 1
            self.frontier.push(h)
            self._pending_lines.append((json.dumps(env, separators=(",", ":")) + "\n").encode())
            return env

    def flush(self) -> None:
        """Write queued records with one fsync."""
        with self._lock:
            if self._pending_lines:
                self._fh.write(b"".join(self._pending_lines))
                self._fh.flush()
                os.fsync(self._fh.fileno())
                self._pending_lines.clear()

    def checkpoint(self) -> dict:
        with self._lock:
            return self._checkpoint()

    def _checkpoint(self) -> dict:
        return self.identity.sign({"schema": "cursiv-checkpoint-1", "robot_id": self.robot_id, "count": self.count,
                                   "head": self.head, "merkle_root": self.frontier.root(), "signed_time": utc_now()},
                                  CHECKPOINT_TYPE)

    def close(self) -> None:
        self.flush()
        self._fh.close()

    # --- synchronization -----------------------------------------------------
    def sync(self, batch: int = 500) -> dict:
        """Upload pending attachments, then send records from the station's head. Safe to repeat
        and safe while recording continues; returns {"link": "up" | "down" | "station_full", ...}."""
        # A consistent snapshot: everything up to `end` bytes / `count` records, and a checkpoint
        # for exactly that count (never one claiming records not yet sent).
        with self._lock:
            self.flush()
            end, count, cp = self.outbox.stat().st_size, self.count, self._checkpoint()
        try:
            for p in sorted((self.dir / "blobs").iterdir()):
                if p.suffix == ".tmp":
                    continue
                status, body = self.client.put_attachment(p.read_bytes(), p.name)
                if status not in (200, 201):
                    return {"link": "up", "error": f"attachment {p.name[:12]} rejected: {body}"}
                p.unlink()
            status, head, _ = self.client.get(f"/v1/robots/{self.robot_id}/head")
            have = head.get("count", 0)
            if have > count:
                raise RuntimeError(f"station has {have} records for {self.robot_id}, this agent {count}: local state was lost")
            sent, offset, n = 0, self.acked_offset, self.acked
            if have < self.acked:   # the station lost records (restored from a backup): resend from the start
                offset, n = 0, 0
            with open(self.outbox, "rb") as f:
                f.seek(offset)
                chunk, chunk_bytes = [], 0
                while offset + chunk_bytes < end:
                    line = f.readline()
                    if not line:
                        break
                    n += 1
                    if n <= have:
                        offset += len(line)
                        continue
                    chunk.append(line)
                    chunk_bytes += len(line)
                    if len(chunk) == batch:
                        r = self._send(chunk)
                        if r:
                            return r
                        sent, offset, chunk, chunk_bytes = sent + len(chunk), offset + chunk_bytes, [], 0
                        with self._lock:
                            self.acked, self.acked_offset = n, offset
                            self._save_ack()
                if chunk:
                    r = self._send(chunk)
                    if r:
                        return r
                    sent, offset = sent + len(chunk), offset + chunk_bytes
            with self._lock:
                self.acked, self.acked_offset = count, offset
                self._save_ack()
            self.client.post("/v1/checkpoints", cp)
            return {"link": "up", "sent": sent, "pending": self.count - count}
        except (LinkDown, ConnectionError, OSError) as e:
            return {"link": "down", "error": str(e), "pending": self.count - self.acked}

    def _send(self, chunk: list[bytes]) -> dict | None:
        # the stored lines are sent as they are: no decoding and re-encoding of every record
        status, data, _ = self.client.submit_lines(chunk)
        if status == 507:
            return {"link": "station_full", "pending": self.count - self.acked}
        for r in data.get("results", [data]):
            if r.get("status") == "rejected":
                # nothing is lost: the record stays in the outbox. Usually the robot key is not enrolled yet.
                return {"link": "rejected", "code": r.get("code"), "detail": r.get("detail"), "pending": self.count - self.acked}
        return None
