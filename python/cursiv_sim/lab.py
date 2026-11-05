"""Run the real bridge binary against a throwaway store, enrol robots, export and verify.

Nothing here talks to the internet; the bridge binds loopback only.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from .client import BridgeClient
from .identity import Identity

REPO = Path(__file__).resolve().parents[2]
EXE = ".exe" if os.name == "nt" else ""


def binary(name: str) -> Path:
    for profile in ("release", "debug"):
        p = REPO / "target" / profile / f"{name}{EXE}"
        if p.exists():
            return p
    raise FileNotFoundError(f"{name} is not built: run `cargo build --release` in {REPO}")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Lab:
    def __init__(self, run_dir: Path, robot_ids: list[str], *, station_id: str = "station-alpha", queue: int = 256, workers: int = 4):
        self.dir = Path(run_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.station_id = station_id
        self.robot_ids = robot_ids
        self.queue, self.workers = queue, workers
        self.port = free_port()
        self.client = BridgeClient(f"http://127.0.0.1:{self.port}")
        self.proc: subprocess.Popen | None = None
        self.robot_state = self.dir / "robots"
        self.trust_path = self.dir / "trust.json"
        self.station_key = self.dir / "station.key"
        self.extra_args: list[str] = []        # e.g. ["--max-store-bytes", "200000"]

    def enrol(self) -> dict:
        """Operator step: generate keys and write the trust store out of band (never via the API)."""
        if not self.station_key.exists():
            out = subprocess.run([str(binary("cursiv-bridge")), "keygen", str(self.station_key)], check=True, capture_output=True, text=True)
            station = json.loads(out.stdout)
        else:
            station = json.loads(self.station_key.read_text())
        trust = {"format": "cursiv-trust-1", "robots": {},
                 "stations": {self.station_id: [{"key_id": station["key_id"], "public_key": station["public_key"], "status": "active",
                                                 "note": "simulation station", "valid_from_seq": None, "valid_until_seq": None}]}}
        if self.trust_path.exists():          # keep robots enrolled earlier (their past records must stay authentic)
            trust["robots"].update(json.loads(self.trust_path.read_text()).get("robots", {}))
        for rid in self.robot_ids:
            ident = Identity.load_or_create(self.robot_state / rid / "robot.key")
            keys = trust["robots"].get(rid, [])
            if not any(k["key_id"] == ident.key_id for k in keys):
                keys.append(ident.trusted_entry("enrolled by the lab harness"))
            trust["robots"][rid] = keys
        self.trust_path.write_text(json.dumps(trust, indent=2))
        return trust

    def start(self) -> None:
        self.proc = subprocess.Popen(
            [str(binary("cursiv-bridge")), "serve", "--store", str(self.dir / "store"), "--station-id", self.station_id,
             "--key", str(self.station_key), "--trust", str(self.trust_path), "--bind", f"127.0.0.1:{self.port}",
             "--queue", str(self.queue), "--workers", str(self.workers), *self.extra_args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(200):
            try:
                if self.client.get("/v1/health")[0] == 200:
                    return
            except ConnectionError:
                pass
            if self.proc.poll() is not None:
                raise RuntimeError("bridge exited: " + self.proc.stderr.read())
            time.sleep(0.05)
        raise RuntimeError("bridge did not start")

    def kill(self) -> None:
        """Hard stop (simulates a power cut at the station)."""
        if self.proc:
            self.proc.kill()
            self.proc.wait()
            self.proc = None

    def stop(self) -> None:
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None

    def export(self, name: str) -> Path:
        status, data, _ = self.client.post("/v1/exports", {"name": name})
        if status != 201:
            raise RuntimeError(f"export failed: {data}")
        return Path(data["path"])

    def verify(self, package: Path, *, trust: Path | None = None, report_md: Path | None = None) -> tuple[int, dict]:
        """The independent verifier (a separate program, no service involved)."""
        cmd = [str(binary("cursiv-verify")), "package", str(package), "--json", "--science"]
        if trust is not False:
            cmd += ["--trust", str(trust or self.trust_path)]
        if report_md:
            cmd += ["--report-md", str(report_md)]
        out = subprocess.run(cmd, capture_output=True, text=True)
        return out.returncode, json.loads(out.stdout)

    def copy_package(self, package: Path, name: str) -> Path:
        dest = self.dir / "tampered" / name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(package, dest)
        return dest


def python() -> str:
    return sys.executable
