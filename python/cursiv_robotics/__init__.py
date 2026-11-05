"""Cursiv Robotics Python API, version 1 (stable). See docs/API.md.

Stable (semantic versioning from API_VERSION 1.0):
    verify(package, trust=None, *, science=False) -> Verification
    convert(package, to, trust, *, out=None) -> dict           # "prov" | "sensorthings"
    discover(root) -> list[Path]                                 # packages on a drive or folder
    import_package(package, workspace, trust, *, quarantine=False) -> dict
    Status, Verification, CursivError, ToolNotFound, NotVerified

Experimental (may change in any release): `cursiv_robotics.experimental`
    StreamingAgent, CaptureConfig, CaptureCore (ROS 2 capture without ROS)
    export_mcap, import_mcap (needs `mcap`, `mcap-ros2-support`)
    ros2_run (needs rclpy)

The verifier itself is the Rust program `cursiv-verify`. This package calls it, so verification
results are identical from Rust, Python and the command line. Set CURSIV_VERIFY to its path if
it is not in target/release or on PATH.
"""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE.parent) not in sys.path:
    sys.path.insert(0, str(_HERE.parent))

from cursiv_integration import importer as _importer  # noqa: E402

API_VERSION = "1.0.0"
__all__ = ["API_VERSION", "Status", "Verification", "CursivError", "ToolNotFound", "NotVerified",
           "verify", "convert", "discover", "import_package"]


class CursivError(Exception):
    """Base class for errors from this API."""


class ToolNotFound(CursivError):
    """cursiv-verify is not built or not found (build with `cargo build --release` or set CURSIV_VERIFY)."""


class NotVerified(CursivError):
    """The evidence did not verify, so the requested operation was refused."""

    def __init__(self, status: str, detail: str = ""):
        super().__init__(f"evidence not verified (status {status}){': ' + detail if detail else ''}")
        self.status = status


class Status:
    """Overall verification outcome. Only VERIFIED may be treated as trusted evidence."""
    VERIFIED = "verified"      # every verdict passed
    FAILED = "failed"          # at least one verdict failed
    INCOMPLETE = "incomplete"  # nothing failed, but authenticity or completeness was not established


@dataclass
class Verification:
    status: str
    verdicts: dict
    exit_code: int
    report: dict = field(repr=False)          # the verifier's full JSON (verification, science, reasoning)

    @property
    def verified(self) -> bool:
        return self.status == Status.VERIFIED


def _tool() -> Path:
    try:
        return _importer._verify_bin()
    except FileNotFoundError as e:
        raise ToolNotFound(str(e)) from None


def verify(package, trust=None, *, science: bool = False) -> Verification:
    """Verify a package with the independent verifier. Never raises for bad evidence: a tampered
    package is a Verification with status FAILED. Raises ToolNotFound or CursivError for usage problems."""
    cmd = [str(_tool()), "package", str(package), "--json"]
    if trust:
        cmd += ["--trust", str(trust)]
    if science:
        cmd += ["--science"]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode == 2 or not p.stdout.strip():
        raise CursivError(p.stderr.strip() or "cursiv-verify failed")
    rep = json.loads(p.stdout)
    v = rep["verification"]
    return Verification(status=v.get("status", Status.FAILED), verdicts={k: x.split(":")[0] for k, x in v["verdicts"].items()},
                        exit_code=p.returncode, report=rep)


def convert(package, to: str, trust, *, out=None) -> dict:
    """W3C PROV-JSON ("prov") or OGC SensorThings data model ("sensorthings") from a VERIFIED package.
    Experimental mappings (see docs/INTEROPERABILITY.md for what each cannot represent)."""
    if to not in ("prov", "sensorthings"):
        raise CursivError("to must be 'prov' or 'sensorthings'")
    cmd = [str(_tool()), "convert", str(package), "--to", to, "--trust", str(trust)]
    if out:
        cmd += ["--out", str(out)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode == 1:
        import re
        m = re.search(r"status (\w+)", p.stderr)
        raise NotVerified(m.group(1) if m else "unknown", "conversion refused")
    if p.returncode != 0:
        raise CursivError(p.stderr.strip())
    return json.loads(Path(out).read_text()) if out else json.loads(p.stdout)


def discover(root) -> list[Path]:
    """Evidence packages under a folder or drive (no links followed)."""
    return _importer.discover(Path(root))


def import_package(package, workspace, trust, *, quarantine: bool = False) -> dict:
    """Verify, then copy into a research workspace (the source is never modified). See docs/CURSIV_INTEGRATION.md."""
    return _importer.import_package(Path(package), Path(workspace), Path(trust) if trust else None, quarantine=quarantine)
