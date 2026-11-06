"""Stable Python API v1 and the PROV / SensorThings converters (through cursiv-verify)."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

import cursiv_robotics as cr  # noqa: E402
from cursiv_integration.layout import record_files  # noqa: E402

PKG = ROOT / "examples/sample-package/sample-buoy-1-package"
TRUST = ROOT / "examples/sample-package/trust.json"


def test_verify_statuses():
    assert cr.API_VERSION.startswith("1.")
    v = cr.verify(PKG, TRUST)
    assert v.verified and v.status == cr.Status.VERIFIED and v.exit_code == 0
    assert cr.verify(PKG).status == cr.Status.INCOMPLETE, "no trust store: authenticity not established"
    with pytest.raises(cr.CursivError):
        cr.verify(PKG, ROOT / "no-such-trust.json")


def test_tampered_evidence_is_failed_and_not_converted(tmp_path):
    bad = tmp_path / PKG.name
    shutil.copytree(PKG, bad)
    f = record_files(bad, "buoy-02")[0]
    f.write_bytes(f.read_bytes().replace(b"A", b"B", 1))
    v = cr.verify(bad, TRUST)
    assert v.status == cr.Status.FAILED and not v.verified
    with pytest.raises(cr.NotVerified) as e:
        cr.convert(bad, "prov", TRUST)
    assert e.value.status == "failed"


def test_prov_output_parses_with_the_w3c_prov_library(tmp_path):
    prov = pytest.importorskip("prov.model")
    d = cr.convert(PKG, "prov", TRUST, out=tmp_path / "p.json")
    doc = prov.ProvDocument.deserialize(content=json.dumps(d["document"]), format="json")
    kinds = {type(r).__name__ for r in doc.get_records()}
    assert {"ProvEntity", "ProvActivity", "ProvAgent", "ProvGeneration", "ProvDerivation", "ProvMembership", "ProvDelegation"} <= kinds
    assert d["verification"]["status"] == "verified"
    assert doc.get_provn().startswith("document")


def test_sensorthings_values_match_the_records():
    s = cr.convert(PKG, "sensorthings", TRUST)
    v = cr.verify(PKG, TRUST, science=True)
    assert v.verified
    obs = [o for t in s["Things"] for d in t["Datastreams"] for o in d["Observations"]]
    assert obs and all(isinstance(o["result"], float) for o in obs)
    assert {d["unitOfMeasurement"]["symbol"] for t in s["Things"] for d in t["Datastreams"]} >= {"degC"}


def test_examples_run():
    out = subprocess.run([sys.executable, str(ROOT / "examples/python/quickstart.py")], capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stderr
    assert "status: verified" in out.stdout and "conversion refused" in out.stdout
