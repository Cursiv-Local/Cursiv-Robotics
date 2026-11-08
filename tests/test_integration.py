"""Cursiv integration contract: discovery, verification, import into a research workspace,
source immutability, refusal of tampered or untrusted evidence, and ingestion by Cursiv itself
(when the Cursiv repository is checked out beside this one)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from cursiv_integration import importer  # noqa: E402
from cursiv_sim import missions  # noqa: E402


@pytest.fixture(scope="module")
def mission(tmp_path_factory):
    cfg = json.loads((ROOT / "missions/buoy-baseline.json").read_text())
    cfg["duration_s"] = 1800                     # shorter for the test
    out = tmp_path_factory.mktemp("m") / cfg["mission_id"]
    missions.Mission(cfg, out).run()
    pkg = next((out / "store/exports").iterdir())
    return pkg, out / "trust.json"


def test_discovery_finds_packages_and_ignores_links(mission, tmp_path):
    pkg, _ = mission
    drive = tmp_path / "usb"
    (drive / "field/day1").mkdir(parents=True)
    shutil.copytree(pkg, drive / "field/day1" / pkg.name)
    (drive / "not-a-package").mkdir()
    if os.name != "nt":
        os.symlink(drive / "field", drive / "loop")
    found = importer.discover(drive)
    assert found == [drive / "field/day1" / pkg.name]


def test_import_builds_a_workspace_without_touching_the_source(mission, tmp_path):
    pkg, trust = mission
    before = importer.fingerprint(pkg)
    ws = tmp_path / "ws"
    s = importer.import_package(pkg, ws, trust)
    assert s["imported"] and s["area"] == "packages" and s["source_unchanged"] and s["contract_version"] == "1"
    assert importer.fingerprint(pkg) == before
    assert importer.fingerprint(ws / "packages" / pkg.name) == before, "an exact copy of the evidence"
    views = ws / "views" / pkg.name
    rows = (views / "observations.csv").read_text().splitlines()
    assert len(rows) - 1 == s["records"] and s["records"] == s["synthetic_records"]
    summary = (views / "research-summary.md").read_text()
    assert "SYNTHETIC DATA" in summary and "analysis-01/" in summary and "| integrity | pass |" in summary
    again = importer.import_package(pkg, ws, trust)
    assert "imported before" in again["reason"], "re-import changes nothing"
    assert len(json.loads((ws / "workspace.json").read_text())["packages"]) == 1


def test_tampered_or_untrusted_packages_are_not_imported(mission, tmp_path):
    pkg, trust = mission
    bad = tmp_path / "bad" / pkg.name
    shutil.copytree(pkg, bad)
    from cursiv_integration.layout import record_files, robots
    f = record_files(bad, next(r for r in robots(bad) if r.startswith("buoy-")))[0]
    f.write_text(f.read_text().replace("A", "B", 1))
    s = importer.import_package(bad, tmp_path / "ws", trust)
    assert not s["imported"] and "did not pass" in s["reason"]
    q = importer.import_package(bad, tmp_path / "ws", trust, quarantine=True)
    assert q["imported"] and q["area"] == "quarantine"
    assert "QUARANTINED" in Path(q["summary"]).read_text()
    other = json.loads(trust.read_text())
    for keys in other["robots"].values():
        for k in keys:
            k["status"] = "revoked"
    revoked = tmp_path / "revoked.json"
    revoked.write_text(json.dumps(other))
    r = importer.import_package(pkg, tmp_path / "ws2", revoked)
    assert not r["imported"], "authentic-looking but signed by revoked keys"
    n = importer.import_package(pkg, tmp_path / "ws3", None)
    assert n["imported"] and "Authenticity not assessed" in Path(n["summary"]).read_text()


def test_a_source_that_changes_during_import_is_not_imported(mission, tmp_path, monkeypatch):
    pkg, trust = mission
    src = tmp_path / "drive" / pkg.name
    shutil.copytree(pkg, src)
    real = importer.verify

    def verify_then_someone_writes(p, t, timeout=None, profile=None):
        out = real(p, t, timeout, profile)
        if Path(p) == src:
            (src / "bag-info.txt").write_text((src / "bag-info.txt").read_text() + "Note: written during import\n")
        return out
    monkeypatch.setattr(importer, "verify", verify_then_someone_writes)
    ws = tmp_path / "ws"
    s = importer.import_package(src, ws, trust)
    assert not s["imported"] and s["source_unchanged"] is False and "source changed during import" in s["reason"]
    assert not (ws / "packages" / pkg.name).exists() and not list((ws / "packages").glob(".importing-*")), "nothing is left behind"
    assert not (ws / "workspace.json").exists()


def test_a_copy_that_is_not_byte_identical_is_not_imported(mission, tmp_path, monkeypatch):
    pkg, trust = mission
    real = shutil.copytree

    def faulty_copy(a, b, *args, **kw):
        out = real(a, b, *args, **kw)
        if Path(b).name.startswith(".importing-"):    # the top-level copy (copytree recurses)
            (Path(b) / "data" / "extra.txt").write_text("a disk fault")
        return out
    monkeypatch.setattr(importer.shutil, "copytree", faulty_copy)
    s = importer.import_package(pkg, tmp_path / "ws", trust)
    assert not s["imported"] and "not byte-identical" in s["reason"]
    assert not list((tmp_path / "ws" / "packages").iterdir())


def test_missing_records_are_refused_and_caveats_are_stated(mission, tmp_path, monkeypatch):
    pkg, trust = mission
    real = importer.verify

    def records_missing(p, t, timeout=None, profile=None):
        code, rep = real(p, t, timeout, profile)
        rep["verification"]["verdicts"]["completeness"] = "fail"
        rep["verification"]["status"] = "failed"
        return 1, rep
    monkeypatch.setattr(importer, "verify", records_missing)
    s = importer.import_package(pkg, tmp_path / "ws", trust)
    assert not s["imported"] and "completeness" in s["reason"] and not s["fully_verified"]
    monkeypatch.setattr(importer, "verify", real)
    n = importer.import_package(pkg, tmp_path / "ws2", None)
    assert n["imported"] and not n["fully_verified"]
    assert any(c.startswith("authenticity not assessed") for c in n["caveats"])
    text = Path(n["summary"]).read_text()
    assert "NOT FULLY VERIFIED" in text and "Fully verified:" not in text


def test_a_clean_trusted_package_is_fully_verified(mission, tmp_path):
    pkg, trust = mission
    profile = trust.parent / "profile.json"   # the mission's own profile (simulated clock, no region)
    s = importer.import_package(pkg, tmp_path / "ws", trust, profile=profile)
    assert s["imported"] and s["verification_status"] == "verified"
    assert s["fully_verified"], s["caveats"]
    assert "Fully verified:" in Path(s["summary"]).read_text()


def test_a_verifier_that_does_not_finish_imports_nothing(mission, tmp_path, monkeypatch):
    pkg, trust = mission
    seen = {}

    def hangs(cmd, **kw):
        seen["timeout"] = kw.get("timeout")
        raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
    monkeypatch.setenv("CURSIV_VERIFY_TIMEOUT", "5")
    monkeypatch.setattr(importer.subprocess, "run", hangs)
    s = importer.import_package(pkg, tmp_path / "ws", trust)
    assert seen["timeout"] == 5.0 and not s["imported"] and "did not finish within 5 s" in s["reason"]
    assert not (tmp_path / "ws" / "packages").exists()


def test_unsupported_contract_version_is_refused(mission, tmp_path):
    pkg, trust = mission
    future = tmp_path / "future" / pkg.name
    shutil.copytree(pkg, future)
    info = future / "bag-info.txt"
    import re
    info.write_text(re.sub(r"Cursiv-Package-Version: \d+", "Cursiv-Package-Version: 9", info.read_text()))
    s = importer.import_package(future, tmp_path / "ws", trust)
    assert not s["imported"] and "not supported" in s["reason"]


@pytest.mark.skipif(not (ROOT.parent / "Cursiv/cursiv_engine").is_dir(), reason="Cursiv repository not checked out beside this one")
def test_cursiv_document_library_ingests_the_research_summary(mission, tmp_path):
    pkg, trust = mission
    s = importer.import_package(pkg, tmp_path / "ws", trust)
    home = tmp_path / "cursiv-home"
    code = ("import sys, json; from pathlib import Path; from cursiv_engine.core import documents; "
            "d = documents.add(Path(sys.argv[1])); hits = documents.search('mean dissolved oxygen', limit=1); "
            "print(json.dumps({'pages': d['pages'], 'hit': hits[0].text if hits else ''}))")
    out = subprocess.run([sys.executable, "-c", code, s["summary"]], cwd=ROOT.parent / "Cursiv", capture_output=True, text=True,
                         env={**os.environ, "HOME": str(home), "CURSIV_APP_DATA": str(home / "app"), "USERPROFILE": str(home)})
    assert out.returncode == 0, out.stderr[-500:]
    r = json.loads(out.stdout.strip().splitlines()[-1])
    assert r["pages"] >= 1 and "dissolved_oxygen_mean" in r["hit"]


def test_one_command_demo_passes(tmp_path):
    out = subprocess.run([sys.executable, str(ROOT / "python/cursiv_demo"), "--out", str(tmp_path / "demo")], capture_output=True, text=True, timeout=600)
    assert out.returncode == 0, out.stdout[-2000:] + out.stderr[-2000:]
    assert "tampering DETECTED" in out.stdout and "DEMO PASSED" in out.stdout
    assert "REFUSED" in out.stdout and "source unchanged: False" not in out.stdout
