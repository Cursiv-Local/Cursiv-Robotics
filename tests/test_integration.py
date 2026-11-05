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
    f = next((bad / "data/robots").glob("buoy-*/records.jsonl"))
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


def test_unsupported_contract_version_is_refused(mission, tmp_path):
    pkg, trust = mission
    future = tmp_path / "future" / pkg.name
    shutil.copytree(pkg, future)
    info = future / "bag-info.txt"
    info.write_text(info.read_text().replace("Cursiv-Package-Version: 1", "Cursiv-Package-Version: 9"))
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
