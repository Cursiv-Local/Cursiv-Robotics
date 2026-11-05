"""Python quick start (stable API v1): verify a package, convert it, import it into a workspace.

    cargo build --release
    python examples/python/quickstart.py

Uses the committed sample package (simulated buoy data, simulation keys only). Offline.
"""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))

import cursiv_robotics as cr  # noqa: E402

pkg = ROOT / "examples/sample-package/sample-buoy-1-package"
trust = ROOT / "examples/sample-package/trust.json"

v = cr.verify(pkg, trust)
print("status:", v.status, v.verdicts)
if not v.verified:
    sys.exit("not verified: do not use this evidence")

out = Path(tempfile.mkdtemp())
prov = cr.convert(pkg, "prov", trust, out=out / "prov.json")
sta = cr.convert(pkg, "sensorthings", trust, out=out / "sensorthings.json")
print("PROV entities:", len(prov["document"]["entity"]), "| SensorThings datastreams:", sum(len(t["Datastreams"]) for t in sta["Things"]))
print("not representable in PROV:", prov["losses"][0][:90], "...")

s = cr.import_package(pkg, out / "workspace", trust)
print("imported:", s["imported"], "| research summary:", s.get("summary"))

untrusted = cr.verify(pkg)            # no trust store: authenticity cannot be established
print("without a trust store:", untrusted.status)
import shutil  # noqa: E402

from cursiv_integration.layout import record_files  # noqa: E402

bad = out / "tampered" / pkg.name
shutil.copytree(pkg, bad)
f = record_files(bad, "buoy-02")[0]
f.write_bytes(f.read_bytes().replace(b"A", b"B", 1))   # one changed byte in a signed record
print("tampered copy:", cr.verify(bad, trust).status)
try:
    cr.convert(bad, "prov", trust)
except cr.NotVerified as e:
    print("conversion refused:", e)
