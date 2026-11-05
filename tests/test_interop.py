"""Interoperability with independent, established tools (optional dependencies; skipped if absent).

    python -m pip install bagit securesystemslib
    python -m pytest tests/test_interop.py -q

- bagit (bagit-python, public domain): our evidence packages are valid RFC 8493 bags, and
  a changed file is caught by BagIt fixity without any Cursiv software.
- securesystemslib (MIT): our records are standard DSSE envelopes it can verify.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from cursiv_sim.lab import Lab  # noqa: E402
from cursiv_sim.robot import RobotAgent  # noqa: E402
from cursiv_sim.rovers import ROVERS  # noqa: E402
from cursiv_sim.world import Site  # noqa: E402


@pytest.fixture(scope="module")
def package(tmp_path_factory):
    d = tmp_path_factory.mktemp("interop")
    lab = Lab(d / "lab", list(ROVERS))
    lab.enrol()
    lab.start()
    site = Site(3)
    rovers = {rid: cls(RobotAgent(rid, lab.robot_state, lab.client, mission_id="interop"), site) for rid, cls in ROVERS.items()}
    for i in range(6):
        for r in rovers.values():
            r.step(i, 6)
    for r in rovers.values():
        r.agent.sync()
    pkg = lab.export("interop")
    yield lab, pkg
    lab.stop()


def test_package_is_a_valid_bagit_bag_and_tampering_breaks_fixity(package, tmp_path):
    bagit = pytest.importorskip("bagit")
    lab, pkg = package
    bag = bagit.Bag(str(pkg))
    bag.validate()                                  # raises BagValidationError if not valid
    assert bag.info["Bag-Software-Agent"].startswith("cursiv-evidence")
    import shutil
    copy = tmp_path / "bag"
    shutil.copytree(pkg, copy)
    f = copy / "data/robots/rover-01/records.jsonl"
    f.write_bytes(f.read_bytes().replace(b"A", b"B", 1))
    with pytest.raises(bagit.BagValidationError):
        bagit.Bag(str(copy)).validate()
    code, rep = lab.verify(copy)
    assert code == 1 and rep["verification"]["verdicts"]["integrity"] == "fail"


def test_records_are_standard_dsse_envelopes(package):
    pytest.importorskip("securesystemslib")
    from securesystemslib.dsse import Envelope
    from securesystemslib.signer import SSlibKey
    lab, pkg = package
    trust = json.loads(lab.trust_path.read_text())
    for rid in ROVERS:
        k = trust["robots"][rid][0]
        key = SSlibKey(keyid=k["key_id"], keytype="ed25519", scheme="ed25519",
                       keyval={"public": base64.b64decode(k["public_key"]).hex()})
        for line in (pkg / f"data/robots/{rid}/records.jsonl").read_text().splitlines():
            env = Envelope.from_dict(json.loads(line))
            assert list(env.verify([key], 1)) == [k["key_id"]]
    station = trust["stations"][lab.station_id][0]
    skey = SSlibKey(keyid=station["key_id"], keytype="ed25519", scheme="ed25519",
                    keyval={"public": base64.b64decode(station["public_key"]).hex()})
    Envelope.from_dict(json.loads((pkg / "manifest.json").read_text())).verify([skey], 1)
