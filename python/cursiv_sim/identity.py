"""Robot identities: one Ed25519 key per robot, in the same key-file format the Rust
service uses (``cursiv-robotics-key-1``), and DSSE envelopes (secure-systems-lab/dsse,
Apache-2.0; the envelope in-toto and Sigstore use) over the exact payload bytes.

Key ids follow Cursiv's ``core/devicekey.py``: first 16 hex chars of SHA-256(raw public key).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def canonical(obj) -> str:
    """Compact, key-sorted JSON. Any stable form works: signatures cover the exact text sent."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Identity:
    def __init__(self, private: Ed25519PrivateKey):
        self._key = private
        raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public_key = _b64(raw)
        self.key_id = hashlib.sha256(raw).hexdigest()[:16]

    @classmethod
    def generate(cls) -> "Identity":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> "Identity":
        """Deterministic key for SIMULATION ONLY (reproducible missions). Never use for real data."""
        return cls(Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed).digest()))

    @classmethod
    def load_or_create(cls, path: Path) -> "Identity":
        path = Path(path)
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("format") != "cursiv-robotics-key-1":
                raise ValueError(f"{path} is not a cursiv-robotics key file")
            ident = cls(Ed25519PrivateKey.from_private_bytes(base64.b64decode(data["seed_b64"])))
            if ident.key_id != data.get("key_id"):
                raise ValueError(f"{path}: key_id does not match the key")
            return ident
        ident = cls.generate()
        ident.save(path)
        return ident

    def save(self, path: Path) -> None:
        seed = self._key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                       serialization.NoEncryption())
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp")   # never collides with a crashed writer's leftover
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"format": "cursiv-robotics-key-1", "key_id": self.key_id,
                       "public_key": self.public_key, "seed_b64": _b64(seed)}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def sign_payload(self, payload_type: str, body: str) -> dict:
        raw = body.encode("utf-8")
        return {"payload": _b64(raw), "payloadType": payload_type,
                "signatures": [{"keyid": self.key_id, "sig": _b64(self._key.sign(pae(payload_type, raw)))}]}

    def sign(self, obj, payload_type: str) -> dict:
        return self.sign_payload(payload_type, canonical(obj))

    def trusted_entry(self, note: str = "") -> dict:
        return {"key_id": self.key_id, "public_key": self.public_key, "status": "active", "note": note or None,
                "valid_from_seq": None, "valid_until_seq": None}


RECORD_TYPE = "application/vnd.cursiv.record.v1+json"
CHECKPOINT_TYPE = "application/vnd.cursiv.checkpoint.v1+json"
MANIFEST_TYPE = "application/vnd.cursiv.package-manifest.v1+json"


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE pre-authentication encoding: "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body."""
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def body(envelope: dict) -> bytes:
    return base64.b64decode(envelope["payload"])


def body_json(envelope: dict):
    return json.loads(body(envelope))


def with_body(envelope: dict, obj) -> dict:
    """The same envelope (same signatures) with a different body: a forgery, for fault tests."""
    return dict(envelope, payload=_b64(canonical(obj).encode("utf-8")))


def payload_hash(envelope: dict) -> str:
    return sha256_hex(body(envelope))


def merkle_root(hashes: list[str]) -> str:
    """Same tree as crates/cursiv-evidence/src/merkle.rs (RFC 6962 style)."""
    def leaf(h: str) -> bytes:
        return hashlib.sha256(b"\x00" + h.encode("ascii")).digest()

    def root(leaves: list[bytes]) -> bytes:
        if not leaves:
            return hashlib.sha256(b"").digest()
        if len(leaves) == 1:
            return leaves[0]
        k = 1
        while k * 2 < len(leaves):
            k *= 2
        return hashlib.sha256(b"\x01" + root(leaves[:k]) + root(leaves[k:])).digest()

    return root([leaf(h) for h in hashes]).hex()
