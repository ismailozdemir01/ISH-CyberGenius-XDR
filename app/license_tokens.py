from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


TOKEN_PREFIX = "OZHX1"
REVOCATION_PREFIX = "OZHX-REV1"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def customer_hash(email: str) -> str:
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()


def license_id() -> str:
    import secrets
    return "LIC-" + secrets.token_hex(12).upper()


def load_private_key(value: str) -> Ed25519PrivateKey:
    raw = value.strip()
    if "BEGIN PRIVATE KEY" in raw:
        key = serialization.load_pem_private_key(raw.encode(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("OZHEX license private key is not Ed25519")
        return key
    return Ed25519PrivateKey.from_private_bytes(_unb64(raw))


def load_public_key(value: str) -> Ed25519PublicKey:
    raw = value.strip()
    if "BEGIN PUBLIC KEY" in raw:
        key = serialization.load_pem_public_key(raw.encode())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("OZHEX license public key is not Ed25519")
        return key
    return Ed25519PublicKey.from_public_bytes(_unb64(raw))


def sign_payload(payload: dict[str, Any], private_key: str) -> str:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = load_private_key(private_key).sign(body)
    return f"{TOKEN_PREFIX}.{_b64(body)}.{_b64(signature)}"


def verify_token(token: str, public_key: str) -> dict[str, Any]:
    parts = token.strip().split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        raise ValueError("Invalid OZHEX license token format")
    body = _unb64(parts[1])
    signature = _unb64(parts[2])
    load_public_key(public_key).verify(signature, body)
    payload = json.loads(body)
    if not isinstance(payload, dict):
        raise ValueError("Invalid OZHEX license payload")
    if payload.get("v") != 1 or not payload.get("license_id"):
        raise ValueError("Unsupported or incomplete OZHEX license")
    return payload


def sign_revocation_manifest(revoked: list[str], private_key: str) -> str:
    payload = {
        "v": 1,
        "updated_at": iso(utcnow()),
        "revoked": sorted(set(str(x).strip() for x in revoked if str(x).strip())),
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = load_private_key(private_key).sign(body)
    return f"{REVOCATION_PREFIX}.{_b64(body)}.{_b64(signature)}"


def verify_revocation_manifest(document: str, public_key: str) -> set[str]:
    parts = document.strip().split(".")
    if len(parts) != 3 or parts[0] != REVOCATION_PREFIX:
        raise ValueError("Invalid OZHEX revocation manifest format")
    body = _unb64(parts[1])
    signature = _unb64(parts[2])
    load_public_key(public_key).verify(signature, body)
    payload = json.loads(body)
    if payload.get("v") != 1:
        raise ValueError("Unsupported revocation manifest")
    revoked = payload.get("revoked", [])
    if not isinstance(revoked, list):
        raise ValueError("Invalid revocation list")
    return {str(x) for x in revoked}


def validate_payload(payload: dict[str, Any], product: str) -> None:
    if payload.get("product") != product:
        raise ValueError("License product mismatch")
    expires_at = payload.get("expires_at")
    if expires_at and datetime.fromisoformat(str(expires_at).replace("Z", "+00:00")) <= utcnow():
        raise ValueError("License expired")
    if int(payload.get("max_activations", 0)) < 1:
        raise ValueError("License has no activation capacity")
