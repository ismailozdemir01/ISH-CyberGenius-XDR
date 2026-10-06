from app.license_tokens import (
    customer_hash,
    sign_payload,
    sign_revocation_manifest,
    validate_payload,
    verify_revocation_manifest,
    verify_token,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def keypair():
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


def test_signed_token_round_trip():
    private, public = keypair()
    payload = {
        "v": 1,
        "license_id": "LIC-TEST",
        "product": "OZHEX-CyberGenius-XDR",
        "plan": "Professional",
        "customer": customer_hash("Buyer@example.com"),
        "issued_at": "2026-10-06T00:00:00Z",
        "expires_at": None,
        "max_activations": 2,
    }
    token = sign_payload(payload, private)
    assert verify_token(token, public)["license_id"] == "LIC-TEST"
    validate_payload(payload, "OZHEX-CyberGenius-XDR")


def test_tampered_token_is_rejected():
    private, public = keypair()
    token = sign_payload({"v": 1, "license_id": "LIC-TEST", "product": "OZHEX-CyberGenius-XDR", "max_activations": 1}, private)
    parts = token.split(".")
    parts[1] = parts[1][:-1] + ("A" if parts[1][-1] != "A" else "B")
    import pytest
    with pytest.raises(Exception):
        verify_token(".".join(parts), public)


def test_signed_revocation_manifest_round_trip():
    private, public = keypair()
    document = sign_revocation_manifest(["LIC-A", "LIC-B"], private)
    assert verify_revocation_manifest(document, public) == {"LIC-A", "LIC-B"}
