from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

private = Ed25519PrivateKey.generate()
private_pem = private.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
public_pem = private.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
open("ozhex-license-private.pem", "wb").write(private_pem)
open("ozhex-license-public.pem", "wb").write(public_pem)
print("Generated ozhex-license-private.pem and ozhex-license-public.pem")
print("Store the private PEM only in GitHub Actions secret OZHEX_LICENSE_PRIVATE_KEY.")
print("Store the public PEM in OZHEX_LICENSE_PUBLIC_KEY and the application environment.")
