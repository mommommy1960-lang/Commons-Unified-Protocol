from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from pathlib import Path

Path("keys").mkdir(exist_ok=True)

priv = Ed25519PrivateKey.generate()
pub = priv.public_key()

priv_bytes = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
pub_bytes = pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

Path("keys/node_private.pem").write_bytes(priv_bytes)
Path("keys/node_public.pem").write_bytes(pub_bytes)

print("Wrote keys/node_private.pem and keys/node_public.pem")
