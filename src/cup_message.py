import base64, json, hashlib

def sha256_bytes(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def canonical_bytes(msg: dict) -> bytes:
    """Bytes we sign: phi_version|from|to|intent|timestamp|nonce|SHA256(content)"""
    content_bytes = json.dumps(msg["content"], separators=(",", ":"), sort_keys=True).encode("utf-8")
    parts = [
        msg["phi_version"], msg["from"], msg["to"], msg["intent"],
        msg["timestamp"], msg["nonce"],
        base64.b64encode(sha256_bytes(content_bytes)).decode("utf-8")
    ]
    return "|".join(parts).encode("utf-8")
