import base64, json, hashlib, re

INTENTS = {"status", "ask", "answer", "event", "transfer"}

def validate_envelope(msg: dict) -> None:
    """Reject ambiguous delimiter fields and non-JSON content before signing."""
    if not isinstance(msg, dict) or msg.get("phi_version") != "0.1":
        raise ValueError("Unsupported Phi envelope")
    if set(msg) - {"phi_version", "from", "to", "intent", "content", "timestamp", "nonce", "signature"}:
        raise ValueError("Unsigned extension fields are not supported")
    for field in ("from", "to", "nonce"):
        if not isinstance(msg.get(field), str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", msg[field]):
            raise ValueError("Invalid " + field)
    if msg.get("intent") not in INTENTS:
        raise ValueError("Invalid intent")
    if not isinstance(msg.get("timestamp"), str) or "|" in msg["timestamp"]:
        raise ValueError("Invalid timestamp")
    if not isinstance(msg.get("content"), dict):
        raise ValueError("Content must be an object")

def sha256_bytes(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def canonical_bytes(msg: dict) -> bytes:
    """Bytes we sign: phi_version|from|to|intent|timestamp|nonce|SHA256(content)"""
    validate_envelope(msg)
    content_bytes = json.dumps(msg["content"], separators=(",", ":"), sort_keys=True, allow_nan=False).encode("utf-8")
    parts = [
        msg["phi_version"], msg["from"], msg["to"], msg["intent"],
        msg["timestamp"], msg["nonce"],
        base64.b64encode(sha256_bytes(content_bytes)).decode("utf-8")
    ]
    return "|".join(parts).encode("utf-8")
