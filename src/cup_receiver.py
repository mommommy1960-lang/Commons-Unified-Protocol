"""Local CUP/ATN inbox: current key + consent checks and durable replay rejection.

Accepting a message records it; it never executes its content. The registry and
policy are trusted local controller inputs, not assertions supplied by senders.
"""
import base64
from copy import deepcopy
from datetime import datetime, timezone
import json
import math
import sqlite3

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from src.cup_message import canonical_bytes


class MessageRejected(ValueError):
    pass


class Receiver:
    def __init__(self, node_id, allowed_nodes, authorize, database=":memory:",
                 max_age_seconds=300, future_skew_seconds=30, max_bytes=16384):
        if not callable(authorize):
            raise ValueError("An explicit current-consent policy is required")
        if not all(isinstance(v, (int, float)) and math.isfinite(v) and v >= 0
                   for v in (max_age_seconds, future_skew_seconds)):
            raise ValueError("Invalid time bounds")
        self.node_id, self.allowed_nodes, self.authorize = node_id, allowed_nodes, authorize
        self.max_age, self.future_skew, self.max_bytes = max_age_seconds, future_skew_seconds, max_bytes
        self.db = sqlite3.connect(database)
        self.db.execute("CREATE TABLE IF NOT EXISTS inbox (sender TEXT, nonce TEXT, envelope TEXT NOT NULL, PRIMARY KEY(sender, nonce))")
        self.db.commit()

    def close(self):
        self.db.close()

    def receive(self, message, *, now=None):
        try:
            # Work on one immutable snapshot even if the caller later edits its dict.
            encoded = json.dumps(message, sort_keys=True, allow_nan=False)
            if len(encoded.encode("utf-8")) > self.max_bytes:
                raise MessageRejected("message_too_large")
            msg = json.loads(encoded)
            signed = canonical_bytes(msg)
            timestamp = datetime.fromisoformat(msg["timestamp"].replace("Z", "+00:00"))
            current = now if now is not None else datetime.now(timezone.utc)
            if timestamp.utcoffset() is None or current.utcoffset() is None:
                raise MessageRejected("timezone_required")
        except MessageRejected:
            raise
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
            raise MessageRejected("malformed_message") from exc
        age = (current - timestamp).total_seconds()
        if age >= self.max_age or age < -self.future_skew:
            raise MessageRejected("stale_or_future_message")
        if msg["to"] != self.node_id:
            raise MessageRejected("wrong_recipient")
        entry = self.allowed_nodes.get(msg["from"])
        if not isinstance(entry, dict) or entry.get("revoked", False):
            raise MessageRejected("unknown_or_revoked_key")
        try:
            public = serialization.load_pem_public_key(entry["pubkey_pem"].encode())
            if not isinstance(public, Ed25519PublicKey):
                raise ValueError("Ed25519 key required")
            public.verify(base64.b64decode(msg["signature"], validate=True), signed)
        except Exception as exc:
            raise MessageRejected("invalid_signature") from exc
        try:
            # Policy must consult current grants. Its mutable copy cannot alter the stored envelope.
            permitted = self.authorize(deepcopy(msg)) is True
        except Exception as exc:
            raise MessageRejected("consent_unavailable") from exc
        if not permitted:
            raise MessageRejected("consent_denied")
        try:
            with self.db:
                self.db.execute("INSERT INTO inbox VALUES (?,?,?)", (msg["from"], msg["nonce"], encoded))
        except sqlite3.IntegrityError as exc:
            raise MessageRejected("replay") from exc
        return deepcopy(msg)
