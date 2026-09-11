"""Fail-closed policy enforcement for CUP messages."""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable


class PolicyViolation(ValueError):
    pass


@dataclass
class ReplayCache:
    seen: set[tuple[str, str]] = field(default_factory=set)

    def consume(self, sender: str, nonce: str) -> None:
        key = (sender, nonce)
        if not nonce or key in self.seen:
            raise PolicyViolation("missing or replayed nonce")
        self.seen.add(key)


@dataclass(frozen=True)
class NodePolicy:
    node_id: str
    allowed_versions: frozenset[str]
    allowed_intents: frozenset[str]
    signing_key: bytes
    revoked: bool = False

    def __post_init__(self) -> None:
        if len(self.signing_key) < 32:
            raise PolicyViolation("signing key must contain at least 32 bytes")


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise PolicyViolation("invalid timestamp") from exc
    if parsed.tzinfo is None:
        raise PolicyViolation("timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def _authenticated_bytes(message: dict) -> bytes:
    authenticated = {key: value for key, value in message.items() if key != "signature"}
    try:
        return json.dumps(
            authenticated, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PolicyViolation("message is not canonically serializable") from exc


def sign_message(message: dict, signing_key: bytes) -> str:
    if len(signing_key) < 32:
        raise PolicyViolation("signing key must contain at least 32 bytes")
    return hmac.new(signing_key, _authenticated_bytes(message), hashlib.sha256).hexdigest()


def authorize_message(
    message: dict,
    policy: NodePolicy,
    replay_cache: ReplayCache,
    *,
    now: datetime | None = None,
    max_age_seconds: int = 300,
    recipient: str | None = None,
) -> None:
    """Raise PolicyViolation unless every authorization condition passes."""
    required = {"phi_version", "from", "to", "intent", "timestamp", "nonce", "signature"}
    if not required.issubset(message):
        raise PolicyViolation("missing required message field")
    if policy.revoked:
        raise PolicyViolation("sender key is revoked")
    if message["from"] != policy.node_id:
        raise PolicyViolation("sender does not match policy")
    if message["phi_version"] not in policy.allowed_versions:
        raise PolicyViolation("unsupported protocol version")
    if message["intent"] not in policy.allowed_intents:
        raise PolicyViolation("intent is outside sender scope")
    if recipient is not None and message["to"] != recipient:
        raise PolicyViolation("wrong recipient")
    supplied_signature = message.get("signature")
    if not isinstance(supplied_signature, str):
        raise PolicyViolation("invalid message signature")
    expected_signature = sign_message(message, policy.signing_key)
    if not hmac.compare_digest(supplied_signature, expected_signature):
        raise PolicyViolation("invalid message signature")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    age = (current - _parse_utc(message["timestamp"])).total_seconds()
    if age < -30 or age > max_age_seconds:
        raise PolicyViolation("message is not fresh")
    replay_cache.consume(message["from"], message["nonce"])


def require_multisig(approvers: Iterable[str], required: int = 2) -> None:
    identities = {item for item in approvers if item}
    if len(identities) < required:
        raise PolicyViolation("insufficient independent approvals")
