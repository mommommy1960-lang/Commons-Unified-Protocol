from datetime import datetime, timedelta, timezone
import pytest

from src.cup_policy import (
    NodePolicy, PolicyViolation, ReplayCache, authorize_message,
    require_multisig, sign_message,
)


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
KEY = b"k" * 32
POLICY = NodePolicy("node-a", frozenset({"0.1"}), frozenset({"status"}), KEY)


def message(**changes):
    base = {
        "phi_version": "0.1", "from": "node-a", "to": "node-b",
        "intent": "status", "timestamp": NOW.isoformat(),
        "nonce": "unique",
    }
    base.update(changes)
    base["signature"] = sign_message(base, KEY)
    return base


def test_authorized_message_consumes_nonce():
    cache = ReplayCache()
    authorize_message(message(), POLICY, cache, now=NOW, recipient="node-b")
    with pytest.raises(PolicyViolation):
        authorize_message(message(), POLICY, cache, now=NOW, recipient="node-b")


@pytest.mark.parametrize("changes", [
    {"intent": "admin"}, {"phi_version": "9"}, {"to": "node-c"},
    {"timestamp": (NOW - timedelta(minutes=6)).isoformat()},
])
def test_scope_version_recipient_and_expiry_fail_closed(changes):
    with pytest.raises(PolicyViolation):
        authorize_message(
            message(**changes), POLICY, ReplayCache(), now=NOW, recipient="node-b"
        )


def test_tampering_after_signature_is_denied():
    value = message()
    value["intent"] = "admin"
    with pytest.raises(PolicyViolation, match="intent|signature"):
        authorize_message(value, POLICY, ReplayCache(), now=NOW)


def test_wrong_key_and_blank_signature_are_denied():
    wrong = message()
    wrong["signature"] = sign_message(wrong, b"z" * 32)
    with pytest.raises(PolicyViolation, match="signature"):
        authorize_message(wrong, POLICY, ReplayCache(), now=NOW)
    blank = message()
    blank["signature"] = ""
    with pytest.raises(PolicyViolation, match="signature"):
        authorize_message(blank, POLICY, ReplayCache(), now=NOW)


def test_revoked_sender_is_denied():
    revoked = NodePolicy(
        "node-a", frozenset({"0.1"}), frozenset({"status"}), KEY, True
    )
    with pytest.raises(PolicyViolation):
        authorize_message(message(), revoked, ReplayCache(), now=NOW)


def test_multisig_requires_distinct_nonempty_approvers():
    require_multisig(["alice", "bob"])
    with pytest.raises(PolicyViolation):
        require_multisig(["alice", "alice", ""])
