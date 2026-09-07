from datetime import datetime, timedelta, timezone
import pytest

from src.cup_policy import NodePolicy, PolicyViolation, ReplayCache, authorize_message


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
POLICY = NodePolicy("node-a", frozenset({"0.1"}), frozenset({"status"}))


def message(**changes):
    base = {
        "phi_version": "0.1", "from": "node-a", "to": "node-b",
        "intent": "status", "timestamp": NOW.isoformat(),
        "nonce": "unique", "signature": "present",
    }
    base.update(changes)
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
        authorize_message(**{"message": message(**changes), "policy": POLICY,
            "replay_cache": ReplayCache(), "now": NOW, "recipient": "node-b"})


def test_revoked_sender_is_denied():
    revoked = NodePolicy("node-a", frozenset({"0.1"}), frozenset({"status"}), True)
    with pytest.raises(PolicyViolation):
        authorize_message(message(), revoked, ReplayCache(), now=NOW)
