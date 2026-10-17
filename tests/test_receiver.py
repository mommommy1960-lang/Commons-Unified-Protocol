import base64
from datetime import datetime, timedelta, timezone
import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from src.cup_node import sign
from src.cup_receiver import MessageRejected, Receiver


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.registry = {"alice": {"pubkey_pem": self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()}}
        self.now = datetime(2026, 10, 17, tzinfo=timezone.utc)
        self.consent = True
        self.inbox = Receiver("bob", self.registry, lambda msg: self.consent)

    def tearDown(self):
        self.inbox.close()

    def message(self, **changes):
        msg = {"phi_version": "0.1", "from": "alice", "to": "bob", "intent": "status",
               "content": {"text": "synthetic test"}, "timestamp": self.now.isoformat(),
               "nonce": "unique-nonce-0001"}
        msg.update(changes)
        return sign(self.key, msg)

    def test_two_nodes_deliver_signed_message(self):
        self.assertEqual(self.inbox.receive(self.message(), now=self.now)["content"]["text"], "synthetic test")

    def test_replay_is_rejected(self):
        msg = self.message()
        self.inbox.receive(msg, now=self.now)
        with self.assertRaisesRegex(MessageRejected, "replay"):
            self.inbox.receive(msg, now=self.now)

    def test_replay_survives_receiver_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "inbox.sqlite")
            one = Receiver("bob", self.registry, lambda msg: True, path)
            one.receive(self.message(), now=self.now)
            one.close()
            two = Receiver("bob", self.registry, lambda msg: True, path)
            try:
                with self.assertRaisesRegex(MessageRejected, "replay"):
                    two.receive(self.message(), now=self.now)
            finally:
                two.close()

    def test_revocation_after_signing_blocks_delivery(self):
        msg = self.message()
        self.registry["alice"]["revoked"] = True
        with self.assertRaisesRegex(MessageRejected, "revoked"):
            self.inbox.receive(msg, now=self.now)

    def test_consent_withdrawal_after_signing_blocks_delivery(self):
        msg = self.message()
        self.consent = False
        with self.assertRaisesRegex(MessageRejected, "consent_denied"):
            self.inbox.receive(msg, now=self.now)

    def test_failed_consent_does_not_consume_nonce(self):
        msg = self.message()
        self.consent = False
        with self.assertRaises(MessageRejected): self.inbox.receive(msg, now=self.now)
        self.consent = True
        self.inbox.receive(msg, now=self.now)

    def test_wrong_recipient_unknown_key_expired_and_future(self):
        cases = [dict(to="other"), dict(**{"from": "mallory"}),
                 dict(timestamp=(self.now-timedelta(seconds=300)).isoformat()),
                 dict(timestamp=(self.now+timedelta(seconds=31)).isoformat())]
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(MessageRejected):
                self.inbox.receive(self.message(**changes), now=self.now)

    def test_mutation_and_malformed_signature(self):
        for mutate in [lambda m: m["content"].update(text="changed"), lambda m: m.update(signature="***")]:
            msg = self.message(); mutate(msg)
            with self.assertRaisesRegex(MessageRejected, "invalid_signature"):
                self.inbox.receive(msg, now=self.now)

    def test_delimiter_collision_rejected_before_signing(self):
        with self.assertRaises(ValueError): self.message(**{"from": "alice|mallory"})

    def test_malformed_nonfinite_large_and_naive_time(self):
        for msg in [None, {}, {"phi_version": "0.1", "content": {"x": float("nan")}}]:
            with self.subTest(msg=msg), self.assertRaises(MessageRejected):
                self.inbox.receive(msg, now=self.now)
        with self.assertRaisesRegex(MessageRejected, "too_large"):
            self.inbox.receive(self.message(content={"text": "x"*20000}), now=self.now)
        with self.assertRaisesRegex(MessageRejected, "timezone"):
            self.inbox.receive(self.message(), now=self.now.replace(tzinfo=None))

    def test_policy_failure_denies_and_cannot_mutate_accepted_content(self):
        def fail(msg): raise RuntimeError("offline")
        self.inbox.authorize = fail
        with self.assertRaisesRegex(MessageRejected, "consent_unavailable"):
            self.inbox.receive(self.message(), now=self.now)
        def mutate(msg): msg["content"]["text"] = "changed"; return True
        self.inbox.authorize = mutate
        self.assertEqual(self.inbox.receive(self.message(), now=self.now)["content"]["text"], "synthetic test")


if __name__ == "__main__": unittest.main()
