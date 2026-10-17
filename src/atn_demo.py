"""Two local nodes, no sockets, no saved private keys or external effects."""
from datetime import datetime, timezone
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from src.cup_node import sign
from src.cup_receiver import Receiver, MessageRejected


def run():
    key = Ed25519PrivateKey.generate()
    registry = {"node-a": {"pubkey_pem": key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()}}
    now = datetime.now(timezone.utc)
    consent = {"active": True}
    receiver = Receiver("node-b", registry, lambda msg: consent["active"])
    outcomes = {}
    try:
        def message(nonce):
            return sign(key, {"phi_version":"0.1", "from":"node-a", "to":"node-b",
                "intent":"status", "content":{"text":"Synthetic two-node test"},
                "timestamp":now.isoformat(), "nonce":nonce})
        first = message("local-test-0001")
        receiver.receive(first, now=now)
        outcomes["initial_delivery"] = "accepted"
        for name, msg in [("replay", first), ("withdrawn_consent", message("local-test-0002"))]:
            if name == "withdrawn_consent": consent["active"] = False
            try:
                receiver.receive(msg, now=now)
                outcomes[name] = "UNEXPECTED_ACCEPTANCE"
            except MessageRejected as exc:
                outcomes[name] = str(exc)
        consent["active"] = True
        registry["node-a"]["revoked"] = True
        try:
            receiver.receive(message("local-test-0003"), now=now)
            outcomes["revoked_key"] = "UNEXPECTED_ACCEPTANCE"
        except MessageRejected as exc:
            outcomes["revoked_key"] = str(exc)
        return outcomes
    finally:
        receiver.close()


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2))
    if result != {"initial_delivery":"accepted", "replay":"replay", "withdrawn_consent":"consent_denied", "revoked_key":"unknown_or_revoked_key"}:
        raise SystemExit(1)
