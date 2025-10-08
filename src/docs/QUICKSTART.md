# QUICKSTART

## Option A — No Python today (Legal moat only)
1. Your main documents already have DOIs (great).
2. Add a **blockchain timestamp** (OriginStamp or OpenTimestamps). Upload each PDF, keep the proof receipts.
3. Upload the same PDFs to another repository (Internet Archive or OSF).
4. Commit the links/DOIs into this repo’s README so everything is discoverable.

## Option B — Run the demo (keys + signatures)
**Requirements:** Python 3.10+ and `pip install cryptography`

**1. Generate keys**
Creates `keys/node_private.pem` and `keys/node_public.pem`.

**2. Put your public key into `allowlist.json`**
- Open `keys/node_public.pem`, copy the whole PEM block.
- In `allowlist.json`, replace `REPLACE_ME` with that PEM text (keep line breaks).

**3. Run the demo**
You should see `Signature valid: True` and the full signed message.

## Next steps
- Set up two nodes (two keypairs) and add both public keys to `allowlist.json`.
- Send messages over HTTP/WebSocket later; the signature format stays the same.
