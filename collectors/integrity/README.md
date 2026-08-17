# Collector integrity — independence from the agent loop (AIM-639)

Reference implementation for scorecard **Dimension 16**.

| Module | Role |
|---|---|
| `signing.py` | Ed25519 `aim.signed-bundle/v1` envelopes |
| `harden.py` | Refuse unsigned/tampered config + binary digests in harden mode |
| `harden.verify_signed_artifact` | Signed update manifest / sha256 for package files |
| `oob_health.py` | Host-level health signal (root timer) |
| `attestation.py` | Continuous architectural attestation |
| `tests/test_anti_bypass.py` | Agent disable/spoof simulations (detect **and** alert) |
| `harden.detect_and_alert` | Shared detect/alert contract used by the suite |

## Quick verify

```bash
pip install cryptography   # integrity package only; collectors stay stdlib for hooks
python -m pytest collectors/integrity/tests -q
python3 scripts/independence_attestation.py
```

## Sign a fleet policy

```bash
python3 scripts/sign_collector_bundle.py --gen-keypair --out-dir /tmp/aim-keys
python3 scripts/sign_collector_bundle.py \
  --in collectors/claude-code/aim_collector/default_enforcement.json \
  --out /tmp/enforcement.signed.json \
  --key-file /tmp/aim-keys/ed25519.priv.b64 \
  --key-id aim-config-dev
# Deploy public key to endpoints:
#   Linux:  /etc/aim-collector/config-pubkey.b64
#   macOS:  /Library/Application Support/AI-Monitoring/collector/config-pubkey.b64
#           (user: ~/Library/Application Support/AI-Monitoring/collector/)
# Deploy signed JSON as managed enforcement/config file; set AIM_HARDEN=1
```

See `docs/security/adr-independence-from-agent-loop.md`.
