"""
CYPHRA Server — Comprehensive Test Suite
Tests both direct access (:5050) and proxied access via Node.js (:3001)
"""

import json
import urllib.request
import sys
import time

DIRECT = "http://127.0.0.1:5050/api/v1"
PROXY  = "http://127.0.0.1:3001/api/CYPHRA"

passed = 0
failed = 0
errors = []

def test(name, method, url, body=None, validate=None):
    global passed, failed, errors
    try:
        data = json.dumps(body).encode() if body else b"{}"
        req = urllib.request.Request(url, data=data if method == "POST" else None,
                                     headers={"Content-Type": "application/json"},
                                     method=method)
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
            if validate:
                assert validate(result), f"Validation failed: {result}"
            passed += 1
            print(f"  PASS  {name}")
            return result
    except Exception as e:
        failed += 1
        errors.append(f"{name}: {e}")
        print(f"  FAIL  {name} -- {e}")
        return None

def run_suite(label, base):
    global passed, failed
    print(f"\n{'='*60}")
    print(f"  {label} ({base})")
    print(f"{'='*60}")

    # Health
    test("Health check", "GET", f"{base}/health",
         validate=lambda r: r["status"] == "healthy")

    # Identity keypair
    kp = test("Generate Kyber1024+X25519 identity keypair", "POST",
              f"{base}/crypto/keypair/identity", {},
              validate=lambda r: r["kyber_public_key_size"] == 1184 and r["algorithm"] == "Kyber1024 + X25519 (PQC-Hybrid)")

    # Signed prekey (requires identity)
    if kp:
        test("Generate signed prekey", "POST", f"{base}/crypto/keypair/signed",
             {"device_id": kp["device_id"], "kyber_public": kp["kyber_public_key"],
              "kyber_secret": "00"*2400, "x25519_public": kp["x25519_public_key"],
              "x25519_secret": kp["x25519_secret_key"]},
             validate=lambda r: r["timestamp"] > 0)

    # One-time prekeys
    test("Generate 10 one-time prekeys", "POST", f"{base}/crypto/keypair/onetime",
         {"count": 10},
         validate=lambda r: r["count"] == 10)

    # HKDF-BLAKE3
    test("HKDF-BLAKE3 key derivation (64 bytes)", "POST", f"{base}/crypto/hkdf",
         {"salt": "deadbeef", "ikm": "0123456789abcdef", "info": "session-key", "output_len": 64},
         validate=lambda r: len(r["derived_key"]) == 128 and r["algorithm"] == "HKDF-BLAKE3")

    # BLAKE3 hash
    test("BLAKE3 hash", "POST", f"{base}/crypto/hash",
         {"data": "48656c6c6f20576f726c64"},
         validate=lambda r: len(r["hash"]) == 64 and r["algorithm"] == "BLAKE3")

    # X3DH full session
    alice = test("X3DH: Generate Alice identity", "POST", f"{base}/crypto/keypair/identity", {})
    bob = test("X3DH: Generate Bob identity", "POST", f"{base}/crypto/keypair/identity", {})
    if alice and bob:
        session = test("X3DH: Initiate session (Kyber encap + X25519 ECDH)", "POST",
                       f"{base}/crypto/x3dh/initiate",
                       {"recipient_identity_kyber_pk": bob["kyber_public_key"],
                        "recipient_signed_prekey_kyber_pk": bob["kyber_public_key"],
                        "sender_kyber_public": alice["kyber_public_key"],
                        "sender_kyber_secret": "00"*2400,
                        "sender_x25519_public": alice["x25519_public_key"],
                        "sender_x25519_secret": alice["x25519_secret_key"],
                        "sender_device_id": alice["device_id"]},
                       validate=lambda r: len(r["root_key"]) == 64 and r["init_message_size"] > 4000)

    # AI Threat Score
    test("AI: Threat score (high metadata leak)", "POST", f"{base}/ai/threat-score",
         {"packet_sizes": [64]*20,
          "inter_arrival_times": [100]*19,
          "direction_pattern": [True]*20,
          "total_bytes": 200000000, "connection_count": 200, "unique_destinations": 80},
         validate=lambda r: r["overall_score"] > 0.0 and r["confidence"] > 0.0)

    # AI Anomaly Detection
    test("AI: Anomaly detection on packet flow", "POST", f"{base}/ai/anomaly-detect",
         {"packets": [{"size": 64, "timestamp": i*100, "outgoing": i%2==0} for i in range(15)]},
         validate=lambda r: r["features_extracted"]["packet_count"] == 15)

# ─── Run ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  CYPHRA Server -- Comprehensive Test Suite")
    print(f"  {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Test direct access
    run_suite("DIRECT (Rust server :5050)", DIRECT)

    # Test proxy access (only if Node backend is running)
    try:
        urllib.request.urlopen(f"{PROXY}/health", timeout=3)
        run_suite("PROXY (Node.js :3001 -> Rust :5050)", PROXY)
    except Exception:
        print(f"\n  SKIP  Proxy tests (Node.js backend not running on :3001)")

    # Summary
    total = passed + failed
    print(f"\n{'='*60}")
    print(f"  RESULTS: {passed}/{total} PASSED, {failed} FAILED")
    print(f"{'='*60}")
    if errors:
        print("\n  Failures:")
        for e in errors:
            print(f"    - {e}")
    print()
    sys.exit(0 if failed == 0 else 1)
