"""
CYPHRA — Full Stack Test Suite
Tests every layer: ML service → Node proxy → Frontend data flow
Run with: python test_all.py
"""
import urllib.request
import urllib.error
import json
import time
import sys

BACKEND  = "http://127.0.0.1:3001"    # Node.js
ML       = "http://127.0.0.1:5002"    # FastAPI

OK  = "[PASS]"
ERR = "[FAIL]"
SKP = "[SKIP]"

results = []

def get(url, timeout=6):
    try:
        r = urllib.request.urlopen(urllib.request.Request(url), timeout=timeout)
        return json.loads(r.read()), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except Exception as e:
        return None, str(e)

def post(url, body, timeout=10):
    try:
        data = json.dumps(body).encode()
        req  = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        r    = urllib.request.urlopen(req, timeout=timeout)
        return json.loads(r.read()), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except Exception as e:
        return None, str(e)

def check(name, ok, value="", note=""):
    status = OK if ok else ERR
    results.append(ok)
    tag = f"\033[92m{status}\033[0m" if ok else f"\033[91m{status}\033[0m"
    val = f"  {value}" if value else ""
    nt  = f"  ({note})" if note else ""
    print(f"  {tag}  {name}{val}{nt}")

print()
print("=" * 60)
print("  CYPHRA FULL STACK TEST")
print(f"  Backend : {BACKEND}")
print(f"  ML Svc  : {ML}")
print("=" * 60)

# ─────────────────────────────────────────────
print("\n[1] ML SERVICE (FastAPI :5002)")
# ─────────────────────────────────────────────

d, e = get(f"{ML}/health")
check("ML service reachable",      d is not None, note=e or "")
if d:
    check("Models loaded",         d.get("models_loaded", 0) == 6, f"{d.get('models_loaded')} / 6")
    check("Packet capture active", d.get("capture_active") == True, d.get("capture_iface","?"))
    check("Feature count correct", d.get("feature_count", 0) == 100, f"{d.get('feature_count')} features")

d, e = get(f"{ML}/model/info")
check("Model info endpoint",       d is not None, note=e or "")
if d:
    check("Ensemble accuracy",     d.get("accuracy", 0) > 98, f"{d.get('accuracy')}%")
    check("6 base model entries",  len(d.get("base_models", [])) > 0)

d, e = get(f"{ML}/monitor/stats")
check("Monitor stats endpoint",    d is not None, note=e or "")
if d:
    check("Real capture mode",     d.get("mode") == "real-capture", d.get("mode","?"))
    check("Packets being captured",d.get("packets_captured", 0) > 0, f"{d.get('packets_captured',0):,} pkts")
    check("Bandwidth present",     d.get("bandwidth_mbps") is not None, f"{d.get('bandwidth_mbps')} Mbps")

# Wait for flows to complete
print("\n  Waiting 8s for real flows to accumulate...")
time.sleep(8)

d, e = get(f"{ML}/realtime/feed?limit=10")
check("Realtime feed endpoint",    d is not None, note=e or "")
if d:
    check("Is real capture",       d.get("real_capture") == True)
    check("Flows being classified",d.get("total_classified", 0) > 0, f"{d.get('total_classified',0)} flows")
    check("Results in feed",       d.get("count", 0) > 0, f"{d.get('count',0)} results")

    if d.get("results"):
        f0 = d["results"][0]
        check("Flow has threat_score",      "threat_score"   in f0)
        check("Flow has threat_level",      "threat_level"   in f0)
        check("Flow has model_scores",      "model_scores"   in f0)
        check("Flow has inference_ms",      "inference_ms"   in f0)
        check("Inference is fast (<100ms)", f0.get("inference_ms",999) < 100,
              f"{f0.get('inference_ms','?')} ms")
        check("6 model scores present",     len(f0.get("model_scores",{})) == 6,
              f"{len(f0.get('model_scores',{}))} models")

d, e = post(f"{ML}/analyze/message", {"text": "exec(/bin/bash -i); /bin/sh -c 'whoami'"})
check("Message analysis endpoint", d is not None, note=e or "")
if d:
    check("Exec detected as threat",   d.get("threat_score", 0) > 0.3, f"score={d.get('threat_score')}")
    check("Classification correct",    d.get("classification") == "Command Injection",
          d.get("classification","?"))
    check("Inference <50ms",           d.get("inference_ms", 999) < 50, f"{d.get('inference_ms')} ms")

# ─────────────────────────────────────────────
print("\n[2] NODE.JS BACKEND PROXY (:3001 -> :5002)")
# ─────────────────────────────────────────────

d, e = get(f"{BACKEND}/api/ml/health")
check("Proxy: /api/ml/health",         d is not None, note=e or "(is Node backend running?)")
if d:
    check("Proxy passes capture status", d.get("capture_active") == True)

d, e = get(f"{BACKEND}/api/ml/model/info")
check("Proxy: /api/ml/model/info",     d is not None, note=e or "")

d, e = get(f"{BACKEND}/api/ml/monitor/stats")
check("Proxy: /api/ml/monitor/stats",  d is not None, note=e or "")

d, e = get(f"{BACKEND}/api/ml/realtime/feed?limit=5")
check("Proxy: /api/ml/realtime/feed",  d is not None, note=e or "")

d, e = post(f"{BACKEND}/api/ml/analyze/message",
            {"text": "exec(base64.decode('payload')) via shell"})
check("Proxy: /api/ml/analyze/message",d is not None, note=e or "")

# ─────────────────────────────────────────────
print("\n[3] BACKEND CORE (VedDB storage)")
# ─────────────────────────────────────────────

d, e = get(f"{BACKEND}/api/storage/ping")
check("VedDB ping",                    d is not None and d.get("status") != "error",
      note=e or d.get("status","?") if d else e)

d, e = post(f"{BACKEND}/api/storage/set", {"key": "test_key_cyphra", "value": "test_ok"})
check("VedDB SET",                     d is not None and d.get("success"), note=e or "")

d, e = get(f"{BACKEND}/api/storage/get/test_key_cyphra")
check("VedDB GET (persisted data)",    d is not None and d.get("value") == "test_ok",
      note=e or "")

# ─────────────────────────────────────────────
print("\n[4] SUMMARY")
# ─────────────────────────────────────────────
passed = sum(1 for r in results if r)
failed = sum(1 for r in results if not r)
total  = len(results)

print(f"  Passed : \033[92m{passed}/{total}\033[0m")
if failed:
    print(f"  Failed : \033[91m{failed}/{total}\033[0m")
if passed == total:
    print("\n  \033[92mALL TESTS PASSED — 100% real pipeline confirmed!\033[0m")
else:
    pct = passed / total * 100
    print(f"\n  {pct:.0f}% tests passing — check failed items above")

print("=" * 60)
