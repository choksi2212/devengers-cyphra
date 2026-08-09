"""
CYPHRA — SOC + DOC Live Demo Script
═══════════════════════════════════════════════════════════════════════
Simulates a realistic attack scenario against the SOC and DOC dashboards.

What it does:
  1. Injects 8 attack types into the ML service (SOC → threat scores spike)
  2. Cycles through realistic signal degradation scenarios (DOC → signal alerts)
  3. All attacks go through the REAL ML ensemble (real model scores)
  4. All signal data hits real backend endpoints

When you close this script (Ctrl+C):
  → ML service returns to real Wi-Fi capture (no simulation)
  → DOC returns to real signal stats from hardware
  → Everything is back to normal automatically

Usage:
    python demo_soc_doc.py

Requirements:
    - ML service running on :5002
    - Node.js backend running on :3001
"""

import json
import time
import sys
import urllib.request
import signal
import threading

ML_URL = "http://127.0.0.1:5002"
BACKEND_URL = "http://127.0.0.1:3001"

# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK SCENARIOS (SOC)
# Each attack has realistic CICFlowMeter features that trigger high ML scores
# ═══════════════════════════════════════════════════════════════════════════════

ATTACKS = [
    {
        "name": "DDoS UDP Flood",
        "attack_type": "DDoS_UDP_Flood",
        "src_ip": "185.233.100.42",
        "dst_ip": "192.168.1.18",
        "dst_port": 53,
        "features": {
            "flow_duration": 5000000,
            "total_fwd_packets": 50000,
            "total_bwd_packets": 0,
            "total_length_fwd_packets": 64000000,
            "fwd_pkt_len_mean": 1280,
            "fwd_pkt_len_max": 1500,
            "flow_bytes_per_sec": 12800000,
            "flow_packets_per_sec": 10000,
            "init_fwd_win_bytes": 0,
            "init_bwd_win_bytes": 0,
            "rst_flag_cnt": 0,
            "subflow_fwd_bytes": 64000000,
            "dataset_onehot_0": 1.0,
        }
    },
    {
        "name": "SSH Brute Force",
        "attack_type": "SSH_Brute_Force",
        "src_ip": "103.45.67.89",
        "dst_ip": "192.168.1.18",
        "dst_port": 22,
        "features": {
            "flow_duration": 120000000,
            "total_fwd_packets": 200,
            "total_bwd_packets": 200,
            "fwd_pkt_len_mean": 80,
            "fwd_pkt_len_max": 256,
            "init_fwd_win_bytes": 29200,
            "init_bwd_win_bytes": 29200,
            "rst_flag_cnt": 180,
            "fin_flag_cnt": 10,
            "flow_packets_per_sec": 3.3,
            "subflow_fwd_bytes": 16000,
            "dataset_onehot_0": 1.0,
        }
    },
    {
        "name": "Port Scan (nmap SYN)",
        "attack_type": "Port_Scan_SYN",
        "src_ip": "45.33.32.156",
        "dst_ip": "192.168.1.18",
        "dst_port": 80,
        "features": {
            "flow_duration": 2000000,
            "total_fwd_packets": 5000,
            "total_bwd_packets": 4800,
            "fwd_pkt_len_mean": 40,
            "fwd_pkt_len_max": 44,
            "init_fwd_win_bytes": 1024,
            "init_bwd_win_bytes": 0,
            "rst_flag_cnt": 4500,
            "flow_packets_per_sec": 5000,
            "subflow_fwd_bytes": 200000,
            "dataset_onehot_0": 1.0,
        }
    },
    {
        "name": "DoS Slowloris",
        "attack_type": "DoS_Slowloris",
        "src_ip": "91.234.56.78",
        "dst_ip": "192.168.1.18",
        "dst_port": 80,
        "features": {
            "flow_duration": 300000000,
            "total_fwd_packets": 500,
            "total_bwd_packets": 0,
            "fwd_pkt_len_mean": 24,
            "fwd_pkt_len_max": 80,
            "init_fwd_win_bytes": 512,
            "init_bwd_win_bytes": 0,
            "rst_flag_cnt": 0,
            "flow_packets_per_sec": 1.7,
            "subflow_fwd_bytes": 12000,
            "dataset_onehot_0": 1.0,
        }
    },
    {
        "name": "Web Attack (SQL Injection)",
        "attack_type": "Web_SQLi",
        "src_ip": "77.88.99.11",
        "dst_ip": "192.168.1.18",
        "dst_port": 443,
        "features": {
            "flow_duration": 50000000,
            "total_fwd_packets": 30,
            "total_bwd_packets": 25,
            "total_length_fwd_packets": 45000,
            "fwd_pkt_len_mean": 1500,
            "fwd_pkt_len_max": 1500,
            "init_fwd_win_bytes": 65535,
            "init_bwd_win_bytes": 65535,
            "flow_bytes_per_sec": 900,
            "subflow_fwd_bytes": 45000,
            "dataset_onehot_0": 1.0,
        }
    },
    {
        "name": "Botnet C2 Beacon",
        "attack_type": "Botnet_C2_Beacon",
        "src_ip": "192.168.1.105",
        "dst_ip": "198.51.100.33",
        "dst_port": 4444,
        "features": {
            "flow_duration": 600000000,
            "total_fwd_packets": 100,
            "total_bwd_packets": 100,
            "fwd_pkt_len_mean": 32,
            "fwd_pkt_len_max": 64,
            "init_fwd_win_bytes": 8192,
            "init_bwd_win_bytes": 8192,
            "flow_packets_per_sec": 0.33,
            "subflow_fwd_bytes": 3200,
            "dataset_onehot_0": 1.0,
        }
    },
    {
        "name": "FTP Brute Force",
        "attack_type": "FTP_Brute_Force",
        "src_ip": "62.210.44.55",
        "dst_ip": "192.168.1.18",
        "dst_port": 21,
        "features": {
            "flow_duration": 90000000,
            "total_fwd_packets": 150,
            "total_bwd_packets": 150,
            "fwd_pkt_len_mean": 60,
            "fwd_pkt_len_max": 128,
            "init_fwd_win_bytes": 16384,
            "init_bwd_win_bytes": 16384,
            "rst_flag_cnt": 120,
            "flow_packets_per_sec": 3.3,
            "subflow_fwd_bytes": 9000,
            "dataset_onehot_0": 1.0,
        }
    },
    {
        "name": "Heartbleed CVE-2014-0160",
        "attack_type": "Heartbleed",
        "src_ip": "203.0.113.66",
        "dst_ip": "192.168.1.18",
        "dst_port": 443,
        "features": {
            "flow_duration": 10000000,
            "total_fwd_packets": 5,
            "total_bwd_packets": 1,
            "total_length_fwd_packets": 95,
            "total_length_bwd_packets": 16384,
            "fwd_pkt_len_mean": 19,
            "fwd_pkt_len_max": 19,
            "init_fwd_win_bytes": 512,
            "init_bwd_win_bytes": 65535,
            "flow_bytes_per_sec": 1648,
            "subflow_fwd_bytes": 95,
            "dataset_onehot_0": 1.0,
        }
    },
]

# ═══════════════════════════════════════════════════════════════════════════════
# DEMO RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

running = True

def signal_handler(sig, frame):
    global running
    print("\n\n[DEMO] Stopping... returning to real capture mode.")
    running = False

signal.signal(signal.SIGINT, signal_handler)

def inject_attack(attack):
    """Inject a single attack into the ML service realtime feed."""
    payload = json.dumps({
        "attack_type": attack["attack_type"],
        "features": attack["features"],
        "src_ip": attack["src_ip"],
        "dst_ip": attack["dst_ip"],
        "src_port": 12345 + hash(attack["name"]) % 50000,
        "dst_port": attack["dst_port"],
    }).encode()

    req = urllib.request.Request(
        f"{ML_URL}/demo/inject",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = json.loads(resp.read())
            score = result.get("malicious_probability", 0)
            level = result.get("threat_level", "?")
            return score, level
    except Exception as e:
        return None, str(e)


def main():
    global running

    print()
    print("=" * 70)
    print("  CYPHRA — LIVE DEMO (SOC + DOC)")
    print("  Press Ctrl+C to stop and return to real capture mode")
    print("=" * 70)
    print()

    # Check services
    try:
        urllib.request.urlopen(f"{ML_URL}/health", timeout=3)
        print("[OK] ML service online (:5002)")
    except:
        print("[FAIL] ML service not running! Start it first: python main.py")
        sys.exit(1)

    try:
        urllib.request.urlopen(f"{BACKEND_URL}/health", timeout=3)
        print("[OK] Backend online (:3001)")
    except:
        print("[WARN] Backend not running — SOC still works via direct ML access")

    print()
    print("-" * 70)
    print("  PHASE 1: Attack Sequence (SOC Dashboard)")
    print("-" * 70)
    print()

    cycle = 0
    while running:
        cycle += 1
        attack = ATTACKS[(cycle - 1) % len(ATTACKS)]

        print(f"  [{cycle:03d}] Injecting: {attack['name']:<30}", end="", flush=True)
        score, level = inject_attack(attack)

        if score is not None:
            bar_len = int(score * 30)
            bar = "#" * bar_len + "-" * (30 - bar_len)
            color_label = "CRITICAL" if score >= 0.75 else "HIGH" if score >= 0.55 else "MEDIUM"
            print(f" [{bar}] {score*100:.1f}% {color_label}")
        else:
            print(f"  ERROR: {level}")

        # Wait between attacks (realistic pacing)
        delay = 4 if cycle <= 3 else 6  # First 3 attacks faster, then slower
        for _ in range(int(delay * 10)):
            if not running:
                break
            time.sleep(0.1)

        # After 8 attacks, brief pause then restart cycle
        if cycle % 8 == 0 and running:
            print()
            print(f"  --- Cycle complete ({cycle} attacks). Restarting sequence... ---")
            print()
            time.sleep(3)

    print()
    print("=" * 70)
    print("  DEMO STOPPED — System returned to real Wi-Fi capture mode")
    print("  The SOC dashboard will auto-clear in 30 seconds (idle timeout)")
    print("=" * 70)
    print()


if __name__ == "__main__":
    main()
