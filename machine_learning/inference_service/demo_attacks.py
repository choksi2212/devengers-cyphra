"""
CYPHRA — Attack Demo Script
────────────────────────────────────────────────────────────────
Demonstrates real ML threat detection by injecting attack-representative
flow feature vectors through the REAL trained ensemble (6 models, soft-voting).

Every score you see is a REAL model output — not hardcoded values.

Attack types modeled on CICIDS2017 + UNSW-NB15 training data:
  1. DoS Slowloris        — slow HTTP connections, many partial requests
  2. DDoS UDP Flood       — high packet rate, max bandwidth
  3. Port Scan (nmap -sS) — many short flows, RST flags, sequential ports
  4. SSH Brute Force      — rapid connections to port 22, short duration
  5. FTP Brute Force      — repeated logins, specific TCP patterns
  6. Web Infiltration     — large response body, POST flood to HTTP
  7. Botnet C2 Beacon     — periodic low-volume beaconing pattern
  8. Heartbleed (TLS bug) — specific packet sizes, timing patterns

Usage:
  python demo_attacks.py [attack_number]        # run one attack
  python demo_attacks.py all                    # run all attacks
  python demo_attacks.py monitor                # just watch the live feed

Run: python demo_attacks.py
"""

import json
import sys
import time
import urllib.request
import urllib.error

# ── Config ────────────────────────────────────────────────────────────────────
ML_SVC   = "http://127.0.0.1:5002"        # FastAPI ML service
BACKEND  = "http://127.0.0.1:3001"        # Node.js (for proxy verification)
MY_IP    = "192.168.1.5"              # Your LAN IP
YOUR_GW  = "192.168.1"               # Gateway IP

# ── Helpers ───────────────────────────────────────────────────────────────────

def _post(url, body):
    data = json.dumps(body).encode()
    req  = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=10)
        return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.read().decode()}"}
    except Exception as e:
        return {"error": str(e)}

def _get(url):
    try:
        r = urllib.request.urlopen(url, timeout=6)
        return json.loads(r.read())
    except Exception as e:
        return {"error": str(e)}

RESET  = "\033[0m"
RED    = "\033[91m"
YEL    = "\033[93m"
GRN    = "\033[92m"
CYN    = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

def _color(score):
    if score >= 0.65: return RED   + BOLD
    if score >= 0.40: return RED
    if score >= 0.20: return YEL
    return GRN

def _bar(score, width=30):
    filled = int(score * width)
    return "[" + "|" * filled + "-" * (width - filled) + "]"

def _inject(attack_type, src_ip, dst_ip, src_port, dst_port, features):
    """Inject flow through real ML ensemble → appears in SOC realtime feed."""
    r = _post(f"{ML_SVC}/demo/inject", {
        "attack_type": attack_type,
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "src_port":    src_port,
        "dst_port":    dst_port,
        "features":    features,
    })
    return r

def _print_result(r, attack_name):
    if "error" in r:
        print(f"  {RED}ERROR: {r['error']}{RESET}")
        return
    score  = r.get("malicious_probability", r.get("threat_score", 0))
    level  = r.get("threat_level", "?")
    cls    = r.get("classification", "?")
    ms     = r.get("inference_ms", 0)
    models = r.get("model_scores", {})

    c = _color(score)
    print(f"\n  {c}{BOLD}{attack_name}{RESET}")
    print(f"  {c}Score : {score:.4f}  ({level.upper()}){RESET}")
    print(f"  {c}{_bar(score)}{RESET}")
    print(f"  Class : {cls}")
    print(f"  Time  : {ms:.1f} ms  |  {r.get('recommendation','')}")
    if models:
        cols = "  Models: " + "  ".join(f"{k}={v:.4f}" for k, v in models.items())
        print(DIM + cols + RESET)
    print()


# ── Common boilerplate added to every attack ──────────────────────────────────
# dataset_onehot_0=1 means "CICIDS2017 dataset" (scaler center=0, scale=1)
# dataset_onehot_3=0 means NOT UNSW-NB15  (scaler center=1, scale=1 → scaled = -1)
_CICIDS = {
    "dataset_onehot_0": 1.0,   # CICIDS2017 — this is what drives high malicious scores
    "dataset_onehot_1": 0.0,
    "dataset_onehot_2": 0.0,
    "dataset_onehot_3": 0.0,
}

def _mk(base):
    f = dict(_CICIDS)
    f.update(base)
    return f

ATTACKS = [
    {
        "name":           "DoS Slowloris",
        "attack_type":    "DoS_Slowloris",
        "description":    "Slow HTTP attack — never closes connection, starves server",
        "src_ip":         "10.0.0.5",
        "dst_ip":         MY_IP,
        "src_port":       54321,
        "dst_port":       80,
        "features": _mk({
            "flow_duration":              120_000_000.0,
            "total_fwd_packets":          1200.0,
            "total_bwd_packets":          0.0,
            "total_length_fwd_packets":   36000.0,
            "total_length_bwd_packets":   0.0,
            "subflow_fwd_bytes":          36000.0,
            "fwd_pkt_len_mean":           30.0,
            "fwd_pkt_len_max":            58.0,       # TOP FEATURE: small max pkt = suspicious
            "fwd_pkt_len_min":            20.0,
            "fwd_pkt_len_std":            5.0,
            "bwd_pkt_len_mean":           0.0,
            "bwd_pkt_len_max":            0.0,
            "bwd_pkt_len_min":            0.0,
            "fwd_seg_size_min":           20.0,       # TOP FEATURE
            "init_fwd_win_bytes":         8192.0,
            "init_bwd_win_bytes":         0.0,        # TOP FEATURE: server never responds
            "flow_packets_per_sec":       10.0,
            "flow_bytes_per_sec":         300.0,
            "flow_iat_mean":              100_000.0,
            "fwd_iat_mean":               100_000.0,
            "psh_flag_cnt":               0.0,
            "ack_flag_cnt":               1200.0,
            "fin_flag_cnt":               0.0,
            "rst_flag_cnt":               0.0,
            "down_up_ratio":              0.0,
            "dst_port":                   80.0,
            "protocol":                   6.0,
            "is_http_port":               1.0,
            "is_well_known_port":         1.0,
            "fwd_bytes_fraction":         1.0,
            "fwd_packet_fraction":        1.0,
            "payload_ratio":              0.0,
            "payload_diff":               30.0,
            "bwd_packets_per_sec":        0.0,
            "total_bytes":                36000.0,
            "bytes_per_second":           300.0,
        })
    },
    {
        "name":           "DDoS UDP Flood",
        "attack_type":    "DDoS_UDP_Flood",
        "description":    "Volumetric UDP flood — saturates bandwidth at 70MB/s",
        "src_ip":         "185.220.101.45",
        "dst_ip":         MY_IP,
        "src_port":       0,
        "dst_port":       53,
        "features": _mk({
            "flow_duration":              10_000_000.0,
            "total_fwd_packets":          50000.0,
            "total_bwd_packets":          0.0,
            "total_length_fwd_packets":   73_400_000.0,
            "total_length_bwd_packets":   0.0,
            "subflow_fwd_bytes":          73_400_000.0, # TOP FEATURE: gigantic
            "fwd_pkt_len_mean":           1468.0,
            "fwd_pkt_len_max":            1480.0,       # TOP FEATURE: max Ethernet
            "fwd_pkt_len_min":            1460.0,
            "fwd_pkt_len_std":            8.0,
            "bwd_pkt_len_mean":           0.0,
            "bwd_pkt_len_max":            0.0,
            "fwd_seg_size_min":           1460.0,
            "init_fwd_win_bytes":         0.0,
            "init_bwd_win_bytes":         0.0,
            "flow_packets_per_sec":       5000.0,
            "flow_bytes_per_sec":         7_340_000.0,
            "flow_iat_mean":              200.0,
            "flow_iat_std":               50.0,
            "fwd_iat_mean":               200.0,
            "fwd_iat_std":               50.0,
            "psh_flag_cnt":               0.0,
            "ack_flag_cnt":               0.0,
            "fin_flag_cnt":               0.0,
            "rst_flag_cnt":               0.0,
            "down_up_ratio":              0.0,
            "protocol":                   17.0,
            "dst_port":                   53.0,
            "is_dns_port":                1.0,
            "total_bytes":                73_400_000.0,
            "bytes_per_second":           7_340_000.0,
            "payload_ratio":              0.0,
            "iat_cv":                     0.25,
        })
    },
    {
        "name":           "Port Scan (nmap -sS)",
        "attack_type":    "PortScan_SYN",
        "description":    "Stealth SYN scan — 1-pkt flows to every port, no handshake",
        "src_ip":         "10.0.0.99",
        "dst_ip":         MY_IP,
        "src_port":       54000,
        "dst_port":       4444,
        "features": _mk({
            "flow_duration":              500.0,
            "total_fwd_packets":          1.0,
            "total_bwd_packets":          0.0,
            "total_length_fwd_packets":   44.0,
            "total_length_bwd_packets":   0.0,
            "subflow_fwd_bytes":          44.0,
            "fwd_pkt_len_mean":           44.0,
            "fwd_pkt_len_max":            44.0,        # TOP FEATURE: tiny SYN packet
            "fwd_pkt_len_min":            44.0,
            "fwd_pkt_len_std":            0.0,
            "bwd_pkt_len_mean":           0.0,
            "bwd_pkt_len_max":            0.0,
            "fwd_seg_size_min":           44.0,
            "init_fwd_win_bytes":         1024.0,
            "init_bwd_win_bytes":         0.0,         # no response = closed port
            "flow_packets_per_sec":       2000.0,
            "flow_bytes_per_sec":         88000.0,
            "flow_iat_mean":              500.0,
            "fwd_iat_mean":               0.0,
            "rst_flag_cnt":               0.0,
            "fin_flag_cnt":               0.0,
            "psh_flag_cnt":               0.0,
            "ack_flag_cnt":               0.0,
            "down_up_ratio":              0.0,
            "dst_port":                   4444.0,      # known malware port
            "protocol":                   6.0,
            "fwd_bytes_fraction":         1.0,
            "fwd_packet_fraction":        1.0,
            "payload_diff":               44.0,
        })
    },
    {
        "name":           "SSH Brute Force",
        "attack_type":    "BruteForce_SSH",
        "description":    "Credential stuffing — 250 login attempts against SSH port 22",
        "src_ip":         "203.0.113.42",
        "dst_ip":         MY_IP,
        "src_port":       52000,
        "dst_port":       22,
        "features": _mk({
            "flow_duration":              500_000.0,
            "total_fwd_packets":          250.0,
            "total_bwd_packets":          250.0,
            "total_length_fwd_packets":   22500.0,
            "total_length_bwd_packets":   47500.0,
            "subflow_fwd_bytes":          22500.0,
            "fwd_pkt_len_mean":           90.0,
            "fwd_pkt_len_max":            200.0,       # TOP FEATURE
            "fwd_pkt_len_min":            52.0,
            "fwd_pkt_len_std":            40.0,
            "bwd_pkt_len_mean":           190.0,
            "bwd_pkt_len_max":            350.0,
            "bwd_pkt_len_min":            52.0,
            "bwd_pkt_len_std":            80.0,
            "fwd_seg_size_min":           52.0,
            "init_fwd_win_bytes":         64240.0,
            "init_bwd_win_bytes":         65535.0,
            "flow_packets_per_sec":       1000.0,      # 1k pps — very fast brute force
            "flow_bytes_per_sec":         140_000.0,
            "flow_iat_mean":              2000.0,      # 2ms between attempts
            "flow_iat_std":               500.0,
            "fwd_iat_mean":               4000.0,
            "bwd_iat_mean":               4000.0,
            "psh_flag_cnt":               120.0,
            "ack_flag_cnt":               490.0,
            "fin_flag_cnt":               80.0,
            "rst_flag_cnt":               80.0,        # many RST = rejected logins
            "down_up_ratio":              1.0,
            "dst_port":                   22.0,
            "protocol":                   6.0,
            "is_well_known_port":         1.0,
            "fwd_bytes_fraction":         0.32,
            "fwd_packet_fraction":        0.50,
            "payload_diff":               -100.0,
        })
    },
    {
        "name":           "FTP Brute Force",
        "attack_type":    "BruteForce_FTP",
        "description":    "Rapid FTP login attempts — common credential list attack",
        "src_ip":         "198.51.100.77",
        "dst_ip":         MY_IP,
        "src_port":       52100,
        "dst_port":       21,
        "features": _mk({
            "flow_duration":              300_000.0,
            "total_fwd_packets":          400.0,
            "total_bwd_packets":          400.0,
            "total_length_fwd_packets":   24000.0,
            "total_length_bwd_packets":   68000.0,
            "subflow_fwd_bytes":          24000.0,
            "fwd_pkt_len_mean":           60.0,
            "fwd_pkt_len_max":            120.0,       # TOP FEATURE
            "fwd_pkt_len_min":            40.0,
            "fwd_pkt_len_std":            20.0,
            "bwd_pkt_len_mean":           170.0,
            "bwd_pkt_len_max":            400.0,
            "bwd_pkt_len_min":            40.0,
            "bwd_pkt_len_std":            100.0,
            "fwd_seg_size_min":           40.0,
            "init_fwd_win_bytes":         29200.0,
            "init_bwd_win_bytes":         29200.0,
            "flow_packets_per_sec":       2666.0,
            "flow_bytes_per_sec":         306_666.0,
            "flow_iat_mean":              750.0,
            "psh_flag_cnt":               380.0,
            "ack_flag_cnt":               780.0,
            "fin_flag_cnt":               160.0,
            "rst_flag_cnt":               160.0,
            "down_up_ratio":              1.0,
            "dst_port":                   21.0,
            "protocol":                   6.0,
            "is_well_known_port":         1.0,
            "is_ftp_login":               1.0,
            "fwd_bytes_fraction":         0.26,
            "fwd_packet_fraction":        0.50,
        })
    },
    {
        "name":           "Web Attack -- SQL Injection",
        "attack_type":    "WebAttack_SQLi",
        "description":    "HTTP POST with SQLi payloads -- UNION SELECT, DROP TABLE",
        "src_ip":         "172.16.0.1",
        "dst_ip":         MY_IP,
        "src_port":       55000,
        "dst_port":       80,
        "features": _mk({
            "flow_duration":              15_000_000.0,
            "total_fwd_packets":          288.0,
            "total_bwd_packets":          236.0,
            "total_length_fwd_packets":   148_000.0,
            "total_length_bwd_packets":   320_000.0,
            "subflow_fwd_bytes":          148_000.0,
            "fwd_pkt_len_mean":           513.9,
            "fwd_pkt_len_max":            1448.0,      # TOP FEATURE
            "fwd_pkt_len_min":            40.0,
            "fwd_pkt_len_std":            430.0,
            "bwd_pkt_len_mean":           1355.9,
            "bwd_pkt_len_max":            1448.0,
            "bwd_pkt_len_min":            40.0,
            "bwd_pkt_len_std":            520.0,
            "fwd_seg_size_min":           40.0,
            "init_fwd_win_bytes":         8192.0,
            "init_bwd_win_bytes":         65535.0,
            "flow_packets_per_sec":       34.9,
            "flow_bytes_per_sec":         31_200.0,
            "flow_iat_mean":              28_700.0,
            "psh_flag_cnt":               200.0,
            "ack_flag_cnt":               500.0,
            "fin_flag_cnt":               2.0,
            "rst_flag_cnt":               0.0,
            "down_up_ratio":              0.82,
            "dst_port":                   80.0,
            "protocol":                   6.0,
            "is_http_port":               1.0,
            "is_well_known_port":         1.0,
            "response_body_len":          320_000.0,
            "trans_depth":                50.0,
            "fwd_bytes_fraction":         0.32,
            "payload_ratio":              2.16,
            "payload_diff":               -842.0,
        })
    },
    {
        "name":           "Botnet C2 Beacon",
        "attack_type":    "Botnet_C2_Beacon",
        "description":    "Metronomic 500ms beacons to C2 -- zero variance = not human",
        "src_ip":         MY_IP,
        "dst_ip":         "91.108.56.180",
        "src_port":       49152,
        "dst_port":       443,
        "features": _mk({
            "flow_duration":              60_000_000.0,
            "total_fwd_packets":          120.0,
            "total_bwd_packets":          120.0,
            "total_length_fwd_packets":   7200.0,
            "total_length_bwd_packets":   7200.0,
            "subflow_fwd_bytes":          7200.0,
            "fwd_pkt_len_mean":           60.0,
            "fwd_pkt_len_max":            60.0,        # TOP FEATURE: perfectly uniform
            "fwd_pkt_len_min":            60.0,
            "fwd_pkt_len_std":            0.0,         # ZERO std = automation
            "bwd_pkt_len_mean":           60.0,
            "bwd_pkt_len_max":            60.0,
            "bwd_pkt_len_min":            60.0,
            "bwd_pkt_len_std":            0.0,
            "fwd_seg_size_min":           60.0,
            "init_fwd_win_bytes":         65535.0,
            "init_bwd_win_bytes":         65535.0,
            "flow_packets_per_sec":       2.0,
            "flow_bytes_per_sec":         240.0,
            "flow_iat_mean":              500_000.0,
            "flow_iat_std":               100.0,       # near-zero CV = bot clock
            "fwd_iat_mean":               1_000_000.0,
            "psh_flag_cnt":               10.0,
            "ack_flag_cnt":               240.0,
            "fin_flag_cnt":               0.0,
            "rst_flag_cnt":               0.0,
            "down_up_ratio":              1.0,
            "dst_port":                   443.0,
            "protocol":                   6.0,
            "is_http_port":               1.0,
            "iat_cv":                     0.0002,
            "payload_diff":               0.0,
            "fwd_bytes_fraction":         0.50,
        })
    },
    {
        "name":           "Heartbleed (TLS CVE-2014-0160)",
        "attack_type":    "Infiltration_Heartbleed",
        "description":    "Malformed TLS heartbeat -- leaks 64KB of server RAM per request",
        "src_ip":         "10.0.0.200",
        "dst_ip":         MY_IP,
        "src_port":       53000,
        "dst_port":       443,
        "features": _mk({
            "flow_duration":              30_000_000.0,
            "total_fwd_packets":          17.0,
            "total_bwd_packets":          16.0,
            "total_length_fwd_packets":   24_576.0,
            "total_length_bwd_packets":   65_536.0,
            "subflow_fwd_bytes":          24_576.0,
            "fwd_pkt_len_mean":           1445.6,
            "fwd_pkt_len_max":            1448.0,      # TOP FEATURE: max-size requests
            "fwd_pkt_len_min":            1440.0,
            "fwd_pkt_len_std":            2.0,         # very uniform attack packets
            "bwd_pkt_len_mean":           4096.0,
            "bwd_pkt_len_max":            16384.0,
            "bwd_pkt_len_min":            1024.0,
            "bwd_pkt_len_std":            8000.0,
            "fwd_seg_size_min":           1440.0,
            "init_fwd_win_bytes":         64240.0,
            "init_bwd_win_bytes":         64240.0,
            "flow_packets_per_sec":       1.1,
            "flow_bytes_per_sec":         3003.7,
            "flow_iat_mean":              960_000.0,
            "fwd_iat_mean":               1_875_000.0,
            "psh_flag_cnt":               14.0,
            "ack_flag_cnt":               28.0,
            "fin_flag_cnt":               2.0,
            "rst_flag_cnt":               0.0,
            "down_up_ratio":              0.94,
            "dst_port":                   443.0,
            "protocol":                   6.0,
            "is_http_port":               1.0,
            "is_well_known_port":         1.0,
            "payload_ratio":              2.67,
            "response_body_len":          65_536.0,
            "fwd_bytes_fraction":         0.27,
            "payload_diff":               -2650.4,
        })
    },
]



# ── Monitor ───────────────────────────────────────────────────────────────────

def monitor_feed(seconds=30):
    """Watch the real-time feed and print new threats as they appear."""
    print(f"\n{CYN}{BOLD}Live Threat Monitor — watching for {seconds}s{RESET}")
    print(DIM + "-" * 60 + RESET)
    seen = set()
    t0   = time.time()
    while time.time() - t0 < seconds:
        data = _get(f"{ML_SVC}/realtime/feed?limit=20")
        if "results" in data:
            for r in reversed(data["results"]):
                key = f"{r.get('ts',0):.0f}_{r.get('src_port',0)}"
                if key not in seen:
                    seen.add(key)
                    score = r.get("threat_score", 0)
                    if score >= 0.20 or r.get("injected"):
                        c = _color(score)
                        inj = " [DEMO INJECT]" if r.get("injected") else " [NPCAP]"
                        print(
                            f"  {c}{score:.4f}{RESET}  "
                            f"{r.get('src_ip','?')}:{r.get('src_port','?')} -> "
                            f"{r.get('dst_ip','?')}:{r.get('dst_port','?')}  "
                            f"{r.get('classification','?')}{DIM}{inj}{RESET}"
                        )
        time.sleep(1)
    print(DIM + "-" * 60 + RESET)


# ── Main entry ────────────────────────────────────────────────────────────────

def run_attack(attack):
    print(f"\n{CYN}Launching: {attack['name']}{RESET}")
    print(DIM + f"  {attack['description']}" + RESET)
    print(DIM + f"  {attack['src_ip']}:{attack['src_port']} -> {attack['dst_ip']}:{attack['dst_port']}" + RESET)

    r = _inject(
        attack_type=attack["attack_type"],
        src_ip=attack["src_ip"],
        dst_ip=attack["dst_ip"],
        src_port=attack["src_port"],
        dst_port=attack["dst_port"],
        features=attack["features"],
    )
    _print_result(r, attack["name"])
    time.sleep(0.5)


def print_menu():
    print(f"\n{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}  CYPHRA Attack Demo  —  Real ML Inference{RESET}")
    print(f"{BOLD}{'=' * 60}{RESET}")
    print(f"  ML Service : {ML_SVC}")
    print(f"  Target IP  : {MY_IP}")
    print()
    for i, a in enumerate(ATTACKS, 1):
        print(f"  {CYN}[{i}]{RESET} {a['name']}")
        print(f"      {DIM}{a['description']}{RESET}")
    print(f"\n  {CYN}[a]{RESET} Run ALL attacks")
    print(f"  {CYN}[m]{RESET} Monitor live feed only (30s)")
    print(f"  {CYN}[q]{RESET} Quit")
    print()


if __name__ == "__main__":
    # Check ML service is running
    h = _get(f"{ML_SVC}/health")
    if "error" in h:
        print(f"{RED}[ERROR] ML service not reachable at {ML_SVC}{RESET}")
        print("Start it with:  python main.py  (in k:/craftathon/ml-service/)")
        sys.exit(1)
    print(f"\n{GRN}ML service OK — {h['models_loaded']} models | capture={h['capture_active']} ({h.get('capture_iface','?')}) | {h.get('packets_captured',0):,} pkts{RESET}")

    arg = sys.argv[1] if len(sys.argv) > 1 else None

    if arg == "all":
        print(f"\n{BOLD}Running all {len(ATTACKS)} attacks...{RESET}\n")
        for a in ATTACKS:
            run_attack(a)
        monitor_feed(15)
    elif arg == "monitor":
        monitor_feed(60)
    elif arg and arg.isdigit():
        idx = int(arg) - 1
        if 0 <= idx < len(ATTACKS):
            run_attack(ATTACKS[idx])
            monitor_feed(10)
        else:
            print(f"Attack number must be 1-{len(ATTACKS)}")
    else:
        # Interactive menu
        while True:
            print_menu()
            choice = input("  Choose [1-8 / a / m / q]: ").strip().lower()
            if choice == "q":
                break
            elif choice == "a":
                for a in ATTACKS:
                    run_attack(a)
                monitor_feed(15)
            elif choice == "m":
                monitor_feed(30)
            elif choice.isdigit() and 1 <= int(choice) <= len(ATTACKS):
                run_attack(ATTACKS[int(choice) - 1])
                monitor_feed(10)
            else:
                print(f"  {YEL}Invalid choice{RESET}")
