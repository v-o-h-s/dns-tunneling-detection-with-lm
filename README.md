# DNS Tunneling Detection

Transport-aware DNS tunneling detection for classic DNS (UDP/TCP) and DNS-over-HTTPS (DoH). Includes trained models, a SOC-style terminal UI, and a replay demo PCAP.

## Quick Start

```bash
git clone <repo-url> && cd c1-dns-tunneling
bash scripts/setup_env.sh      # Creates venv, installs deps, generates demo PCAP
bash scripts/run_replay_demo.sh # Starts the TUI in replay mode
```

Controls: `q` = quit, `c` = clear alerts, arrow keys = select row for flow details.

---

## Manual Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Using the Demo PCAP

Generate a synthetic replay PCAP with benign and malicious UDP53, TCP53, and DoH flows:

```bash
.venv/bin/python pipeline/create_demo_pcap.py
```

This creates `samples/demo_dns_mix.pcap`. No arguments — it builds a fixed set of packets including:

| Traffic | Count | Type |
|---|---|---|
| UDP53 | 3 | Benign queries (example.com, python.org, github.com) |
| UDP53 | 5 | Malicious tunnel-like queries with hex-encoded subdomains |
| TCP53 | 3 | Benign queries (mozilla.org, wikipedia.org, cloudflare.com) |
| TCP53 | 3 | Malicious queries with beacon/upload/chunk patterns |
| DoH | 2 | Known-DoH-resolver HTTPS flows (benign-size and large exfil patterns) |

---

## Running the TUI

### Replay Mode (no root required)

Replays packets from a PCAP file through the detection pipeline:

```bash
.venv/bin/python pipeline/tui.py --mode replay --pcap samples/demo_dns_mix.pcap
```

### Live Mode (requires root)

Captures DNS and DoH traffic from a network interface in real time:

```bash
sudo .venv/bin/python pipeline/tui.py --mode live --iface wlan0
sudo .venv/bin/python pipeline/tui.py --mode live --iface eth0
```

Generate test traffic on another terminal while live mode is running:

```bash
dig example.com
dig github.com
dig +tcp cloudflare.com
```

### Auto Mode (default)

Tries live capture first. Falls back to replay if live fails or no DNS/DoH packets appear within 5 seconds:

```bash
.venv/bin/python pipeline/tui.py
```

---

## TUI Options

```
--mode auto|live|replay        Source mode (default: auto)
--iface <interface>            Interface for live capture (e.g. wlan0, eth0)
--pcap <path>                  PCAP file for replay (default: samples/demo_dns_mix.pcap)
--artifacts-root <path>        Model artifacts directory (default: artifacts)
--window-seconds <float>       Flow aggregation window in seconds (default: 10)
--flush-seconds <float>        Polling interval for draining completed flows (default: 1)
--malicious-threshold <float>  Minimum probability to flag as malicious (default: 0.70)
--enable-doh / --no-doh        Enable/disable DoH detection (default: enabled)
```

Example — stricter threshold:

```bash
.venv/bin/python pipeline/tui.py --mode replay --malicious-threshold 0.85
```

---

## How Detection Works

1. Packets are parsed via Scapy (UDP/53, TCP/53, and known DoH resolver TCP/443)
2. Packets are grouped into short flows (10-second windows by default)
3. Transport-specific features are extracted per flow:
   - **UDP53/TCP53** — lexical features (entropy, hex ratio, label length), query rate, TXT/NULL records, TCP segment stats
   - **DOH** — packet length/timing statistics, flow byte rates, response time distributions
4. Model routing:
   - UDP53/TCP53 flows → `artifacts/classic_dns/best_model.pkl` (RandomForest)
   - DoH flows → `artifacts/doh/xgboost.pkl` (XGBoost + scaler)
5. If a model artifact is missing, flows show `Unsupported model`

---

## TUI Layout

```
+----------------+--------------------------------------------+
| DNS TUNNEL     |  Source: replay: samples/demo_dns_mix.pcap  |
| MONITOR        |  Flows: 24  Benign: 12  Malicious: 10       |
|                |  Unsupported: 2  Alert Rate: 41.7%          |
| Mode: replay   +--------------------------------------------+
| Iface: N/A     |  ALERTS - select row for details            |
| PCAP: demo...  |  Time  | Transport | Src | Dst | Label     |
|                |  12:00 | UDP53     | ... | ... | Malicious |
| Models:        |  12:01 | TCP53     | ... | ... | Benign    |
| UDP53: Ready   |  ...                                       |
| TCP53: Ready   +--------------------------------------------+
| DOH: Ready     |  FLOW DETAIL                               |
|                |  Transport: UDP53                          |
| Keys:          |  Query: a1b2c3d4.tunnel.attacker.test      |
| c = clear      |  Label: Malicious  Threat: CRITICAL        |
| q = quit       |  Confidence: 94.2%                         |
|                |  HIGH-SIGNAL FEATURES                      |
|                |  query_entropy              3.892          |
|                |  hex_ratio                   0.914          |
|                +--------------------------------------------+
|                |  Log messages...                           |
+----------------+--------------------------------------------+
```

---

## Pipeline Scripts

| Script | Purpose |
|---|---|
| `create_demo_pcap.py` | Generate `samples/demo_dns_mix.pcap` for replay demos |
| `extract_classic_dns_pcaps.py` | Extract labeled feature rows from raw PCAPs into a training CSV |
| `enhance_classic_dns_datasets.py` | Add synthetic calibration rows to the training CSV |
| `train_classic_dns_detector.py` | Train and export the classic DNS model artifacts |
| `tui.py` | **Main entry point** — replays or live-captures traffic and shows alerts |

### Rebuilding Classic DNS Artifacts

If `datasets/classic_dns_from_pcaps.csv` already exists:

```bash
.venv/bin/python pipeline/train_classic_dns_detector.py \
  --dataset datasets/classic_dns_from_pcaps.csv \
  --output-dir artifacts/classic_dns
```

To extract from scratch (requires `DNS-Tunnel-Datasets/` clone):

```bash
.venv/bin/python pipeline/extract_classic_dns_pcaps.py \
  --dataset-root DNS-Tunnel-Datasets \
  --output datasets/classic_dns_from_pcaps.csv
```

The extracted CSV is large and git-ignored.

### Rebuilding DoH Artifacts

Open and run the notebook:

```bash
jupyter notebook notebooks/doh_detector.ipynb
```

This exports `xgboost.pkl`, `scaler.pkl`, `label_encoder.pkl`, and `feature_names.csv` to `artifacts/doh/`.

---

## Troubleshooting

**`Permission denied` in live mode** — use `sudo`:

```bash
sudo .venv/bin/python pipeline/tui.py --mode live --iface wlan0
```

**`Unsupported model` in TUI** — missing artifact. Check:

```bash
ls artifacts/classic_dns/best_model.pkl
ls artifacts/doh/xgboost.pkl
```

Re-run training or notebook to regenerate.

**`No module named scapy`** — run `bash scripts/setup_env.sh` to install all dependencies.

---

## Repository Structure

```text
.
├── artifacts/
│   ├── classic_dns/          # RandomForest model, features, metrics
│   └── doh/                  # XGBoost model, scaler, label encoder
├── notebooks/                # Jupyter notebooks for DoH + classic DNS
├── pipeline/                 # Python scripts (see table above)
├── report/                   # Project report (PDF + LaTeX source)
├── samples/
│   └── demo_dns_mix.pcap     # Replay PCAP for demos
├── scripts/
│   ├── setup_env.sh          # One-command environment setup
│   └── run_replay_demo.sh    # One-command demo launcher
├── requirements.txt
└── README.md
```
