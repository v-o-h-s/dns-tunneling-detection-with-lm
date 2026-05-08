# DNS Tunneling Detection

Transport-aware DNS tunneling detection for classic DNS over UDP/TCP and DNS-over-HTTPS (DoH). The project includes trained model artifacts, a live/replay terminal UI, packet-to-flow feature extraction, and notebooks/scripts for reproducing the models.

## What This Project Does

The monitor watches DNS traffic, groups packets into short flows, extracts model features, routes each flow to the right detector, and shows alerts in a SOC-style terminal UI.

| Transport | Traffic | Model artifact |
|---|---|---|
| `UDP53` | Classic DNS over UDP/53 | `artifacts/classic_dns/best_model.pkl` |
| `TCP53` | Classic DNS over TCP/53 | `artifacts/classic_dns/best_model.pkl` |
| `DOH` | HTTPS flows to known DoH resolvers on TCP/443 | `artifacts/doh/xgboost.pkl` |

If a required artifact is missing, the TUI shows `Unsupported model` instead of producing a placeholder prediction.

## Repository Structure

```text
.
├── artifacts/
│   ├── classic_dns/          # Classic DNS model, features, metrics, metadata
│   └── doh/                  # DoH model, scaler, label encoder, metrics
├── datasets/                 # Generated datasets, not committed when large
├── notebooks/
│   ├── classic_dns_detector.ipynb
│   └── doh_detector.ipynb
├── pipeline/
│   ├── tui.py                # Live/replay transport-aware monitor
│   ├── create_demo_pcap.py   # Builds the reliable replay demo PCAP
│   ├── extract_classic_dns_pcaps.py
│   ├── train_classic_dns_detector.py
│   └── enhance_classic_dns_datasets.py
├── samples/
│   └── demo_dns_mix.pcap     # Small replay PCAP for class demos
├── scripts/
│   ├── setup_env.sh
│   └── run_replay_demo.sh
└── report/
    ├── report.tex
    └── report.pdf
```

## Quick Start

From a fresh clone:

```bash
git clone <your-repo-url>
cd c1-dns-tunneling

bash scripts/setup_env.sh
bash scripts/run_replay_demo.sh
```

That installs dependencies, verifies the model artifacts, regenerates the sample replay PCAP if needed, and starts the TUI in replay mode.

Manual setup:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python pipeline/create_demo_pcap.py
python pipeline/tui.py --mode replay --pcap samples/demo_dns_mix.pcap
```

## Running The TUI

### Replay Mode

Replay mode is the recommended class-demo path because it does not require packet-capture permissions and always produces UDP53, TCP53, and DoH examples.

```bash
.venv/bin/python pipeline/tui.py --mode replay --pcap samples/demo_dns_mix.pcap
```1

Expected replay output includes:

- benign UDP DNS
- malicious UDP DNS
- benign TCP DNS
- malicious TCP DNS
- benign DoH
- malicious DoH

### Live Mode

Live capture requires permission to sniff packets.

```bash
sudo .venv/bin/python pipeline/tui.py --mode live --iface <interface>
```

Examples:

```bash
sudo .venv/bin/python pipeline/tui.py --mode live --iface wlan0
sudo .venv/bin/python pipeline/tui.py --mode live --iface eth0
```

To generate normal DNS traffic during a demo:

```bash
dig example.com
dig github.com
dig +tcp cloudflare.com
```

### Auto Mode

Auto mode tries live capture first and falls back to the replay PCAP if live capture fails or no DNS/DoH packets are observed.

```bash
.venv/bin/python pipeline/tui.py
```

## TUI Options

```text
--mode auto|live|replay
--iface <interface>
--pcap samples/demo_dns_mix.pcap
--artifacts-root artifacts
--window-seconds 10
--flush-seconds 1
--malicious-threshold 0.70
--enable-doh / --no-doh
```

The default malicious announcement threshold is `0.70`. The model probability is still shown in the details panel, but the row label becomes `Malicious` only when the probability is at least 70%.

Example with a stricter threshold:

```bash
.venv/bin/python pipeline/tui.py --mode replay --malicious-threshold 0.80
```

## TUI Controls

| Key | Action |
|---|---|
| `c` | Clear alerts |
| `q` | Quit |
| Arrow keys / click | Select an alert row |

Selecting a row opens the flow detail panel with transport, source/destination, query name, model status, malicious probability, threshold, and high-signal features.

## How The TUI Works

1. Packet source starts in `live`, `replay`, or `auto` mode.
2. Scapy parses UDP/53, TCP/53, and known DoH resolver TCP/443 packets.
3. Packets are grouped into short flows, defaulting to 10-second windows.
4. The flow extractor builds transport-specific feature rows.
5. The model registry routes:
   - `UDP53` and `TCP53` to `artifacts/classic_dns/`
   - `DOH` to `artifacts/doh/`
6. The model returns a malicious probability.
7. The TUI applies the alert threshold and displays the result.

## Model Artifacts

The project uses two deployed model folders:

```text
artifacts/classic_dns/
├── best_model.pkl
├── feature_names.csv
├── model_metadata.json
├── model_metrics.csv
├── threshold_analysis.csv
└── ...

artifacts/doh/
├── xgboost.pkl
├── scaler.pkl
├── label_encoder.pkl
├── feature_names.csv
├── model_metadata.json
└── model_metrics.csv
```

Classic DNS training compares Random Forest, XGBoost, and Logistic Regression. The current classic DNS artifact selects Random Forest as `best_model.pkl`. DoH uses the XGBoost artifact exported from the DoH notebook.

## Rebuilding Classic DNS Artifacts

If `datasets/classic_dns_from_pcaps.csv` already exists:

```bash
.venv/bin/python pipeline/train_classic_dns_detector.py \
  --dataset datasets/classic_dns_from_pcaps.csv \
  --output-dir artifacts/classic_dns
```

To regenerate the classic DNS CSV from the external PCAP dataset:

```bash
.venv/bin/python pipeline/extract_classic_dns_pcaps.py \
  --dataset-root DNS-Tunnel-Datasets \
  --output datasets/classic_dns_from_pcaps.csv
```

The extracted CSV can be large, so it is ignored by Git. Keep large datasets outside Git or use Git LFS if your course requires publishing them.

## Rebuilding DoH Artifacts

Open and run:

```bash
jupyter notebook notebooks/doh_detector.ipynb
```

The DoH notebook trains and exports:

- `artifacts/doh/xgboost.pkl`
- `artifacts/doh/scaler.pkl`
- `artifacts/doh/label_encoder.pkl`
- `artifacts/doh/feature_names.csv`

## Regenerating The Demo PCAP

```bash
.venv/bin/python pipeline/create_demo_pcap.py
```

This writes `samples/demo_dns_mix.pcap`, which contains UDP53, TCP53, and DoH-like flows for reliable replay demos.

## Report

The written report is in:

```text
report/report.pdf
```

To rebuild it:

```bash
chromium --headless --disable-gpu --no-sandbox --no-pdf-header-footer \
  --print-to-pdf=report/report.pdf \
  file://$(pwd)/report/report.html
```

A LaTeX source version is also kept at `report/report.tex` for editing or export with a working TeX installation.

## Troubleshooting

### `Permission denied` in live mode

Use replay mode for demos, or run live mode with packet-capture permissions:

```bash
sudo .venv/bin/python pipeline/tui.py --mode live --iface <interface>
```

### `Unsupported model`

Check that the relevant artifact folder exists:

```bash
ls artifacts/classic_dns
ls artifacts/doh
```

### Dataset not found in a notebook

Start Jupyter from the project root:

```bash
jupyter notebook
```

The classic notebook also auto-detects the project root, so restart the kernel and run from the first cell if old variables are still in memory.

## Demo Script

For class, the simplest script is:

```bash
bash scripts/run_replay_demo.sh
```

Then explain:

> The TUI reads packets, aggregates them into DNS flows, extracts transport-specific features, routes UDP/TCP DNS to the classic DNS model and DoH to the DoH model, then shows the model confidence and high-signal features for each alert.
