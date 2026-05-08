# DNS Tunneling Detection

Transport-aware DNS tunneling detection for classic DNS (UDP/TCP) and DNS-over-HTTPS (DoH).

<img width="1919" height="1035" alt="Image" src="https://github.com/user-attachments/assets/184a1eb0-6e05-4089-b5a2-9d635e87907f" />

## Quick Start

```bash
git clone https://github.com/v-o-h-s/dns-tunneling-detection-with-lm && cd c1-dns-tunneling
bash scripts/setup_env.sh
bash scripts/run_replay_demo.sh
```

## Train the Classifier

### Classic DNS (UDP53 / TCP53)

```bash
.venv/bin/python pipeline/train_classic_dns_detector.py
```

Auto-downloads the 250 MB dataset from Google Drive (cached to `/tmp`), trains three models (Random Forest, XGBoost, Logistic Regression), and exports the best one to `artifacts/classic_dns/best_model.pkl`.

### DNS-over-HTTPS (DoH)

```bash
.venv/bin/jupyter nbconvert --to notebook --execute notebooks/doh_detector.ipynb --output artifacts/doh/
```

Downloads the BCCC-CIRA-CIC-DoHBrw-2020 dataset (500K rows) from Kaggle, trains RF / XGBoost / LR on 28 statistical flow features, and exports `best_model.pkl` + `scaler.pkl` to `artifacts/doh/`.

## Running the TUI

### Replay mode (no root)

```bash
.venv/bin/python pipeline/tui.py --mode replay --pcap samples/demo_dns_mix.pcap
```

### Live mode (needs root)

```bash
sudo .venv/bin/python pipeline/tui.py --mode live --iface wlan0
sudo .venv/bin/python pipeline/tui.py --mode live --iface eth0
```

### Auto mode (live first, falls back to replay)

```bash
.venv/bin/python pipeline/tui.py
```

### Custom threshold

```bash
.venv/bin/python pipeline/tui.py --mode replay --malicious-threshold 0.85
```

### Without DoH detection

```bash
.venv/bin/python pipeline/tui.py --mode replay --no-doh
```

### Full options

```
--mode auto|live|replay
--iface <interface>
--pcap samples/demo_dns_mix.pcap
--malicious-threshold 0.70
--window-seconds 10
--flush-seconds 1
--enable-doh / --no-doh
```

## Generate Demo PCAP

```bash
.venv/bin/python pipeline/create_demo_pcap.py
```

Creates `samples/demo_dns_mix.pcap` with benign and malicious UDP53, TCP53, and DoH flows.
