# DNS Tunneling Detection

Transport-aware DNS tunneling detection for classic DNS (UDP/TCP) and DNS-over-HTTPS (DoH).

<img width="1919" height="1035" alt="Image" src="https://github.com/user-attachments/assets/184a1eb0-6e05-4089-b5a2-9d635e87907f" />

## Quick Start

```bash
git clone https://github.com/v-o-h-s/dns-tunneling-detection-with-lm && cd c1-dns-tunneling
bash scripts/setup_env.sh
bash scripts/run_replay_demo.sh
```

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
