#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-.venv/bin/python}"

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Could not find $PYTHON_BIN. Run: bash scripts/setup_env.sh"
  exit 1
fi

if [[ ! -f "samples/demo_dns_mix.pcap" ]]; then
  "$PYTHON_BIN" pipeline/create_demo_pcap.py
fi

"$PYTHON_BIN" pipeline/tui.py \
  --mode replay \
  --pcap samples/demo_dns_mix.pcap \
  --malicious-threshold 0.70
