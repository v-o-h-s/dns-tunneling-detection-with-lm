#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -d ".venv" ]]; then
  python3 -m venv .venv
fi

.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt

if [[ ! -f "samples/demo_dns_mix.pcap" ]]; then
  .venv/bin/python pipeline/create_demo_pcap.py
fi

.venv/bin/python - <<'PY'
from pathlib import Path

required = [
    Path("artifacts/classic_dns/best_model.pkl"),
    Path("artifacts/classic_dns/feature_names.csv"),
    Path("artifacts/doh/xgboost.pkl"),
    Path("artifacts/doh/scaler.pkl"),
    Path("artifacts/doh/label_encoder.pkl"),
    Path("artifacts/doh/feature_names.csv"),
    Path("samples/demo_dns_mix.pcap"),
]
missing = [str(path) for path in required if not path.exists()]
if missing:
    print("Setup finished, but these files are missing:")
    for path in missing:
        print(f"  - {path}")
    print("Replay mode will mark missing model folders as Unsupported model.")
else:
    print("Setup complete. Replay demo is ready.")
PY

echo
echo "Run the demo with:"
echo "  bash scripts/run_replay_demo.sh"
