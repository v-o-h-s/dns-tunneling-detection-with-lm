# DNS Tunneling Detection

Detect DNS tunneling attacks using an XGBoost model trained on the BCCC-CIRA-CIC-DoHBrw-2020 dataset. 28 statistical flow features → 99.99% F1.

<img width="1919" height="1035" alt="Image" src="https://github.com/user-attachments/assets/184a1eb0-6e05-4089-b5a2-9d635e87907f" />

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Generate Model Artifacts

Before running the TUI, you need the trained model files. There are two ways:

1. **Manually (recommended)** — open `cns_c1.ipynb` in Jupyter and run all cells. This trains XGBoost and saves the artifacts.

2. **Headless** — run the notebook from the command line:
   ```bash
   jupyter nbconvert --to notebook --execute --inplace cns_c1.ipynb
   ```

Either way creates `artifacts/` with `xgboost.pkl`, `scaler.pkl`, and `label_encoder.pkl`.

## Run

```bash
source .venv/bin/activate
.venv/bin/python pipeline/tui.py
```

## Controls

| Key | Action |
|-----|--------|
| `b` | Generate 1 benign flow |
| `m` | Generate 1 malicious flow |
| `c` | Clear alerts |
| `q` | Quit |
| Tab | Navigate buttons |
| ↑↓  | Navigate alerts |

Click any alert row to see DNS query details + all 28 features.


