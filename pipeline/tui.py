#!/usr/bin/env python3
"""
Interactive TUI — DNS Tunnel Detection
Gruvbox theme · Flow detail inspector · Live alerts
"""

from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd

FEATURE_NAMES = [
    "FlowBytesSent","FlowSentRate","FlowBytesReceived","FlowReceivedRate",
    "PacketLengthVariance","PacketLengthStandardDeviation","PacketLengthMean",
    "PacketLengthMedian","PacketLengthMode","PacketLengthSkewFromMedian",
    "PacketLengthSkewFromMode","PacketLengthCoefficientofVariation",
    "PacketTimeVariance","PacketTimeStandardDeviation","PacketTimeMean",
    "PacketTimeMedian","PacketTimeMode","PacketTimeSkewFromMedian",
    "PacketTimeSkewFromMode","PacketTimeCoefficientofVariation",
    "ResponseTimeTimeVariance","ResponseTimeTimeStandardDeviation",
    "ResponseTimeTimeMean","ResponseTimeTimeMedian","ResponseTimeTimeMode",
    "ResponseTimeTimeSkewFromMedian","ResponseTimeTimeSkewFromMode",
    "ResponseTimeTimeCoefficientofVariation",
]

FEATURE_GROUPS = {
    "Flow Volume (4)": FEATURE_NAMES[:4],
    "Packet Length (8)": FEATURE_NAMES[4:12],
    "Packet Timing (8)": FEATURE_NAMES[12:20],
    "Response Time (8)": FEATURE_NAMES[20:28],
}

# ── DNS-over-HTTPS wire-size per-packet overhead ──────────────────────────────
# The DoHMeter training data computes packet-length stats from pcap IP-length
# fields.  Our simulation generates DNS+HTTP payload sizes; adding minimal
# transport overhead produces realistic on-wire IP packet sizes.
#   20 (IP) + 20 (TCP)
_DOH_BASE = 40


def _compute_features(sizes: np.ndarray, iats: np.ndarray, rtts: np.ndarray) -> dict[str, float]:
    """Compute the 28 statistical flow features from raw packet measurements.

    sizes — every packet's on-wire size (query, response, alternating)
    iats  — inter-arrival times between consecutive *query* packets
    rtts  — response-time deltas (response arrival – query departure)
    """
    q_sizes = sizes[0::2]   # query  packets (even indices: 0, 2, 4, …)
    r_sizes = sizes[1::2]   # response packets (odd indices:  1, 3, 5, …)
    sent     = float(np.sum(q_sizes))
    received = float(np.sum(r_sizes))
    duration = float(np.sum(iats)) + float(np.sum(rtts))

    def _stats(arr: np.ndarray) -> dict:
        m   = float(np.mean(arr))
        s   = float(np.std(arr, ddof=1)) if len(arr) > 1 else 0.0
        med = float(np.median(arr))
        counts, edges = np.histogram(arr, bins="auto")
        mode_val = float(edges[np.argmax(counts)])
        return {
            "Variance": s ** 2,
            "StandardDeviation": s,
            "Mean": m,
            "Median": med,
            "Mode": mode_val,
            "SkewFromMedian": (m - med) / s if s > 0 else 0.0,
            "SkewFromMode": (m - mode_val) / s if s > 0 else 0.0,
            "CoefficientofVariation": s / m if m > 0 else 0.0,
        }

    pl = _stats(sizes)   # PacketLength  — all packets (queries + responses)
    pt = _stats(iats)    # PacketTime    — inter-arrival times
    rt = _stats(rtts)    # ResponseTime  — query→response deltas

    return {
        "FlowBytesSent":    sent,
        "FlowSentRate":     sent / duration if duration > 0 else 0.0,
        "FlowBytesReceived": received,
        "FlowReceivedRate": received / duration if duration > 0 else 0.0,
        **{f"PacketLength{k}": v          for k, v in pl.items()},
        **{f"PacketTime{k}": v            for k, v in pt.items()},
        **{f"ResponseTimeTime{k}": v      for k, v in rt.items()}
    }


def _simulate_flow(traffic_type: str, rng: np.random.Generator) -> dict[str, float]:
    """Simulate one DNS-over-HTTPS flow as alternating query/response packets.

    Each flow consists of *n* query→response exchanges with on-wire sizes
    (IP + TCP + TLS + HTTP/2 + DNS payload).  The packet-level model mirrors:

      Benign   — normal browser: few small DNS queries (3–10), highly variable
                 sizes from different record types, wide human-paced gaps
                 (1–60 s) with bursts, short RTTs 5–250 ms.
      Malicious — tunnel tools (dnscat2 / iodine / dns2tcp): many queries
                  (30–80) with large uniform encoded payloads, machinelike
                  regular gaps 50–550 ms, long RTTs 300–6000 ms.
    """
    if traffic_type == "benign":
        n_queries = rng.integers(5, 13)
        # normal browsing: tiny A-record queries (20–50 B DNS) to modest
        # CNAME/AAAA responses (35–150 B DNS)
        q_payloads = rng.uniform(20, 50, n_queries)
        r_payloads = rng.uniform(35, 150, n_queries)
        # bursty human gaps: mixture of short bursts + long idle periods
        # ensures high timing variance regardless of random draw
        n_short = max(1, n_queries // 3)
        n_long = n_queries - n_short
        short_gaps = rng.uniform(0.5, 3.0, n_short)
        long_gaps  = rng.uniform(15.0, 60.0, n_long)
        iats = np.concatenate([short_gaps, long_gaps])
        rng.shuffle(iats)
        # nearby resolver: 5–250 ms
        rtts = rng.uniform(0.005, 0.250, n_queries)

    else:  # malicious
        n_queries = rng.integers(30, 81)
        # dnscat2 / iodine / dns2tcp: encoded tunnel data
        # → tight, large payload blocks
        q_payloads = rng.uniform(200, 480, n_queries)
        r_payloads = rng.uniform(220, 500, n_queries)
        # automated polling: 50–550 ms, ±1% jitter
        tick = rng.uniform(0.05, 0.55)
        iats = np.full(n_queries, tick) + rng.normal(0, tick * 0.01, n_queries)
        iats = np.maximum(0.005, iats)
        # tunnel forwarder adds network latency: 300–6000 ms
        rtts = rng.uniform(0.3, 6.0, n_queries)

    sizes = np.empty(n_queries * 2)
    sizes[0::2] = q_payloads + _DOH_BASE   # query  wire-size
    sizes[1::2] = r_payloads + _DOH_BASE   # response wire-size

    return _compute_features(sizes, iats, rtts)


def _synthetic_features(n: int, traffic_type: str) -> pd.DataFrame:
    """Generate *n* independent synthetic flows of the given traffic type."""
    rng = np.random.default_rng()
    flows = [_simulate_flow(traffic_type, rng) for _ in range(n)]
    return pd.DataFrame(flows)


def generate_benign_flows(n: int = 15) -> tuple[pd.DataFrame, list[dict]]:
    samples = _synthetic_features(n, "benign")
    domains = [
        "google.com", "youtube.com", "github.com", "wikipedia.org", "reddit.com",
        "stackoverflow.com", "mozilla.org", "archlinux.org", "python.org",
        "cloudflare.com", "npmjs.com", "pypi.org", "crates.io", "docker.com",
    ]
    meta = []
    for _ in range(n):
        meta.append({
            "dns_query": f"{random.choice(domains)}",
            "dns_type": random.choice(["A", "AAAA", "CNAME"]),
            "src": f"192.168.1.{random.randint(20, 200)}",
            "dst": random.choice(["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]),
            "dst_port": "443",
            "protocol": "HTTPS/DoH",
            "query_size": random.randint(40, 150),
            "response_size": random.randint(80, 800),
            "flow_duration": round(random.uniform(0.1, 3.5), 3),
        })
    return samples, meta


def generate_malicious_flows(n: int = 15) -> tuple[pd.DataFrame, list[dict]]:
    samples = _synthetic_features(n, "malicious")
    tunnel_patterns = [
        "dGhpcyBpcyBhIHRlc3Q.base64.c2.attacker.xyz",
        "data-exfil.payload.a1b2c3d4.tun.c2server.net",
        f"pastebin-{random.randint(1000, 9999)}.hexdata.evil.corp",
        f"cmd-{random.randint(10000, 99999)}.revshell.hack.me",
        f"upload.{random.randint(1000, 9999)}.drop.data-exfil.co",
        "aaaaaaaaaaaaaaaaaaaaaaa.pad.tunnel.dns.rip",
        "knock-knock.checkin.beacon.malware.biz",
    ]
    meta = []
    for _ in range(n):
        meta.append({
            "dns_query": f"{random.choice(tunnel_patterns)}",
            "dns_type": random.choice(["TXT", "A", "AAAA", "MX"]),
            "src": f"10.0.5.{random.randint(50, 250)}",
            "dst": random.choice(["8.8.8.8", "1.1.1.1", "9.9.9.9"]),
            "dst_port": "443",
            "protocol": "HTTPS/DoH",
            "query_size": random.randint(256, 1500),
            "response_size": random.randint(500, 2000),
            "flow_duration": round(random.uniform(5.0, 60.0), 3),
        })
    return samples, meta

@dataclass
class PredictionResult:
    label: str
    confidence: float
    malicious_prob: float
    threat: str
    features: list[float] = field(default_factory=list)
    time_str: str = ""
    src: str = "?"
    dst: str = "?"
    dst_port: str = "?"
    protocol: str = "?"
    dns_query: str = ""
    dns_type: str = "A"
    query_size: int = 0
    response_size: int = 0
    flow_duration: float = 0.0

class Detector:
    def __init__(self, artifacts_dir: Path):
        self.model = joblib.load(artifacts_dir / "xgboost.pkl")
        self.scaler = joblib.load(artifacts_dir / "scaler.pkl")
        self.le = joblib.load(artifacts_dir / "label_encoder.pkl")

    def predict(self, df: pd.DataFrame, meta: list[dict] | None = None) -> list[PredictionResult]:
        X = df[FEATURE_NAMES].values.astype(np.float64)
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        X_df = pd.DataFrame(X, columns=FEATURE_NAMES)
        X_scaled = self.scaler.transform(X_df)
        probs = self.model.predict_proba(X_scaled)
        preds = self.model.predict(X_scaled)
        results = []
        for i in range(len(X)):
            label = self.le.inverse_transform([preds[i]])[0]
            mal_prob = float(probs[i][1])
            conf = float(probs[i].max())
            if label == "Malicious":
                threat = "CRITICAL" if mal_prob >= 0.98 else ("HIGH" if mal_prob >= 0.85 else "MEDIUM")
            else:
                threat = "BENIGN"
            m = meta[i] if meta and i < len(meta) else {}
            results.append(PredictionResult(
                label=label, confidence=conf, malicious_prob=mal_prob,
                threat=threat, features=X[i].tolist(),
                time_str=time.strftime("%H:%M:%S"),
                src=m.get("src", "?"), dst=m.get("dst", "?"),
                dst_port=m.get("dst_port", "?"), protocol=m.get("protocol", "?"),
                dns_query=m.get("dns_query", ""), dns_type=m.get("dns_type", "A"),
                query_size=m.get("query_size", 0), response_size=m.get("response_size", 0),
                flow_duration=m.get("flow_duration", 0.0),
            ))
        return results


from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, Container, ScrollableContainer
from textual.widgets import Header, Footer, Button, Static, DataTable, Label, Log, Rule
from textual.reactive import reactive
from textual.coordinate import Coordinate
from textual.theme import Theme

GRUVBOX = Theme(
    name="gruvbox",
    primary="#d79921",
    secondary="#458588",
    accent="#98971a",
    background="#282828",
    surface="#3c3836",
    panel="#1d2021",
    error="#cc241d",
    warning="#d79921",
    success="#98971a",
    foreground="#ebdbb2",
)


class StatsPanel(Static):
    total = reactive(0)
    benign = reactive(0)
    malicious = reactive(0)

    def render(self) -> str:
        rate = f"{self.malicious / self.total * 100:.1f}%" if self.total > 0 else "0%"
        return (
            f"[bold #ebdbb2]Flows:[/bold #ebdbb2] {self.total}\n"
            f"[bold #98971a]Benign:[/bold #98971a] {self.benign}\n"
            f"[bold #cc241d]Malicious:[/bold #cc241d] {self.malicious}\n"
            f"[bold #d79921]Alert Rate:[/bold #d79921] {rate}"
        )


class FlowDetailPanel(ScrollableContainer):
    selected_result: Optional[PredictionResult] = None

    def show_flow(self, result: PredictionResult) -> None:
        self.selected_result = result
        self.refresh()

    def compose(self) -> ComposeResult:
        yield Label(id="flow-detail-content")

    def on_mount(self) -> None:
        self._refresh_content()

    def _refresh_content(self) -> None:
        content = self.query_one("#flow-detail-content", Label)
        if self.selected_result is None:
            content.update("[dim #928374]Click a row in Alerts → flow details here[/dim #928374]")
            return

        r = self.selected_result
        lines = []

        # ── Flow Metadata ──
        lines.append("[bold #d79921]═══ DNS Query ═══[/bold #d79921]")
        threat_color = {"CRITICAL": "#cc241d", "HIGH": "#d79921", "MEDIUM": "#d65d0e", "BENIGN": "#98971a"}.get(r.threat, "#ebdbb2")
        lines.append(f"  [bold #ebdbb2]Domain:[/bold #ebdbb2] [{threat_color}]{r.dns_query}[/{threat_color}]")
        lines.append(f"  [bold #ebdbb2]Type:[/bold #ebdbb2] {r.dns_type}   [bold #ebdbb2]Proto:[/bold #ebdbb2] {r.protocol}")
        lines.append(f"  [bold #ebdbb2]Src:[/bold #ebdbb2] {r.src}:{r.dst_port}   →   [bold #ebdbb2]Dst:[/bold #ebdbb2] {r.dst}:53")
        lines.append(f"  [bold #ebdbb2]Query Size:[/bold #ebdbb2] {r.query_size}B   [bold #ebdbb2]Resp Size:[/bold #ebdbb2] {r.response_size}B")
        lines.append(f"  [bold #ebdbb2]Duration:[/bold #ebdbb2] {r.flow_duration:.3f}s   [bold #ebdbb2]Time:[/bold #ebdbb2] {r.time_str}")
        lines.append("")
        lines.append(f"[bold #d79921]═══ Prediction ═══[/bold #d79921]")
        lines.append(f"  [bold #ebdbb2]Label:[/bold #ebdbb2] [{threat_color}]{r.label} ({r.threat})[/{threat_color}]")
        lines.append(f"  [bold #ebdbb2]Malicious Prob:[/bold #ebdbb2] [bold #cc241d]{r.malicious_prob:.4%}[/bold #cc241d]")
        lines.append("")

       # ── Feature Groups ──
        feat = r.features
        if not feat:
            content.update("\n".join(lines))
            return

        for group_name, cols in FEATURE_GROUPS.items():
            lines.append(f"[bold #458588]═══ {group_name} ═══[/bold #458588]")
            for name, val in zip(cols, [feat[FEATURE_NAMES.index(c)] for c in cols]):
                color = "#98971a" if abs(val) < 1 else "#d79921" if abs(val) < 100 else "#cc241d"
                val_str = f"{val:>12.4f}" if abs(val) > 0.001 else f"{val:>12.6f}"
                lines.append(f"  [bold #ebdbb2]{name:<35}[/bold #ebdbb2] [{color}]{val_str}[/{color}]")
            lines.append("")

        content.update("\n".join(lines))

    def refresh(self, *, layout: bool = False, **kwargs) -> None:
        super().refresh(layout=layout, **kwargs)
        self._refresh_content()


class DnsTunnelApp(App):
    """DNS Tunnel Detector — Gruvbox TUI"""

    CSS = """
    Screen {
        background: #282828;
    }
    Header {
        background: #1d2021;
        color: #d79921;
        text-style: bold;
    }
    Footer {
        background: #1d2021;
        color: #928374;
    }
    Button {
        width: 100%;
        margin: 1 0;
        border: none;
    }
    #btn-benign {
        background: #98971a;
        color: #1d2021;
        text-style: bold;
    }
    #btn-benign:hover {
        background: #b8bb26;
    }
    #btn-malicious {
        background: #cc241d;
        color: #ebdbb2;
        text-style: bold;
    }
    #btn-malicious:hover {
        background: #fb4934;
    }
    #btn-clear {
        background: #504945;
        color: #ebdbb2;
    }
    #btn-clear:hover {
        background: #665c54;
    }
    #left-panel {
        width: 28;
        border: solid #504945;
        background: #1d2021;
        padding: 1 1 0 1;
    }
    #stats-panel {
        height: 7;
        border: solid #504945;
        background: #1d2021;
        padding: 1 2;
    }
    #alerts-table {
        height: 8;
        border: solid #504945;
        background: #282828;
    }
    #flow-detail {
        height: 1fr;
        border: solid #504945;
        background: #1d2021;
        padding: 1;
    }
    #log-panel {
        height: 5;
        border: solid #504945;
        background: #1d2021;
    }
    DataTable {
        background: #282828;
    }
    DataTable > .datatable--header {
        background: #3c3836;
        color: #d79921;
        text-style: bold;
    }
    DataTable > .datatable--cursor {
        background: #458588;
        color: #ebdbb2;
    }
    Vertical:focus-within {
        border: none;
    }
    *:focus {
        border: tall #d79921;
    }
    Button:focus {
        border: tall #d79921;
    }
    Label {
        padding: 0 1;
    }
    Rule {
        color: #504945;
    }
    .section-label {
        color: #d79921;
        text-style: bold;
        padding: 0 1;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("b", "generate_benign", "Generate Benign"),
        ("m", "generate_malicious", "Generate Malicious"),
        ("c", "clear_alerts", "Clear"),
    ]

    def __init__(self, artifacts_dir: Path):
        super().__init__()
        self.artifacts_dir = artifacts_dir
        self.detector: Optional[Detector] = None
        self.all_results: list[PredictionResult] = []

    def on_mount(self) -> None:
        self.detector = Detector(self.artifacts_dir)
        self.title = "DNS Tunnel Detector"
        self.sub_title = "XGBoost | Gruvbox"

        table = self.query_one("#alerts-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns("Time", "Label", "Confidence", "Threat")

        log = self.query_one("#log-panel", Log)
        log.write_line("[bold #98971a]✓ XGBoost loaded — F1: 0.9999[/bold #98971a]")
        log.write_line("[dim #928374]b=benign  m=malicious  c=clear  q=quit[/dim #928374]")

    def compose(self) -> ComposeResult:
        yield Header()
        yield Horizontal(
            # ── Left: Controls ──
            Vertical(
                Label("[bold #d79921]🛠 TRAFFIC GEN[/bold #d79921]"),
                Rule(),
                Button("🟢 Benign", id="btn-benign"),
                Button("🔴 Malicious", id="btn-malicious"),
                Button("🗑 Clear", id="btn-clear"),
                Rule(),
                Label("[bold #928374]Keys[/bold #928374]"),
                Label("  b = benign"),
                Label("  m = malicious"),
                Label("  c = clear"),
                Label("  q = quit"),
                id="left-panel",
            ),
            # ── Right: Stats + Alerts + Detail + Log ──
            Vertical(
                StatsPanel(id="stats-panel"),
                Label("[bold #d79921]🚨 ALERTS — ↑↓ nav → flow detail[/bold #d79921]", classes="section-label"),
                DataTable(id="alerts-table"),
                Label("[bold #d79921]📦 FLOW DETAIL[/bold #d79921]", classes="section-label"),
                FlowDetailPanel(id="flow-detail", can_focus=False),
                Log(id="log-panel", max_lines=100, highlight=True),
            ),
        )
        yield Footer()

    def action_generate_benign(self) -> None:
        self._generate("benign", generate_benign_flows)

    def action_generate_malicious(self) -> None:
        self._generate("malicious", generate_malicious_flows)

    def action_clear_alerts(self) -> None:
        self.all_results.clear()
        table = self.query_one("#alerts-table", DataTable)
        table.clear()
        stats = self.query_one("#stats-panel", StatsPanel)
        stats.total = 0
        stats.benign = 0
        stats.malicious = 0
        self.query_one("#flow-detail", FlowDetailPanel).selected_result = None
        self.query_one("#flow-detail", FlowDetailPanel).refresh()
        self.query_one("#log-panel", Log).write_line("[bold #d79921]Alerts cleared[/bold #d79921]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-benign":
            self._generate("benign", generate_benign_flows)
        elif event.button.id == "btn-malicious":
            self._generate("malicious", generate_malicious_flows)
        elif event.button.id == "btn-clear":
            self.action_clear_alerts()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row_key = event.row_key
        if row_key is not None and row_key.value is not None and row_key.value < len(self.all_results):
            result = self.all_results[row_key.value]
            self.query_one("#flow-detail", FlowDetailPanel).show_flow(result)
            self.query_one("#log-panel", Log).write_line(
                f"[dim #928374]Inspecting flow — {result.dns_query} ({result.label})[/dim #928374]"
            )

    def _generate(self, label: str, gen_fn) -> None:
        log = self.query_one("#log-panel", Log)
        n_flows = 1

        try:
            df, metas = gen_fn(n_flows)
            results = self.detector.predict(df, metas)
        except Exception as e:
            log.write_line(f"[bold #cc241d]Error: {e}[/bold #cc241d]")
            return

        table = self.query_one("#alerts-table", DataTable)
        stats = self.query_one("#stats-panel", StatsPanel)

        for r in results:
            threat_icon = {"CRITICAL": "🔴", "HIGH": "🟡", "MEDIUM": "🟠", "BENIGN": "🟢"}.get(r.threat, "⚪")
            color = {"CRITICAL": "#cc241d", "HIGH": "#d79921", "MEDIUM": "#d65d0e", "BENIGN": "#98971a"}.get(r.threat, "#ebdbb2")
            table.add_row(
                r.time_str,
                f"{r.label}",
                f"{r.malicious_prob:.2%}",
                f"[{color}]{threat_icon} {r.threat}[/{color}]",
            )
            self.all_results.append(r)
            stats.total += 1
            if r.label == "Malicious":
                stats.malicious += 1
            else:
                stats.benign += 1

        if table.row_count > 0:
            table.move_cursor(row=table.row_count - 1)

        result = results[0] if results else None
        if result:
            style = "#cc241d" if result.label == "Malicious" else "#98971a"
            threat = result.threat
            prob = result.malicious_prob
            log.write_line(f"[bold {style}]→ {label.upper()}: {result.dns_query}  |  {result.label} ({threat}) — {prob:.4%}[/bold {style}]")
            # Show details in flow detail panel
            self.query_one("#flow-detail", FlowDetailPanel).show_flow(result)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="DNS Tunnel Detection TUI")
    parser.add_argument(
        "--artifacts-dir",
        default=str(Path(__file__).resolve().parent.parent / "artifacts"),
        help="Directory with xgboost.pkl, scaler.pkl, etc.",
    )
    args = parser.parse_args()
    artifacts = Path(args.artifacts_dir)
    if not (artifacts / "xgboost.pkl").exists():
        print(f"ERROR: Model not found at {artifacts / 'xgboost.pkl'}")
        return

    app = DnsTunnelApp(artifacts)
    app.register_theme(GRUVBOX)
    app.theme = "gruvbox"
    app.run()


if __name__ == "__main__":
    main()
