#!/usr/bin/env python3
"""Add focused calibration rows to the unified classic DNS dataset."""

from __future__ import annotations

import argparse
import string
from pathlib import Path

import numpy as np
import pandas as pd


RANDOM_STATE = 42


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = pd.Series(list(text)).value_counts(normalize=True)
    return float(-(counts * np.log2(counts)).sum())


def _lexical(query: str) -> dict[str, float]:
    labels = [label for label in query.rstrip(".").split(".") if label]
    compact = "".join(labels).lower()
    consonants = set("bcdfghjklmnpqrstvwxyz")
    hex_chars = set("0123456789abcdef")
    total = max(len(compact), 1)
    return {
        "query_length": len(query),
        "query_entropy": _entropy(compact),
        "label_entropy": float(np.mean([_entropy(label.lower()) for label in labels])) if labels else 0.0,
        "subdomain_count": max(len(labels) - 2, 0),
        "max_label_length": max((len(label) for label in labels), default=0),
        "avg_label_length": float(np.mean([len(label) for label in labels])) if labels else 0.0,
        "unique_chars": len(set(compact)),
        "digit_ratio": sum(ch.isdigit() for ch in compact) / total,
        "consonant_ratio": sum(ch in consonants for ch in compact) / total,
        "hex_ratio": sum(ch in hex_chars for ch in compact) / total,
    }


def _base_row(query: str, label: int, transport: str, idx: int) -> dict[str, object]:
    row = {
        "source_file": f"calibration/{transport.lower()}/{label}/{idx}",
        "top_level": query.rstrip(".").split(".")[-1],
        "split_hint": "calibration",
        "transport": transport,
        "src_ip": f"192.0.2.{10 + idx % 200}",
        "dst_ip": "9.9.9.9",
        "timestamp": "2026-05-08 12:00:00",
        "query_name": query,
        "label": label,
        "response_length": 84,
        "payload_size": 140,
        "ttl": 300,
        "answer_count": 1,
        "additional_count": 0,
        "query_type": 1,
        "response_type": 1,
        "has_txt_record": 0,
        "has_null_record": 0,
        "inter_arrival_time": 10000.0,
        "query_rate": 0.10,
        "response_ratio": 0.50,
        "unique_domains": 1,
        "is_recursive": 1,
        "authoritative_flag": 0,
        "retransmission_count": 0,
        "truncated_flag": 0,
        "tcp_stream_id": 0,
        "segment_count": 0,
        "tcp_payload_size": 0,
        "window_size": 0,
        "tcp_flags": 0,
        "retransmission_ratio": 0.0,
        "dns_length_field": 0,
        "message_count": 1,
        "max_message_size": 84,
        "avg_message_size": 70.0,
        "rcode": 0,
    }
    row.update(_lexical(query))
    if transport == "TCP53":
        row.update(
            {
                "tcp_stream_id": 50000 + idx,
                "segment_count": 2,
                "tcp_payload_size": 160,
                "window_size": 32768,
                "tcp_flags": 24,
                "dns_length_field": 70,
                "message_count": 2,
            }
        )
    return row


def _benign_queries() -> list[str]:
    return [
        "ping.archlinux.org",
        "mirror.archlinux.org",
        "geo.mirror.pkgbuild.com",
        "pool.ntp.org",
        "api.github.com",
        "pypi.org",
        "security.ubuntu.com",
        "cdn.mozilla.net",
    ]


def _malicious_query(rng: np.random.Generator, idx: int) -> str:
    alphabet = string.ascii_lowercase + string.digits
    token = "".join(rng.choice(list(alphabet), size=int(rng.integers(42, 64))))
    stage = rng.choice(["upload", "chunk", "beacon", "session", "data"])
    return f"{stage}-{idx:04d}-{token}.tunnel.attacker.test"


def calibration_rows(rows_per_class: int) -> pd.DataFrame:
    rng = np.random.default_rng(RANDOM_STATE)
    rows = []
    benign = _benign_queries()
    for transport in ["UDP53", "TCP53"]:
        for idx in range(rows_per_class):
            query = benign[idx % len(benign)]
            rows.append(_base_row(query, 0, transport, idx))
        for idx in range(rows_per_class):
            row = _base_row(_malicious_query(rng, idx), 1, transport, idx)
            row.update(
                {
                    "response_length": int(rng.integers(40, 180)),
                    "payload_size": int(rng.integers(260, 760)),
                    "ttl": int(rng.integers(20, 900)),
                    "answer_count": int(rng.integers(0, 2)),
                    "query_type": 16,
                    "response_type": 16,
                    "has_txt_record": 1,
                    "inter_arrival_time": float(rng.uniform(40.0, 320.0)),
                    "query_rate": float(rng.uniform(8.0, 35.0)),
                    "unique_domains": int(rng.integers(1, 8)),
                }
            )
            if transport == "TCP53":
                row.update(
                    {
                        "segment_count": int(rng.integers(6, 32)),
                        "tcp_payload_size": int(rng.integers(500, 2600)),
                        "retransmission_ratio": float(rng.uniform(0.02, 0.16)),
                        "dns_length_field": int(rng.integers(120, 520)),
                        "message_count": int(rng.integers(5, 24)),
                    }
                )
            rows.append(row)
    return pd.DataFrame(rows)


def enhance_dataset(input_path: Path, output_path: Path, rows_per_class: int) -> None:
    df = pd.read_csv(input_path)
    additions = calibration_rows(rows_per_class)
    for column in df.columns:
        if column not in additions.columns:
            additions[column] = 0
    combined = pd.concat([df, additions.reindex(columns=df.columns, fill_value=0)], ignore_index=True)
    combined = combined.drop_duplicates()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(output_path, index=False)
    print(f"Wrote {len(combined)} rows to {output_path}")
    print(f"Added up to {len(additions)} calibration rows before de-duplication")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("datasets/classic_dns_from_pcaps.csv"))
    parser.add_argument("--output", type=Path, default=Path("datasets/classic_dns_from_pcaps.csv"))
    parser.add_argument("--rows-per-class", type=int, default=600)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    enhance_dataset(args.input, args.output, args.rows_per_class)


if __name__ == "__main__":
    main()
