#!/usr/bin/env python3
"""Extract classic DNS UDP/TCP ML features from DNS-Tunnel-Datasets PCAPs."""

from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd
from scapy.all import DNS, IP, Raw, TCP, UDP, PcapReader


TRAIN_LABELS = {
    "normal": 0,
    "tunnel": 1,
}
ROBUSTNESS_LABELS = {
    "unkownTunnel": 1,
    "unknownTunnel": 1,
    "crossEndPoint": 1,
    "wildcard": 0,
}


@dataclass
class PendingQuery:
    ts: float
    src_ip: str
    dst_ip: str
    sport: int
    dport: int
    query_name: str
    query_type: int
    query_length: int
    payload_size: int
    dns_size: int
    is_recursive: int
    truncated_flag: int
    transport: str
    tcp_stream_id: int
    tcp_flags: int
    window_size: int
    source_file: str
    top_level: str
    label: int
    split_hint: str


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {char: text.count(char) for char in set(text)}
    total = len(text)
    return float(-sum((count / total) * math.log2(count / total) for count in counts.values()))


def safe_decode(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore").rstrip(".")
    return str(value).rstrip(".")


def lexical_features(query_name: str) -> dict[str, float | int]:
    labels = [label for label in query_name.split(".") if label]
    compact = "".join(labels)
    total = len(compact)
    consonants = set("bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ")
    hex_chars = set("0123456789abcdefABCDEF")
    return {
        "query_length": len(query_name),
        "query_entropy": entropy(compact),
        "label_entropy": float(sum(entropy(label) for label in labels) / len(labels)) if labels else 0.0,
        "subdomain_count": max(len(labels) - 2, 0),
        "max_label_length": max((len(label) for label in labels), default=0),
        "avg_label_length": float(sum(len(label) for label in labels) / len(labels)) if labels else 0.0,
        "unique_chars": len(set(compact)),
        "digit_ratio": sum(char.isdigit() for char in compact) / total if total else 0.0,
        "consonant_ratio": sum(char in consonants for char in compact) / total if total else 0.0,
        "hex_ratio": sum(char in hex_chars for char in compact) / total if total else 0.0,
    }


def pcap_label(path: Path, dataset_root: Path, include_robustness: bool) -> tuple[int | None, str, str]:
    rel = path.relative_to(dataset_root)
    top_level = rel.parts[0]
    if top_level in TRAIN_LABELS:
        return TRAIN_LABELS[top_level], top_level, "train"
    if include_robustness and top_level in ROBUSTNESS_LABELS:
        return ROBUSTNESS_LABELS[top_level], top_level, "robustness"
    return None, top_level, "ignored"


def packet_dns_payload(packet) -> tuple[str, DNS | None, bytes | None, int, int, int, int, int, int, int]:
    if IP not in packet:
        return "", None, None, 0, 0, 0, 0, 0, 0, 0

    if UDP in packet and (packet[UDP].sport == 53 or packet[UDP].dport == 53) and DNS in packet:
        return (
            "UDP53",
            packet[DNS],
            bytes(packet[DNS]),
            int(packet[UDP].sport),
            int(packet[UDP].dport),
            0,
            0,
            0,
            0,
            len(packet[UDP].payload),
        )

    if TCP in packet and (packet[TCP].sport == 53 or packet[TCP].dport == 53) and Raw in packet:
        raw = bytes(packet[Raw].load)
        if len(raw) < 3:
            return "", None, None, 0, 0, 0, 0, 0, 0, 0
        dns_len = int.from_bytes(raw[:2], "big")
        payload = raw[2 : 2 + dns_len]
        if not payload:
            return "", None, None, 0, 0, 0, 0, 0, 0, 0
        try:
            dns = DNS(payload)
        except Exception:
            return "", None, None, 0, 0, 0, 0, 0, 0, 0
        return (
            "TCP53",
            dns,
            payload,
            int(packet[TCP].sport),
            int(packet[TCP].dport),
            int(packet[TCP].flags),
            int(packet[TCP].window),
            int(packet[TCP].seq),
            dns_len,
            len(raw),
        )

    return "", None, None, 0, 0, 0, 0, 0, 0, 0


def answer_stats(dns: DNS) -> dict[str, int]:
    ttl_values: list[int] = []
    has_txt = 0
    has_null = 0
    response_type = 0
    for idx in range(int(dns.ancount or 0)):
        try:
            rr = dns.an[idx]
        except Exception:
            continue
        rr_type = int(getattr(rr, "type", 0) or 0)
        response_type = response_type or rr_type
        has_txt = int(has_txt or rr_type == 16)
        has_null = int(has_null or rr_type == 10)
        ttl = int(getattr(rr, "ttl", 0) or 0)
        if ttl:
            ttl_values.append(ttl)
    return {
        "ttl": int(sum(ttl_values) / len(ttl_values)) if ttl_values else 0,
        "answer_count": int(dns.ancount or 0),
        "additional_count": int(dns.arcount or 0),
        "response_type": response_type,
        "has_txt_record": has_txt,
        "has_null_record": has_null,
        "rcode": int(dns.rcode or 0),
        "authoritative_flag": int(dns.aa or 0),
    }


def query_key(dns_id: int, client: str, resolver: str, sport: int, transport: str) -> tuple[Any, ...]:
    return dns_id, client, resolver, sport, transport


def pending_to_row(query: PendingQuery, response_dns: DNS | None, response_size: int, response_ts: float | None) -> dict[str, Any]:
    stats = answer_stats(response_dns) if response_dns else {
        "ttl": 0,
        "answer_count": 0,
        "additional_count": 0,
        "response_type": 0,
        "has_txt_record": 0,
        "has_null_record": 0,
        "rcode": -1,
        "authoritative_flag": 0,
    }
    lex = lexical_features(query.query_name)
    response_time = max(float(response_ts - query.ts), 0.0) if response_ts is not None else 0.0
    payload_size = query.payload_size + response_size
    row = {
        "source_file": query.source_file,
        "top_level": query.top_level,
        "split_hint": query.split_hint,
        "label": query.label,
        "transport": query.transport,
        "transport_code": 1 if query.transport == "TCP53" else 0,
        "src_ip": query.src_ip,
        "dst_ip": query.dst_ip,
        "timestamp": pd.to_datetime(query.ts, unit="s", errors="coerce"),
        "dns_id": 0,
        "query_name": query.query_name,
        "query_type": query.query_type,
        "response_type": stats["response_type"],
        "query_length": lex["query_length"],
        "response_length": response_size,
        "payload_size": payload_size,
        "ttl": stats["ttl"],
        "answer_count": stats["answer_count"],
        "additional_count": stats["additional_count"],
        "has_txt_record": int(stats["has_txt_record"] or query.query_type == 16),
        "has_null_record": int(stats["has_null_record"] or query.query_type == 10),
        "is_recursive": query.is_recursive,
        "truncated_flag": query.truncated_flag,
        "authoritative_flag": stats["authoritative_flag"],
        "rcode": stats["rcode"],
        "response_time": response_time,
        "response_ratio": response_size / query.dns_size if query.dns_size else 0.0,
        "tcp_stream_id": query.tcp_stream_id,
        "segment_count": 1 if query.transport == "TCP53" else 0,
        "tcp_payload_size": payload_size if query.transport == "TCP53" else 0,
        "window_size": query.window_size,
        "tcp_flags": query.tcp_flags,
        "dns_length_field": query.dns_size if query.transport == "TCP53" else 0,
        "message_count": 1,
        "avg_message_size": payload_size,
        "max_message_size": max(query.payload_size, response_size),
        **lex,
    }
    return row


def extract_pcap(
    path: Path,
    dataset_root: Path,
    include_robustness: bool,
    max_packets: int | None,
    progress_every: int,
) -> list[dict[str, Any]]:
    label, top_level, split_hint = pcap_label(path, dataset_root, include_robustness)
    if label is None:
        return []

    rows: list[dict[str, Any]] = []
    pending: dict[tuple[Any, ...], PendingQuery] = {}
    source_file = str(path.relative_to(dataset_root))
    packet_count = 0

    try:
        reader = PcapReader(str(path))
    except Exception:
        return []

    with reader:
        for packet in reader:
            packet_count += 1
            if progress_every and packet_count % progress_every == 0:
                print(
                    f"    packets={packet_count:,} rows={len(rows):,} pending={len(pending):,}",
                    flush=True,
                )
            if max_packets and packet_count > max_packets:
                break
            transport, dns, payload, sport, dport, tcp_flags, window_size, seq, dns_len, packet_payload_size = packet_dns_payload(packet)
            if not transport or dns is None or payload is None or IP not in packet:
                continue

            ip = packet[IP]
            ts = float(packet.time)
            dns_id = int(dns.id or 0)
            is_response = int(dns.qr or 0) == 1

            if not is_response:
                if not dns.qd:
                    continue
                qname = safe_decode(dns.qd.qname)
                qtype = int(dns.qd.qtype or 0)
                key = query_key(dns_id, str(ip.src), str(ip.dst), sport, transport)
                pending[key] = PendingQuery(
                    ts=ts,
                    src_ip=str(ip.src),
                    dst_ip=str(ip.dst),
                    sport=sport,
                    dport=dport,
                    query_name=qname,
                    query_type=qtype,
                    query_length=len(qname),
                    payload_size=packet_payload_size,
                    dns_size=len(payload),
                    is_recursive=int(dns.rd or 0),
                    truncated_flag=int(dns.tc or 0),
                    transport=transport,
                    tcp_stream_id=seq,
                    tcp_flags=tcp_flags,
                    window_size=window_size,
                    source_file=source_file,
                    top_level=top_level,
                    label=label,
                    split_hint=split_hint,
                )
            else:
                key = query_key(dns_id, str(ip.dst), str(ip.src), dport, transport)
                query = pending.pop(key, None)
                if query is None and dns.qd:
                    qname = safe_decode(dns.qd.qname)
                    qtype = int(dns.qd.qtype or 0)
                    query = PendingQuery(
                        ts=ts,
                        src_ip=str(ip.dst),
                        dst_ip=str(ip.src),
                        sport=dport,
                        dport=sport,
                        query_name=qname,
                        query_type=qtype,
                        query_length=len(qname),
                        payload_size=0,
                        dns_size=len(payload),
                        is_recursive=int(dns.rd or 0),
                        truncated_flag=int(dns.tc or 0),
                        transport=transport,
                        tcp_stream_id=seq,
                        tcp_flags=tcp_flags,
                        window_size=window_size,
                        source_file=source_file,
                        top_level=top_level,
                        label=label,
                        split_hint=split_hint,
                    )
                if query is not None:
                    rows.append(pending_to_row(query, dns, len(payload), ts))

    rows.extend(pending_to_row(query, None, 0, None) for query in pending.values())
    return rows


def add_context_features(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.sort_values(["source_file", "src_ip", "timestamp"])

    group = df.groupby(["source_file", "src_ip"], dropna=False)
    df["inter_arrival_time"] = group["timestamp"].diff().dt.total_seconds().fillna(0.0)
    df["query_rate"] = 1.0 / df["inter_arrival_time"].replace(0, float("nan")).astype("float64")
    df["query_rate"] = df["query_rate"].fillna(0.0).clip(upper=1000.0)
    df["unique_domains"] = group["query_name"].transform("nunique")
    df["retransmission_count"] = group["dns_id"].transform(lambda values: max(len(values) - len(set(values)), 0))
    df["retransmission_ratio"] = df["retransmission_count"] / group["dns_id"].transform("count").replace(0, 1)
    df["timestamp_hour"] = df["timestamp"].dt.hour.fillna(-1).astype(int)
    df["timestamp_dayofweek"] = df["timestamp"].dt.dayofweek.fillna(-1).astype(int)
    df["timestamp"] = df["timestamp"].astype(str)
    return df


def discover_pcaps(dataset_root: Path) -> list[Path]:
    return sorted(dataset_root.rglob("*.pcap"))


def limit_per_top_level(pcaps: list[Path], dataset_root: Path, max_files_per_top_level: int | None) -> list[Path]:
    if not max_files_per_top_level:
        return pcaps
    counts: dict[str, int] = defaultdict(int)
    selected = []
    for pcap in pcaps:
        top_level = pcap.relative_to(dataset_root).parts[0]
        if counts[top_level] >= max_files_per_top_level:
            continue
        selected.append(pcap)
        counts[top_level] += 1
    return selected


def extract_dataset(
    dataset_root: Path,
    output: Path,
    include_robustness: bool,
    limit_files: int | None,
    max_packets_per_file: int | None,
    progress_every: int,
    max_files_per_top_level: int | None,
) -> dict[str, Any]:
    if output.exists() and output.is_dir():
        raise IsADirectoryError(f"--output must be a CSV file path, not a directory: {output}")
    if output.suffix.lower() != ".csv":
        raise ValueError(f"--output must end with .csv: {output}")

    dataset_root = dataset_root.resolve()
    all_pcaps = discover_pcaps(dataset_root)
    pcaps = [
        pcap
        for pcap in all_pcaps
        if pcap_label(pcap, dataset_root, include_robustness)[0] is not None
    ]
    pcaps = limit_per_top_level(pcaps, dataset_root, max_files_per_top_level)
    if limit_files:
        pcaps = pcaps[:limit_files]

    print(
        f"Selected {len(pcaps)} PCAPs from {len(all_pcaps)} total files "
        f"(include_robustness={include_robustness})",
        flush=True,
    )

    rows: list[dict[str, Any]] = []
    file_summaries = []
    for index, pcap in enumerate(pcaps, start=1):
        rel_path = pcap.relative_to(dataset_root)
        print(f"[{index}/{len(pcaps)}] extracting {rel_path} ...", flush=True)
        extracted = extract_pcap(
            pcap,
            dataset_root,
            include_robustness,
            max_packets_per_file,
            progress_every,
        )
        if extracted:
            rows.extend(extracted)
            file_summaries.append({"file": str(pcap.relative_to(dataset_root)), "rows": len(extracted)})
        print(
            f"[{index}/{len(pcaps)}] rows in file={len(extracted)} total_rows={len(rows)}",
            flush=True,
        )

    df = add_context_features(pd.DataFrame(rows))
    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False)

    summary = {
        "dataset_root": str(dataset_root),
        "output": str(output),
        "pcap_files_seen": len(pcaps),
        "pcap_files_with_rows": len(file_summaries),
        "rows": int(len(df)),
        "label_counts": df["label"].value_counts().sort_index().to_dict() if not df.empty else {},
        "transport_counts": df["transport"].value_counts().to_dict() if not df.empty else {},
        "top_level_counts": df["top_level"].value_counts().to_dict() if not df.empty else {},
        "include_robustness": include_robustness,
    }
    output.with_suffix(".profile.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", type=Path, default=Path("DNS-Tunnel-Datasets"), help="Path to DNS-Tunnel-Datasets clone (default: DNS-Tunnel-Datasets)")
    parser.add_argument("--output", type=Path, default=Path("datasets/classic_dns_from_pcaps.csv"))
    parser.add_argument("--include-robustness", action="store_true", help="Also extract unknownTunnel/crossEndPoint/wildcard rows")
    parser.add_argument("--limit-files", type=int, default=None, help="Debug limit for number of PCAP files")
    parser.add_argument("--max-packets-per-file", type=int, default=None, help="Debug limit for packets read per PCAP")
    parser.add_argument("--progress-every", type=int, default=50000, help="Print packet progress every N packets per PCAP; 0 disables")
    parser.add_argument(
        "--max-files-per-top-level",
        type=int,
        default=None,
        help="Use at most N PCAPs from each top-level dataset folder (normal, tunnel, etc.).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    summary = extract_dataset(
        dataset_root=args.dataset_root,
        output=args.output,
        include_robustness=args.include_robustness,
        limit_files=args.limit_files,
        max_packets_per_file=args.max_packets_per_file,
        progress_every=args.progress_every,
        max_files_per_top_level=args.max_files_per_top_level,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
