#!/usr/bin/env python3
"""Transport-aware DNS tunneling monitor with live capture and replay fallback."""

from __future__ import annotations

import argparse
import math
import multiprocessing
import queue
import statistics
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

import joblib
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pipeline import train_classic_dns_detector  # noqa: E402

try:  # Scapy is required for live/replay capture, but keep import errors readable.
    from scapy.all import DNS, IP, Raw, TCP, UDP, rdpcap, sniff

    SCAPY_AVAILABLE = True
except Exception as exc:  # pragma: no cover - exercised when scapy is missing.
    DNS = DNSQR = DNSRR = IP = Raw = TCP = UDP = None
    rdpcap = sniff = wrpcap = None
    SCAPY_AVAILABLE = False
    SCAPY_IMPORT_ERROR = exc
else:
    SCAPY_IMPORT_ERROR = None

from textual.app import App, ComposeResult
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.reactive import reactive
from textual.theme import Theme
from textual.widgets import DataTable, Footer, Header, Label, Log, Rule, Static


THEME = {
    "bg": "#0b1120",
    "panel": "#111827",
    "panel_alt": "#172033",
    "surface": "#1f2937",
    "border": "#334155",
    "border_focus": "#38bdf8",
    "text": "#e5e7eb",
    "muted": "#94a3b8",
    "dim": "#64748b",
    "accent": "#38bdf8",
    "accent_2": "#60a5fa",
    "benign": "#22c55e",
    "warning": "#f59e0b",
    "medium": "#f97316",
    "critical": "#ef4444",
    "unsupported": "#a78bfa",
    "udp": "#38bdf8",
    "tcp": "#60a5fa",
    "doh": "#a78bfa",
}

SOC_DARK = Theme(
    name="soc_dark",
    primary=THEME["accent"],
    secondary=THEME["accent_2"],
    accent=THEME["doh"],
    background=THEME["bg"],
    surface=THEME["surface"],
    panel=THEME["panel"],
    error=THEME["critical"],
    warning=THEME["warning"],
    success=THEME["benign"],
    foreground=THEME["text"],
)

SEVERITY_STYLE = {
    "BENIGN": THEME["benign"],
    "MEDIUM": THEME["medium"],
    "HIGH": THEME["warning"],
    "CRITICAL": THEME["critical"],
    "UNSUPPORTED": THEME["unsupported"],
}
TRANSPORT_STYLE = {
    "UDP53": THEME["udp"],
    "TCP53": THEME["tcp"],
    "DOH": THEME["doh"],
}

DEFAULT_MALICIOUS_THRESHOLD = 0.70

DOH_RESOLVERS = {
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "94.140.14.14",
    "94.140.15.15",
}

DOH_FEATURE_NAMES = [
    "FlowBytesSent",
    "FlowSentRate",
    "FlowBytesReceived",
    "FlowReceivedRate",
    "PacketLengthVariance",
    "PacketLengthStandardDeviation",
    "PacketLengthMean",
    "PacketLengthMedian",
    "PacketLengthMode",
    "PacketLengthSkewFromMedian",
    "PacketLengthSkewFromMode",
    "PacketLengthCoefficientofVariation",
    "PacketTimeVariance",
    "PacketTimeStandardDeviation",
    "PacketTimeMean",
    "PacketTimeMedian",
    "PacketTimeMode",
    "PacketTimeSkewFromMedian",
    "PacketTimeSkewFromMode",
    "PacketTimeCoefficientofVariation",
    "ResponseTimeTimeVariance",
    "ResponseTimeTimeStandardDeviation",
    "ResponseTimeTimeMean",
    "ResponseTimeTimeMedian",
    "ResponseTimeTimeMode",
    "ResponseTimeTimeSkewFromMedian",
    "ResponseTimeTimeSkewFromMode",
    "ResponseTimeTimeCoefficientofVariation",
]

BASE_DNS_COLUMNS = {
    "src_ip": "",
    "dst_ip": "",
    "timestamp": "",
    "query_length": 0,
    "response_length": 0,
    "payload_size": 0,
    "ttl": 0,
    "answer_count": 0,
    "additional_count": 0,
    "query_type": 0,
    "response_type": 0,
    "has_txt_record": 0,
    "has_null_record": 0,
    "query_entropy": 0.0,
    "label_entropy": 0.0,
    "subdomain_count": 0,
    "max_label_length": 0,
    "avg_label_length": 0.0,
    "unique_chars": 0,
    "digit_ratio": 0.0,
    "consonant_ratio": 0.0,
    "hex_ratio": 0.0,
    "inter_arrival_time": 0.0,
    "query_rate": 0.0,
    "response_ratio": 0.0,
    "unique_domains": 0,
    "is_recursive": 1,
    "authoritative_flag": 0,
}

UDP_DEFAULTS = {
    **BASE_DNS_COLUMNS,
    "retransmission_count": 0,
    "truncated_flag": 0,
}

TCP_DEFAULTS = {
    **BASE_DNS_COLUMNS,
    "tcp_stream_id": 0,
    "segment_count": 0,
    "tcp_payload_size": 0,
    "window_size": 0,
    "tcp_flags": 0,
    "retransmission_ratio": 0.0,
    "dns_length_field": 0,
    "message_count": 0,
    "avg_message_size": 0,
    "max_message_size": 0,
}


@dataclass(frozen=True)
class FlowKey:
    transport: str
    src: str
    dst: str
    sport: int
    dport: int


@dataclass
class FlowState:
    key: FlowKey
    first_ts: float
    last_ts: float
    packet_times: list[float] = field(default_factory=list)
    packet_sizes: list[int] = field(default_factory=list)
    client_times: list[float] = field(default_factory=list)
    server_times: list[float] = field(default_factory=list)
    client_sizes: list[int] = field(default_factory=list)
    server_sizes: list[int] = field(default_factory=list)
    query_names: list[str] = field(default_factory=list)
    query_types: list[int] = field(default_factory=list)
    response_types: list[int] = field(default_factory=list)
    dns_message_sizes: list[int] = field(default_factory=list)
    query_dns_sizes: list[int] = field(default_factory=list)
    response_dns_sizes: list[int] = field(default_factory=list)
    ttls: list[int] = field(default_factory=list)
    answer_counts: list[int] = field(default_factory=list)
    additional_counts: list[int] = field(default_factory=list)
    recursive_flags: list[int] = field(default_factory=list)
    authoritative_flags: list[int] = field(default_factory=list)
    truncated_flags: list[int] = field(default_factory=list)
    rcodes: list[int] = field(default_factory=list)
    tcp_windows: list[int] = field(default_factory=list)
    tcp_flags: list[int] = field(default_factory=list)
    tcp_payload_sizes: list[int] = field(default_factory=list)
    tcp_sequences: list[int] = field(default_factory=list)
    dns_length_fields: list[int] = field(default_factory=list)


@dataclass
class FlowRecord:
    transport: str
    src: str
    dst: str
    sport: int
    dport: int
    start_ts: float
    end_ts: float
    dns_query: str
    dns_type: str
    raw_features: pd.DataFrame
    model_features: pd.DataFrame
    feature_values: dict[str, float]
    meta: dict[str, object]


@dataclass
class PredictionResult:
    transport: str
    label: str
    confidence: float
    malicious_prob: float
    threat: str
    model_status: str
    time_str: str
    src: str
    dst: str
    sport: int
    dport: int
    dns_query: str
    dns_type: str
    flow_duration: float
    packet_count: int
    feature_values: dict[str, float] = field(default_factory=dict)
    meta: dict[str, object] = field(default_factory=dict)


def _decode_name(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip(".")
    return str(value).rstrip(".")


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return float(-sum((count / total) * math.log2(count / total) for count in counts.values()))


def _ratio(count: int, total: int) -> float:
    return float(count / total) if total else 0.0


def _mode(values: Iterable[int | float], default: int = 0) -> int:
    values = list(values)
    if not values:
        return default
    return int(Counter(int(v) for v in values).most_common(1)[0][0])


def _mean(values: Iterable[int | float], default: float = 0.0) -> float:
    values = list(values)
    return float(statistics.fmean(values)) if values else default


def _safe_duration(first_ts: float, last_ts: float) -> float:
    return max(float(last_ts - first_ts), 0.001)


def _numeric_stats(values: Iterable[int | float]) -> dict[str, float]:
    arr = np.asarray(list(values), dtype=float)
    if arr.size == 0:
        arr = np.asarray([0.0], dtype=float)
    mean = float(np.mean(arr))
    std = float(np.std(arr, ddof=1)) if arr.size > 1 else 0.0
    median = float(np.median(arr))
    rounded = np.round(arr, 6)
    mode = float(Counter(rounded.tolist()).most_common(1)[0][0])
    return {
        "Variance": std**2,
        "StandardDeviation": std,
        "Mean": mean,
        "Median": median,
        "Mode": mode,
        "SkewFromMedian": (mean - median) / std if std > 0 else 0.0,
        "SkewFromMode": (mean - mode) / std if std > 0 else 0.0,
        "CoefficientofVariation": std / mean if mean > 0 else 0.0,
    }


def _lexical_features(query: str) -> dict[str, float]:
    labels = [label for label in query.split(".") if label]
    compact = "".join(labels)
    length = len(query)
    max_label = max((len(label) for label in labels), default=0)
    avg_label = _mean([len(label) for label in labels])
    consonants = set("bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ")
    hex_chars = set("0123456789abcdefABCDEF")
    return {
        "query_length": length,
        "query_entropy": _entropy(compact),
        "label_entropy": _mean([_entropy(label) for label in labels]),
        "subdomain_count": max(len(labels) - 2, 0),
        "max_label_length": max_label,
        "avg_label_length": avg_label,
        "unique_chars": len(set(compact)),
        "digit_ratio": _ratio(sum(ch.isdigit() for ch in compact), len(compact)),
        "consonant_ratio": _ratio(sum(ch in consonants for ch in compact), len(compact)),
        "hex_ratio": _ratio(sum(ch in hex_chars for ch in compact), len(compact)),
    }


def _dns_type_name(value: int) -> str:
    return {
        1: "A",
        2: "NS",
        5: "CNAME",
        10: "NULL",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
    }.get(int(value or 0), str(int(value or 0)))


def _dns_messages(packet) -> list:
    if DNS is None:
        return []
    if packet.haslayer(DNS):
        return [packet[DNS]]
    if TCP is None or Raw is None or not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return []
    tcp = packet[TCP]
    if tcp.sport != 53 and tcp.dport != 53:
        return []
    data = bytes(packet[Raw].load)
    messages = []
    offset = 0
    while offset + 2 <= len(data):
        length = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        if length <= 0 or offset + length > len(data):
            break
        try:
            messages.append(DNS(data[offset : offset + length]))
        except Exception:
            pass
        offset += length
    if not messages:
        try:
            messages.append(DNS(data))
        except Exception:
            return []
    return messages


def _flow_key(packet, enable_doh: bool) -> tuple[Optional[FlowKey], bool]:
    if IP is None or not packet.haslayer(IP):
        return None, False
    ip = packet[IP]
    src = str(ip.src)
    dst = str(ip.dst)
    if packet.haslayer(UDP) and (packet[UDP].sport == 53 or packet[UDP].dport == 53):
        udp = packet[UDP]
        client_to_server = udp.dport == 53
        if client_to_server:
            return FlowKey("UDP53", src, dst, int(udp.sport), int(udp.dport)), True
        return FlowKey("UDP53", dst, src, int(udp.dport), int(udp.sport)), False
    if packet.haslayer(TCP) and (packet[TCP].sport == 53 or packet[TCP].dport == 53):
        tcp = packet[TCP]
        client_to_server = tcp.dport == 53
        if client_to_server:
            return FlowKey("TCP53", src, dst, int(tcp.sport), int(tcp.dport)), True
        return FlowKey("TCP53", dst, src, int(tcp.dport), int(tcp.sport)), False
    if (
        enable_doh
        and packet.haslayer(TCP)
        and (packet[TCP].sport == 443 or packet[TCP].dport == 443)
        and (src in DOH_RESOLVERS or dst in DOH_RESOLVERS)
    ):
        tcp = packet[TCP]
        client_to_server = tcp.dport == 443 and dst in DOH_RESOLVERS
        if client_to_server:
            return FlowKey("DOH", src, dst, int(tcp.sport), int(tcp.dport)), True
        return FlowKey("DOH", dst, src, int(tcp.dport), int(tcp.sport)), False
    return None, False


class FlowAggregator:
    def __init__(self, window_seconds: float, enable_doh: bool = True):
        self.window_seconds = float(window_seconds)
        self.enable_doh = enable_doh
        self.flows: dict[FlowKey, FlowState] = {}

    def add_packet(self, packet) -> None:
        key, client_to_server = _flow_key(packet, self.enable_doh)
        if key is None:
            return
        ts = float(getattr(packet, "time", time.time()))
        state = self.flows.get(key)
        if state is None:
            state = FlowState(key=key, first_ts=ts, last_ts=ts)
            self.flows[key] = state
        state.last_ts = max(state.last_ts, ts)
        self._update_state(state, packet, ts, client_to_server)

    def flush_expired(self, now: Optional[float] = None) -> list[FlowRecord]:
        now = time.time() if now is None else now
        expired = [
            key for key, state in self.flows.items() if now - state.first_ts >= self.window_seconds
        ]
        return [self._pop_record(key) for key in expired if key in self.flows]

    def flush_all(self) -> list[FlowRecord]:
        keys = list(self.flows)
        return [self._pop_record(key) for key in keys if key in self.flows]

    def _pop_record(self, key: FlowKey) -> FlowRecord:
        state = self.flows.pop(key)
        if state.key.transport == "DOH":
            return self._build_doh_record(state)
        if state.key.transport == "TCP53":
            return self._build_tcp_record(state)
        return self._build_udp_record(state)

    def _update_state(self, state: FlowState, packet, ts: float, client_to_server: bool) -> None:
        packet_size = len(packet)
        state.packet_times.append(ts)
        state.packet_sizes.append(packet_size)
        if client_to_server:
            state.client_times.append(ts)
            state.client_sizes.append(packet_size)
        else:
            state.server_times.append(ts)
            state.server_sizes.append(packet_size)

        if TCP is not None and packet.haslayer(TCP):
            tcp = packet[TCP]
            state.tcp_windows.append(int(tcp.window))
            state.tcp_flags.append(int(tcp.flags))
            state.tcp_sequences.append(int(tcp.seq))
            payload_size = len(bytes(tcp.payload))
            if payload_size:
                state.tcp_payload_sizes.append(payload_size)

        for dns in _dns_messages(packet):
            self._update_dns_state(state, dns, client_to_server)

    def _update_dns_state(self, state: FlowState, dns, client_to_server: bool) -> None:
        dns_size = len(bytes(dns))
        state.dns_message_sizes.append(dns_size)
        state.dns_length_fields.append(dns_size)
        qr = int(getattr(dns, "qr", 0))
        is_query = qr == 0 or client_to_server

        qname = ""
        qtype = 0
        if getattr(dns, "qd", None):
            qd = dns.qd
            qname = _decode_name(getattr(qd, "qname", ""))
            qtype = int(getattr(qd, "qtype", 0) or 0)
            if qname:
                state.query_names.append(qname)
            if qtype:
                state.query_types.append(qtype)
        if is_query:
            state.query_dns_sizes.append(dns_size)
        else:
            state.response_dns_sizes.append(dns_size)

        state.answer_counts.append(int(getattr(dns, "ancount", 0) or 0))
        state.additional_counts.append(int(getattr(dns, "arcount", 0) or 0))
        state.recursive_flags.append(int(getattr(dns, "rd", 0) or 0))
        state.authoritative_flags.append(int(getattr(dns, "aa", 0) or 0))
        state.truncated_flags.append(int(getattr(dns, "tc", 0) or 0))
        state.rcodes.append(int(getattr(dns, "rcode", 0) or 0))

        answer = getattr(dns, "an", None)
        if answer is not None:
            answers = answer if isinstance(answer, list) else [answer]
            for rr in answers:
                rrtype = int(getattr(rr, "type", 0) or 0)
                ttl = int(getattr(rr, "ttl", 0) or 0)
                if rrtype:
                    state.response_types.append(rrtype)
                if ttl:
                    state.ttls.append(ttl)

        if qtype:
            if qtype in {10, 16}:
                state.response_types.append(qtype)

    def _common_dns_row(self, state: FlowState, defaults: dict[str, object]) -> dict[str, object]:
        query = state.query_names[-1] if state.query_names else ""
        lexical = _lexical_features(query)
        message_count = max(len(state.dns_message_sizes), len(state.packet_sizes), 1)
        response_count = len(state.response_dns_sizes) or len(state.server_sizes)
        query_count = len(state.query_dns_sizes) or len(state.client_sizes)
        client_times = sorted(state.client_times)
        if len(client_times) > 1:
            query_iats = np.diff(client_times)
            inter_arrival_ms = float(_mean(query_iats) * 1000.0)
            query_span = max(client_times[-1] - client_times[0], 0.001)
            query_rate = float(query_count / query_span)
        else:
            inter_arrival_ms = float(self.window_seconds * 1000.0)
            query_rate = float(query_count / max(self.window_seconds, 1.0))
        row = dict(defaults)
        row.update(
            {
                "src_ip": state.key.src,
                "dst_ip": state.key.dst,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(state.first_ts)),
                "query_length": int(lexical["query_length"]),
                "response_length": int(_mean(state.response_dns_sizes or state.server_sizes, 0.0)),
                "payload_size": int(sum(state.dns_message_sizes) or sum(state.packet_sizes)),
                "ttl": int(_mean(state.ttls, 64.0)),
                "answer_count": int(round(_mean(state.answer_counts, 0.0))),
                "additional_count": int(round(_mean(state.additional_counts, 0.0))),
                "query_type": _mode(state.query_types),
                "response_type": _mode(state.response_types or state.query_types),
                "has_txt_record": int(16 in state.query_types or 16 in state.response_types),
                "has_null_record": int(10 in state.query_types or 10 in state.response_types),
                "query_entropy": lexical["query_entropy"],
                "label_entropy": lexical["label_entropy"],
                "subdomain_count": int(lexical["subdomain_count"]),
                "max_label_length": int(lexical["max_label_length"]),
                "avg_label_length": lexical["avg_label_length"],
                "unique_chars": int(lexical["unique_chars"]),
                "digit_ratio": lexical["digit_ratio"],
                "consonant_ratio": lexical["consonant_ratio"],
                "hex_ratio": lexical["hex_ratio"],
                "inter_arrival_time": inter_arrival_ms,
                "query_rate": query_rate,
                "response_ratio": float(response_count / message_count),
                "unique_domains": len(set(state.query_names)) or 1,
                "is_recursive": _mode(state.recursive_flags, 1),
                "authoritative_flag": _mode(state.authoritative_flags, 0),
            }
        )
        return row

    def _build_udp_record(self, state: FlowState) -> FlowRecord:
        row = self._common_dns_row(state, UDP_DEFAULTS)
        row["retransmission_count"] = max(len(state.query_names) - len(set(state.query_names)), 0)
        row["truncated_flag"] = _mode(state.truncated_flags, 0)
        row["transport_code"] = 0
        row["rcode"] = _mode(state.rcodes, 0)
        raw = pd.DataFrame([row])
        featured = train_classic_dns_detector.add_derived_features(raw)
        return self._record_from_row(state, raw, featured)

    def _build_tcp_record(self, state: FlowState) -> FlowRecord:
        row = self._common_dns_row(state, TCP_DEFAULTS)
        seq_repeats = len(state.tcp_sequences) - len(set(state.tcp_sequences))
        segment_count = len(state.packet_sizes)
        tcp_payload_total = int(sum(state.tcp_payload_sizes))
        row.update(
            {
                "tcp_stream_id": abs(hash((state.key.src, state.key.dst, state.key.sport, state.key.dport))) % 100000,
                "segment_count": segment_count,
                "tcp_payload_size": tcp_payload_total or int(sum(state.packet_sizes)),
                "window_size": int(_mean(state.tcp_windows, 0.0)),
                "tcp_flags": int(np.bitwise_or.reduce(state.tcp_flags)) if state.tcp_flags else 0,
                "retransmission_ratio": float(seq_repeats / segment_count) if segment_count else 0.0,
                "dns_length_field": int(_mean(state.dns_length_fields, 0.0)),
                "message_count": max(len(state.dns_message_sizes), 1),
                "avg_message_size": int(_mean(state.dns_message_sizes or state.packet_sizes, 0.0)),
                "max_message_size": int(max(state.dns_message_sizes or state.packet_sizes or [0])),
                "transport_code": 1,
                "rcode": _mode(state.rcodes, 0),
            }
        )
        raw = pd.DataFrame([row])
        featured = train_classic_dns_detector.add_derived_features(raw)
        return self._record_from_row(state, raw, featured)

    def _build_doh_record(self, state: FlowState) -> FlowRecord:
        duration = _safe_duration(state.first_ts, state.last_ts)
        client_sizes = state.client_sizes or [0]
        server_sizes = state.server_sizes or [0]
        all_sizes = state.packet_sizes or [0]
        client_iats = np.diff(sorted(state.client_times)) if len(state.client_times) > 1 else [duration]
        rtts = []
        server_times = sorted(state.server_times)
        for client_ts in sorted(state.client_times):
            later = [server_ts for server_ts in server_times if server_ts >= client_ts]
            if later:
                rtts.append(later[0] - client_ts)
        if not rtts:
            rtts = [0.05]
        packet_length = _numeric_stats(all_sizes)
        packet_time = _numeric_stats(client_iats)
        response_time = _numeric_stats(rtts)
        features = {
            "FlowBytesSent": float(sum(client_sizes)),
            "FlowSentRate": float(sum(client_sizes) / duration),
            "FlowBytesReceived": float(sum(server_sizes)),
            "FlowReceivedRate": float(sum(server_sizes) / duration),
            **{f"PacketLength{k}": v for k, v in packet_length.items()},
            **{f"PacketTime{k}": v for k, v in packet_time.items()},
            **{f"ResponseTimeTime{k}": v for k, v in response_time.items()},
        }
        featured = pd.DataFrame([{name: features.get(name, 0.0) for name in DOH_FEATURE_NAMES}])
        return FlowRecord(
            transport=state.key.transport,
            src=state.key.src,
            dst=state.key.dst,
            sport=state.key.sport,
            dport=state.key.dport,
            start_ts=state.first_ts,
            end_ts=state.last_ts,
            dns_query="known DoH resolver HTTPS flow",
            dns_type="HTTPS",
            raw_features=featured.copy(),
            model_features=featured,
            feature_values=featured.iloc[0].to_dict(),
            meta=self._meta(state, "known DoH resolver HTTPS flow", "HTTPS"),
        )

    def _record_from_row(self, state: FlowState, raw: pd.DataFrame, featured: pd.DataFrame) -> FlowRecord:
        query = state.query_names[-1] if state.query_names else "(no DNS query decoded)"
        qtype = _dns_type_name(_mode(state.query_types))
        return FlowRecord(
            transport=state.key.transport,
            src=state.key.src,
            dst=state.key.dst,
            sport=state.key.sport,
            dport=state.key.dport,
            start_ts=state.first_ts,
            end_ts=state.last_ts,
            dns_query=query,
            dns_type=qtype,
            raw_features=raw,
            model_features=featured,
            feature_values=featured.iloc[0].to_dict(),
            meta=self._meta(state, query, qtype),
        )

    def _meta(self, state: FlowState, query: str, qtype: str) -> dict[str, object]:
        return {
            "packet_count": len(state.packet_sizes),
            "dns_messages": len(state.dns_message_sizes),
            "query": query,
            "query_type": qtype,
            "duration": _safe_duration(state.first_ts, state.last_ts),
            "bytes": sum(state.packet_sizes),
        }


class PacketSource:
    def start(self) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError

    def drain(self) -> list[FlowRecord]:
        raise NotImplementedError

    @property
    def status(self) -> str:
        raise NotImplementedError


class PcapReplaySource(PacketSource):
    def __init__(self, pcap: Path, window_seconds: float, enable_doh: bool):
        self.pcap = pcap
        self.aggregator = FlowAggregator(window_seconds, enable_doh)
        self.records: queue.Queue[FlowRecord] = queue.Queue()
        self.thread: Optional[threading.Thread] = None
        self.error: Optional[str] = None
        self.done = False

    @property
    def status(self) -> str:
        if self.error:
            return f"replay error: {self.error}"
        return f"replay: {self.pcap}"

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.done = True

    def drain(self) -> list[FlowRecord]:
        drained = []
        while True:
            try:
                drained.append(self.records.get_nowait())
            except queue.Empty:
                return drained

    def _run(self) -> None:
        try:
            if not SCAPY_AVAILABLE:
                raise RuntimeError(f"scapy unavailable: {SCAPY_IMPORT_ERROR}")
            if not self.pcap.exists():
                raise FileNotFoundError(self.pcap)
            for packet in rdpcap(str(self.pcap)):
                self.aggregator.add_packet(packet)
            for record in self.aggregator.flush_all():
                self.records.put(record)
        except Exception as exc:
            self.error = str(exc)
        finally:
            self.done = True


class LiveCaptureSource(PacketSource):
    def __init__(self, iface: Optional[str], window_seconds: float, enable_doh: bool):
        self.iface = iface
        self.aggregator = FlowAggregator(window_seconds, enable_doh)
        self.lock = threading.Lock()
        self.thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.error: Optional[str] = None
        self.packet_count = 0

    @property
    def status(self) -> str:
        if self.error:
            return f"live error: {self.error}"
        iface = self.iface or "default interface"
        return f"live: {iface}"

    def start(self) -> None:
        if not SCAPY_AVAILABLE:
            self.error = f"scapy unavailable: {SCAPY_IMPORT_ERROR}"
            return
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()

    def drain(self) -> list[FlowRecord]:
        with self.lock:
            return self.aggregator.flush_expired(time.time())

    def _run(self) -> None:
        try:
            sniff(
                iface=self.iface,
                filter="(udp port 53) or (tcp port 53) or (tcp port 443)",
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: self.stop_event.is_set(),
            )
        except Exception as exc:
            self.error = str(exc)

    def _handle_packet(self, packet) -> None:
        self.packet_count += 1
        with self.lock:
            self.aggregator.add_packet(packet)


class AutoSource(PacketSource):
    def __init__(
        self,
        iface: Optional[str],
        pcap: Path,
        window_seconds: float,
        enable_doh: bool,
        fallback_seconds: float = 5.0,
    ):
        self.live = LiveCaptureSource(iface, window_seconds, enable_doh)
        self.replay = PcapReplaySource(pcap, window_seconds, enable_doh)
        self.current: PacketSource = self.live
        self.fallback_seconds = fallback_seconds
        self.started_at = 0.0
        self.fallback_reason: Optional[str] = None

    @property
    def status(self) -> str:
        if self.fallback_reason:
            return f"{self.current.status} (fallback: {self.fallback_reason})"
        return self.current.status

    def start(self) -> None:
        self.started_at = time.time()
        self.live.start()
        if self.live.error:
            self._fallback(self.live.error)

    def stop(self) -> None:
        self.current.stop()
        if self.current is not self.live:
            self.live.stop()

    def drain(self) -> list[FlowRecord]:
        if self.current is self.live:
            if self.live.error:
                self._fallback(self.live.error)
            elif time.time() - self.started_at >= self.fallback_seconds and self.live.packet_count == 0:
                self._fallback("no live DNS/DoH packets observed")
        return self.current.drain()

    def _fallback(self, reason: str) -> None:
        self.fallback_reason = reason
        self.live.stop()
        self.current = self.replay
        self.replay.start()


class TransportModel:
    def __init__(self, transport: str, artifact_dir: Path, malicious_threshold: float):
        self.transport = transport
        self.artifact_dir = artifact_dir
        self.malicious_threshold = float(malicious_threshold)
        self.supported = False
        self.status = "Unsupported model"
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names: list[str] = []
        self._load()

    def _load(self) -> None:
        try:
            feature_path = self.artifact_dir / "feature_names.csv"
            if not feature_path.exists():
                self.status = "Unsupported model"
                return
            self.feature_names = pd.read_csv(feature_path)["feature"].tolist()
            if self.transport == "DOH":
                model_path = self.artifact_dir / "xgboost.pkl"
                scaler_path = self.artifact_dir / "scaler.pkl"
                encoder_path = self.artifact_dir / "label_encoder.pkl"
                if not (model_path.exists() and scaler_path.exists() and encoder_path.exists()):
                    self.status = "Unsupported model"
                    return
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                self.label_encoder = joblib.load(encoder_path)
            else:
                model_path = self.artifact_dir / "best_model.pkl"
                if not model_path.exists():
                    self.status = "Unsupported model"
                    return
                self.model = joblib.load(model_path)
            self.supported = True
            self.status = f"Ready (threshold {self.malicious_threshold:.0%})"
        except Exception as exc:
            self.supported = False
            self.status = f"Unsupported model: {exc}"

    def predict(self, record: FlowRecord) -> PredictionResult:
        if not self.supported or self.model is None:
            return self._unsupported(record)
        X = record.model_features.reindex(columns=self.feature_names, fill_value=0)
        X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
        if self.transport == "DOH":
            scaled = self.scaler.transform(X)
            proba = self.model.predict_proba(scaled)[0]
            classes = list(getattr(self.model, "classes_", [0, 1]))
            mal_index = classes.index(1) if 1 in classes else len(classes) - 1
        else:
            proba = self.model.predict_proba(X)[0]
            classes = list(getattr(self.model, "classes_", [0, 1]))
            mal_index = classes.index(1) if 1 in classes else len(classes) - 1
        malicious_prob = float(proba[mal_index])
        label = "Malicious" if malicious_prob >= self.malicious_threshold else "Benign"
        confidence = malicious_prob if label == "Malicious" else 1.0 - malicious_prob
        threat = _threat(label, malicious_prob)
        result = _result_from_record(record, label, confidence, malicious_prob, threat, self.status)
        result.meta["decision_threshold"] = self.malicious_threshold
        return result

    def _unsupported(self, record: FlowRecord) -> PredictionResult:
        result = _result_from_record(record, "Unsupported model", 0.0, 0.0, "UNSUPPORTED", self.status)
        result.meta["decision_threshold"] = self.malicious_threshold
        return result


class ModelRegistry:
    def __init__(self, artifacts_root: Path, malicious_threshold: float = DEFAULT_MALICIOUS_THRESHOLD):
        self.malicious_threshold = float(malicious_threshold)
        self.models = {
            "DOH": TransportModel("DOH", artifacts_root / "doh", self.malicious_threshold),
            "UDP53": TransportModel("UDP53", artifacts_root / "classic_dns", self.malicious_threshold),
            "TCP53": TransportModel("TCP53", artifacts_root / "classic_dns", self.malicious_threshold),
        }

    def predict(self, record: FlowRecord) -> PredictionResult:
        model = self.models.get(record.transport)
        if model is None:
            return _result_from_record(record, "Unsupported model", 0.0, 0.0, "UNSUPPORTED", "Unsupported model")
        return model.predict(record)

    def summary(self) -> list[str]:
        return [f"{transport}: {model.status}" for transport, model in self.models.items()]


def _threat(label: str, malicious_prob: float) -> str:
    if label != "Malicious":
        return "BENIGN"
    if malicious_prob >= 0.95:
        return "CRITICAL"
    if malicious_prob >= 0.80:
        return "HIGH"
    return "MEDIUM"


def _result_from_record(
    record: FlowRecord,
    label: str,
    confidence: float,
    malicious_prob: float,
    threat: str,
    model_status: str,
) -> PredictionResult:
    return PredictionResult(
        transport=record.transport,
        label=label,
        confidence=confidence,
        malicious_prob=malicious_prob,
        threat=threat,
        model_status=model_status,
        time_str=time.strftime("%H:%M:%S", time.localtime(record.end_ts)),
        src=record.src,
        dst=record.dst,
        sport=record.sport,
        dport=record.dport,
        dns_query=record.dns_query,
        dns_type=record.dns_type,
        flow_duration=_safe_duration(record.start_ts, record.end_ts),
        packet_count=int(record.meta.get("packet_count", 0)),
        feature_values=record.feature_values,
        meta=record.meta,
    )


class StatsPanel(Static):
    total = reactive(0)
    benign = reactive(0)
    malicious = reactive(0)
    unsupported = reactive(0)
    source = reactive("starting")

    def render(self) -> str:
        alert_rate = f"{self.malicious / self.total * 100:.1f}%" if self.total else "0.0%"
        return (
            f"[bold {THEME['text']}]Source:[/bold {THEME['text']}] {self.source}\n"
            f"[bold {THEME['text']}]Flows:[/bold {THEME['text']}] {self.total}\n"
            f"[bold {THEME['benign']}]Benign:[/bold {THEME['benign']}] {self.benign}   "
            f"[bold {THEME['critical']}]Malicious:[/bold {THEME['critical']}] {self.malicious}\n"
            f"[bold {THEME['unsupported']}]Unsupported:[/bold {THEME['unsupported']}] {self.unsupported}   "
            f"[bold {THEME['warning']}]Alert Rate:[/bold {THEME['warning']}] {alert_rate}"
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
            content.update(f"[dim {THEME['muted']}]Select an alert row to inspect flow details[/dim {THEME['muted']}]")
            return
        r = self.selected_result
        threat_color = SEVERITY_STYLE.get(r.threat, THEME["text"])
        transport_color = TRANSPORT_STYLE.get(r.transport, THEME["text"])
        lines = [
            f"[bold {THEME['accent']}]FLOW[/bold {THEME['accent']}]",
            f"  [bold {THEME['text']}]Transport:[/bold {THEME['text']}] [{transport_color}]{r.transport}[/{transport_color}]",
            f"  [bold {THEME['text']}]Path:[/bold {THEME['text']}] {r.src}:{r.sport} -> {r.dst}:{r.dport}",
            f"  [bold {THEME['text']}]Query:[/bold {THEME['text']}] {r.dns_query}",
            f"  [bold {THEME['text']}]Type:[/bold {THEME['text']}] {r.dns_type}",
            f"  [bold {THEME['text']}]Duration:[/bold {THEME['text']}] {r.flow_duration:.3f}s   "
            f"[bold {THEME['text']}]Packets:[/bold {THEME['text']}] {r.packet_count}",
            "",
            f"[bold {THEME['accent']}]PREDICTION[/bold {THEME['accent']}]",
            f"  [bold {THEME['text']}]Label:[/bold {THEME['text']}] [{threat_color}]{r.label}[/{threat_color}]",
            f"  [bold {THEME['text']}]Threat:[/bold {THEME['text']}] [{threat_color}]{r.threat}[/{threat_color}]",
            f"  [bold {THEME['text']}]Confidence:[/bold {THEME['text']}] {r.confidence:.2%}",
            f"  [bold {THEME['text']}]Malicious probability:[/bold {THEME['text']}] {r.malicious_prob:.2%}",
            f"  [bold {THEME['text']}]Decision threshold:[/bold {THEME['text']}] "
            f"{float(r.meta.get('decision_threshold', DEFAULT_MALICIOUS_THRESHOLD)):.0%}",
            f"  [bold {THEME['text']}]Model:[/bold {THEME['text']}] {r.model_status}",
            "",
            f"[bold {THEME['accent']}]HIGH-SIGNAL FEATURES[/bold {THEME['accent']}]",
        ]
        important = _important_features(r.transport)
        shown = 0
        for name in important:
            if name in r.feature_values:
                value = r.feature_values[name]
                if isinstance(value, (int, float, np.number)):
                    value_str = f"{float(value):.4f}"
                else:
                    value_str = str(value)
                lines.append(f"  [bold {THEME['text']}]{name:<36}[/bold {THEME['text']}] {value_str}")
                shown += 1
        if shown == 0:
            for name, value in list(r.feature_values.items())[:16]:
                lines.append(f"  [bold {THEME['text']}]{name:<36}[/bold {THEME['text']}] {value}")
        content.update("\n".join(lines))

    def refresh(self, *, layout: bool = False, **kwargs) -> None:
        super().refresh(layout=layout, **kwargs)
        self._refresh_content()


def _important_features(transport: str) -> list[str]:
    if transport == "UDP53":
        return [
            "query_length",
            "query_entropy",
            "label_entropy",
            "digit_ratio",
            "hex_ratio",
            "query_rate",
            "inter_arrival_time",
            "has_txt_record",
            "has_null_record",
            "txt_or_null_record",
        ]
    if transport == "TCP53":
        return [
            "segment_count",
            "tcp_payload_size",
            "retransmission_ratio",
            "dns_length_field",
            "message_count",
            "query_length",
            "query_entropy",
            "hex_ratio",
            "query_rate",
            "retransmission_payload_pressure",
        ]
    return [
        "FlowBytesSent",
        "FlowSentRate",
        "FlowBytesReceived",
        "FlowReceivedRate",
        "PacketLengthMean",
        "PacketLengthStandardDeviation",
        "PacketTimeMean",
        "PacketTimeStandardDeviation",
        "ResponseTimeTimeMean",
    ]


class DnsTunnelApp(App):
    """Transport-aware DNS tunneling monitor."""

    CSS = f"""
    Screen {{
        background: {THEME['bg']};
    }}
    Header {{
        background: {THEME['panel']};
        color: {THEME['accent']};
        text-style: bold;
    }}
    Footer {{
        background: {THEME['panel']};
        color: {THEME['muted']};
    }}
    #left-panel {{
        width: 34;
        border: solid {THEME['border']};
        background: {THEME['panel']};
        padding: 1;
    }}
    #stats-panel {{
        height: 7;
        border: solid {THEME['border']};
        background: {THEME['panel_alt']};
        padding: 1 2;
    }}
    #alerts-table {{
        height: 12;
        border: solid {THEME['border']};
        background: {THEME['bg']};
    }}
    #flow-detail {{
        height: 1fr;
        border: solid {THEME['border']};
        background: {THEME['panel']};
        padding: 1;
    }}
    #log-panel {{
        height: 7;
        border: solid {THEME['border']};
        background: {THEME['panel']};
    }}
    DataTable {{
        background: {THEME['bg']};
    }}
    DataTable > .datatable--header {{
        background: {THEME['surface']};
        color: {THEME['accent']};
        text-style: bold;
    }}
    DataTable > .datatable--cursor {{
        background: {THEME['border_focus']};
        color: {THEME['bg']};
    }}
    Vertical:focus-within {{
        border: none;
    }}
    *:focus {{
        border: tall {THEME['border_focus']};
    }}
    Label {{
        padding: 0 1;
    }}
    Rule {{
        color: {THEME['border']};
    }}
    .section-label {{
        color: {THEME['accent']};
        text-style: bold;
        padding: 0 1;
    }}
    .muted {{
        color: {THEME['muted']};
    }}
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("c", "clear_alerts", "Clear"),
    ]

    def __init__(self, args: argparse.Namespace):
        super().__init__()
        self.args = args
        self.registry = ModelRegistry(args.artifacts_root, args.malicious_threshold)
        self.source: Optional[PacketSource] = None
        self.all_results: list[PredictionResult] = []
        self.source_notice = ""

    def compose(self) -> ComposeResult:
        yield Header()
        yield Horizontal(
            Vertical(
                Label(f"[bold {THEME['accent']}]DNS TUNNEL MONITOR[/bold {THEME['accent']}]"),
                Rule(),
                Label(f"[bold {THEME['text']}]Mode[/bold {THEME['text']}]"),
                Label(str(self.args.mode), id="mode-label"),
                Label(f"[bold {THEME['text']}]Interface[/bold {THEME['text']}]"),
                Label(str(self.args.iface or "auto/default"), id="iface-label"),
                Label(f"[bold {THEME['text']}]Replay PCAP[/bold {THEME['text']}]"),
                Label(str(self.args.pcap), id="pcap-label"),
                Rule(),
                Label(f"[bold {THEME['text']}]Models[/bold {THEME['text']}]"),
                Label("\n".join(self.registry.summary()), id="models-label"),
                Label(f"Alert threshold: {self.args.malicious_threshold:.0%}"),
                Rule(),
                Label(f"[bold {THEME['muted']}]Keys[/bold {THEME['muted']}]"),
                Label("c = clear alerts"),
                Label("q = quit"),
                id="left-panel",
            ),
            Vertical(
                StatsPanel(id="stats-panel"),
                Label(f"[bold {THEME['accent']}]ALERTS - select row for details[/bold {THEME['accent']}]", classes="section-label"),
                DataTable(id="alerts-table"),
                Label(f"[bold {THEME['accent']}]FLOW DETAIL[/bold {THEME['accent']}]", classes="section-label"),
                FlowDetailPanel(id="flow-detail", can_focus=False),
                Log(id="log-panel", max_lines=200, highlight=True),
            ),
        )
        yield Footer()

    def on_mount(self) -> None:
        self.title = "DNS Tunnel Monitor"
        self.sub_title = "Live/replay transport-aware detection"
        table = self.query_one("#alerts-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns("Time", "Transport", "Src", "Dst", "Label", "Confidence", "Threat")
        self._start_source()
        self.set_interval(self.args.flush_seconds, self._poll_source)

    def on_unmount(self) -> None:
        if self.source:
            self.source.stop()

    def _start_source(self) -> None:
        if self.args.mode == "replay":
            self.source = PcapReplaySource(self.args.pcap, self.args.window_seconds, self.args.enable_doh)
        elif self.args.mode == "live":
            self.source = LiveCaptureSource(self.args.iface, self.args.window_seconds, self.args.enable_doh)
        else:
            self.source = AutoSource(self.args.iface, self.args.pcap, self.args.window_seconds, self.args.enable_doh)
        self.source.start()
        self.query_one("#stats-panel", StatsPanel).source = self.source.status
        log = self.query_one("#log-panel", Log)
        log.write_line(f"[bold {THEME['benign']}]Source started:[/bold {THEME['benign']}] {self.source.status}")
        for line in self.registry.summary():
            log.write_line(f"[dim {THEME['muted']}]{line}[/dim {THEME['muted']}]")

    def _poll_source(self) -> None:
        if not self.source:
            return
        stats = self.query_one("#stats-panel", StatsPanel)
        old_status = stats.source
        stats.source = self.source.status
        if old_status != stats.source:
            self.query_one("#log-panel", Log).write_line(
                f"[bold {THEME['warning']}]Source status:[/bold {THEME['warning']}] {stats.source}"
            )
        for record in self.source.drain():
            self._add_result(self.registry.predict(record))

    def action_clear_alerts(self) -> None:
        self.all_results.clear()
        self.query_one("#alerts-table", DataTable).clear()
        stats = self.query_one("#stats-panel", StatsPanel)
        stats.total = stats.benign = stats.malicious = stats.unsupported = 0
        detail = self.query_one("#flow-detail", FlowDetailPanel)
        detail.selected_result = None
        detail.refresh()
        self.query_one("#log-panel", Log).write_line(f"[bold {THEME['warning']}]Alerts cleared[/bold {THEME['warning']}]")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        try:
            idx = int(str(event.row_key.value))
        except Exception:
            return
        if 0 <= idx < len(self.all_results):
            result = self.all_results[idx]
            self.query_one("#flow-detail", FlowDetailPanel).show_flow(result)
            self.query_one("#log-panel", Log).write_line(
                f"[dim {THEME['muted']}]Inspecting {result.transport} flow {result.src} -> {result.dst}[/dim {THEME['muted']}]"
            )

    def _add_result(self, result: PredictionResult) -> None:
        idx = len(self.all_results)
        self.all_results.append(result)
        stats = self.query_one("#stats-panel", StatsPanel)
        stats.total += 1
        if result.threat == "UNSUPPORTED":
            stats.unsupported += 1
        elif result.label == "Malicious":
            stats.malicious += 1
        else:
            stats.benign += 1

        table = self.query_one("#alerts-table", DataTable)
        transport_color = TRANSPORT_STYLE.get(result.transport, THEME["text"])
        threat_color = SEVERITY_STYLE.get(result.threat, THEME["text"])
        label_color = threat_color if result.label != "Benign" else THEME["benign"]
        table.add_row(
            result.time_str,
            f"[{transport_color}]{result.transport}[/{transport_color}]",
            result.src,
            result.dst,
            f"[{label_color}]{result.label}[/{label_color}]",
            "--" if result.threat == "UNSUPPORTED" else f"{result.confidence:.1%}",
            f"[{threat_color}]{result.threat}[/{threat_color}]",
            key=str(idx),
        )
        table.move_cursor(row=table.row_count - 1)
        self.query_one("#flow-detail", FlowDetailPanel).show_flow(result)
        self.query_one("#log-panel", Log).write_line(
            f"[bold {threat_color}]{result.transport} {result.label} {result.malicious_prob:.2%} "
            f"{result.src}->{result.dst} {result.dns_query}[/bold {threat_color}]"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Transport-aware DNS tunneling TUI")
    parser.add_argument("--mode", choices=["auto", "live", "replay"], default="auto")
    parser.add_argument("--iface", default=None, help="Interface for live capture. Default lets Scapy choose.")
    parser.add_argument("--pcap", type=Path, default=PROJECT_ROOT / "samples" / "demo_dns_mix.pcap")
    parser.add_argument("--artifacts-root", type=Path, default=PROJECT_ROOT / "artifacts")
    parser.add_argument("--window-seconds", type=float, default=10.0)
    parser.add_argument("--flush-seconds", type=float, default=1.0)
    parser.add_argument(
        "--malicious-threshold",
        type=float,
        default=DEFAULT_MALICIOUS_THRESHOLD,
        help="Minimum malicious probability needed to announce a flow as malicious.",
    )
    parser.add_argument("--enable-doh", dest="enable_doh", action="store_true", default=True)
    parser.add_argument("--no-doh", dest="enable_doh", action="store_false")
    args = parser.parse_args()
    if not 0.0 <= args.malicious_threshold <= 1.0:
        parser.error("--malicious-threshold must be between 0.0 and 1.0")
    return args


def main() -> None:
    args = parse_args()
    app = DnsTunnelApp(args)
    app.register_theme(SOC_DARK)
    app.theme = "soc_dark"
    app.run()


if __name__ == "__main__":
    multiprocessing.set_start_method("fork")
    main()
