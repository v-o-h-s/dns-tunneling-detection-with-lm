#!/usr/bin/env python3
"""Create a small DNS/DoH replay PCAP for the TUI class demo."""

from __future__ import annotations

from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, Raw, TCP, UDP, wrpcap


PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT = PROJECT_ROOT / "samples" / "demo_dns_mix.pcap"


def _stamp(packet, ts: float):
    packet.time = ts
    return packet


def _udp_pair(ts: float, client: str, resolver: str, sport: int, qname: str, qtype: str, answer: str):
    dns_id = sport % 65535
    query = IP(src=client, dst=resolver, ttl=64) / UDP(sport=sport, dport=53) / DNS(
        id=dns_id,
        rd=1,
        qd=DNSQR(qname=qname, qtype=qtype),
    )
    if qtype == "TXT":
        rr = DNSRR(rrname=qname, type="TXT", ttl=120, rdata=answer)
    else:
        rr = DNSRR(rrname=qname, type="A", ttl=300, rdata=answer)
    response = IP(src=resolver, dst=client, ttl=60) / UDP(sport=53, dport=sport) / DNS(
        id=dns_id,
        qr=1,
        aa=1,
        rd=1,
        ra=1,
        qd=DNSQR(qname=qname, qtype=qtype),
        an=rr,
    )
    return [_stamp(query, ts), _stamp(response, ts + 0.045)]


def _tcp_dns_packet(ts: float, src: str, dst: str, sport: int, dport: int, seq: int, dns):
    payload = len(bytes(dns)).to_bytes(2, "big") + bytes(dns)
    packet = IP(src=src, dst=dst, ttl=64) / TCP(sport=sport, dport=dport, flags="PA", seq=seq, window=32768) / Raw(payload)
    return _stamp(packet, ts)


def _tcp_pair(ts: float, client: str, resolver: str, sport: int, qname: str, qtype: str, answer: str):
    dns_id = sport % 65535
    seq_seed = int(ts * 1000)
    query_dns = DNS(id=dns_id, rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    if qtype == "TXT":
        rr = DNSRR(rrname=qname, type="TXT", ttl=120, rdata=answer)
    else:
        rr = DNSRR(rrname=qname, type="A", ttl=300, rdata=answer)
    response_dns = DNS(
        id=dns_id,
        qr=1,
        aa=1,
        rd=1,
        ra=1,
        qd=DNSQR(qname=qname, qtype=qtype),
        an=rr,
    )
    return [
        _tcp_dns_packet(ts, client, resolver, sport, 53, 1000 + sport + seq_seed, query_dns),
        _tcp_dns_packet(ts + 0.065, resolver, client, 53, sport, 5000 + sport + seq_seed, response_dns),
    ]


def _doh_flow(ts: float, client: str, resolver: str, sport: int, sizes: list[tuple[str, int, float]]):
    packets = []
    seq_client = 100000
    seq_server = 200000
    for direction, size, offset in sizes:
        if direction == "c":
            payload = bytes([0x17]) * size
            packet = IP(src=client, dst=resolver, ttl=64) / TCP(
                sport=sport,
                dport=443,
                flags="PA",
                seq=seq_client,
                window=32768,
            ) / Raw(payload)
            seq_client += size
        else:
            payload = bytes([0x16]) * size
            packet = IP(src=resolver, dst=client, ttl=60) / TCP(
                sport=443,
                dport=sport,
                flags="PA",
                seq=seq_server,
                window=32768,
            ) / Raw(payload)
            seq_server += size
        packets.append(_stamp(packet, ts + offset))
    return packets


def build_packets():
    packets = []

    benign_udp = ["example.com", "python.org", "github.com"]
    for idx, qname in enumerate(benign_udp):
        packets.extend(_udp_pair(1.0 + idx * 0.8, "192.168.10.20", "8.8.8.8", 41000, qname, "A", "93.184.216.34"))

    suspicious_udp = [
        "a1b2c3d4e5f60718293a4b5c6d7e8f90cafebabefeed001.tunnel.attacker.test",
        "7061796c6f61642d6368756e6b2d3030312d657866696c.tunnel.attacker.test",
        "dGhpcy1sb29rcy1saWtlLWRhdGEtZXhmaWwtcGFja2V0.tunnel.attacker.test",
        "9f8e7d6c5b4a39281726354433221100deadc0debead.tunnel.attacker.test",
        "upload-bmV4dC1kYXRhLWJsb2NrLXN0YWdlLTAwNA.tunnel.attacker.test",
    ]
    for idx, qname in enumerate(suspicious_udp):
        packets.extend(_udp_pair(15.0 + idx * 0.08, "192.168.10.55", "1.1.1.1", 42000, qname, "TXT", "ack=next"))

    benign_tcp = ["mozilla.org", "wikipedia.org", "cloudflare.com"]
    for idx, qname in enumerate(benign_tcp):
        packets.extend(_tcp_pair(30.0 + idx * 0.9, "192.168.10.30", "9.9.9.9", 43000, qname, "A", "93.184.216.34"))

    suspicious_tcp = [
        "beacon-001-abcdef0123456789.control.example.net",
        "upload-002-0123456789abcdef.control.example.net",
        "chunk-003-fedcba9876543210.control.example.net",
    ]
    for idx, qname in enumerate(suspicious_tcp):
        packets.extend(_tcp_pair(45.0 + idx * 0.22, "192.168.10.70", "8.8.4.4", 44000, qname, "TXT", "ack"))

    packets.extend(
        _doh_flow(
            60.0,
            "192.168.10.40",
            "1.1.1.1",
            45000,
            [("c", 70, 0.0), ("s", 120, 0.05), ("c", 68, 1.5), ("s", 115, 1.56), ("c", 72, 5.5), ("s", 130, 5.58)],
        )
    )
    packets.extend(
        _doh_flow(
            80.0,
            "192.168.10.80",
            "8.8.8.8",
            46000,
            [
                ("c", 420, 0.00),
                ("s", 460, 0.12),
                ("c", 440, 0.30),
                ("s", 480, 0.42),
                ("c", 430, 0.60),
                ("s", 470, 0.74),
                ("c", 450, 0.90),
                ("s", 490, 1.04),
            ],
        )
    )

    return sorted(packets, key=lambda packet: packet.time)


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    packets = build_packets()
    wrpcap(str(OUTPUT), packets)
    print(f"Wrote {len(packets)} packets to {OUTPUT}")


if __name__ == "__main__":
    main()
