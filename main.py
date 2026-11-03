"""
main.py
=======
CodeAlpha Cybersecurity Internship - Task 4
Network Intrusion Detection System (NIDS) - Entry point
Wires together:
    packet_sniffer.py     - capture + parse
    intrusion_detector.py - detection rules
    alert_manager.py      - CSV/JSON persistence
Usage (live mode requires Administrator):
    python main.py                                  # default interface
    python main.py --iface "Wi-Fi"                  # specific interface
    python main.py --iface "Loopback Pseudo-Interface 1"
    python main.py --duration 30                    # stop after 30s
    python main.py --limit 500                      # stop after 500 packets
    python main.py --synthetic                      # fake packets, no admin
    python main.py --stats                          # print log stats and exit
    python main.py --clear                          # wipe logs and exit
Run --help for the full list.
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional
from alert_manager import AlertManager
from intrusion_detector import IntrusionDetector
from packet_sniffer import (
    ensure_admin,
    find_loopback_interface,
    print_interfaces,
    start_sniffing,
)
PROJECT_ROOT = Path(__file__).resolve().parent
RULES_PATH = PROJECT_ROOT / "rules" / "detection_rules.json"
SEVERITY_TAG = {
    "LOW":      "[ LOW  ]",
    "MEDIUM":   "[MEDIUM]",
    "HIGH":     "[ HIGH ]",
    "CRITICAL": "[CRIT  ]",
    "UNKNOWN":  "[  ??  ]",
}
class LiveNIDS:
    """Owns the detector, alert manager, and per-session counters."""
    def __init__(self, rules_path: Path):
        self.detector = IntrusionDetector(str(rules_path))
        self.alerts = AlertManager()
        self._lock = Lock()
        self.packets_seen = 0
        self.alerts_raised = 0
        self.by_attack: Dict[str, int] = {}
        self.by_source: Dict[str, int] = {}
    def on_packet(self, record: Dict) -> None:
        with self._lock:
            self.packets_seen += 1
        alerts = self.detector.ingest(record)
        if not alerts:
            return
        self.alerts.save_alerts(alerts)
        for alert in alerts:
            with self._lock:
                self.alerts_raised += 1
                atk = alert.get("attack_type", "UNKNOWN")
                src = alert.get("src_ip", "UNKNOWN")
                self.by_attack[atk] = self.by_attack.get(atk, 0) + 1
                self.by_source[src] = self.by_source.get(src, 0) + 1
            self.print_alert(alert)
    def print_alert(self, alert: Dict) -> None:
        tag = SEVERITY_TAG.get(alert.get("severity", "UNKNOWN"),
                               SEVERITY_TAG["UNKNOWN"])
        details = alert.get("details") or {}
        detail_str = ", ".join(f"{k}={v}" for k, v in details.items())
        src_port = alert.get("src_port", "-")
        dst_port = alert.get("dst_port", "-")
        print(
            f"{tag} {alert['attack_type']:<22} "
            f"{alert['src_ip']}:{src_port} -> {alert['dst_ip']}:{dst_port}  "
            f"{detail_str}"
        )
    def summary(self) -> None:
        print("\n" + "=" * 70)
        print(" NIDS SESSION SUMMARY")
        print("=" * 70)
        print(f" Packets processed : {self.packets_seen}")
        print(f" Alerts raised     : {self.alerts_raised}")
        if self.by_attack:
            print(" Alerts by type    :")
            for name, count in sorted(self.by_attack.items(), key=lambda kv: -kv[1]):
                print(f"     {name:<24} {count}")
        if self.by_source:
            print(" Top alert sources :")
            for src, count in sorted(self.by_source.items(), key=lambda kv: -kv[1])[:5]:
                print(f"     {src:<20} {count}")
        print(" Logs              : logs/alerts.csv, logs/alerts.json")
        print("=" * 70)
# ---------------------------------------------------------------------- #
# Modes
# ---------------------------------------------------------------------- #
def mode_stats() -> int:
    s = AlertManager().stats()
    print("\nCurrent alert log statistics")
    print("-" * 40)
    print(f" total_alerts = {s['total_alerts']}")
    for k, v in s["by_attack"].items():
        print(f"   attack  {k:<22} {v}")
    for k, v in s["by_severity"].items():
        print(f"   sev     {k:<22} {v}")
    for k, v in s["by_source"].items():
        print(f"   source  {k:<22} {v}")
    if s["last_alert"]:
        la = s["last_alert"]
        print(f" last_alert  = {la['attack_type']} from "
              f"{la['src_ip']} at {la['timestamp']}")
    return 0
def mode_clear() -> int:
    AlertManager().clear()
    print("logs/ cleared.")
    return 0
def mode_synthetic(rules_path: Path) -> int:
    """Feed the same pipeline 3 scripted attacks - no admin, no capture."""
    print("Synthetic mode - piping 15 fake packets through the real pipeline.")
    print("(Same code path as live traffic; only the input is scripted.)\n")
    nids = LiveNIDS(rules_path)
    # 12 SYNs to distinct ports from 10.0.0.99 -> triggers PORT_SCAN on #10
    for i in range(12):
        nids.on_packet({
            "timestamp": f"2026-11-03T20:0{i % 10}:00",
            "src_ip": "10.0.0.99", "dst_ip": "10.0.0.1",
            "protocol": "TCP", "src_port": 50000 + i, "dst_port": 10000 + i,
            "tcp_flags": "S", "length": 56,
        })
    # Single SYN to telnet (23) from 10.0.0.10 -> SUSPICIOUS_PORT
    nids.on_packet({
        "timestamp": "2026-11-03T20:10:00",
        "src_ip": "10.0.0.10", "dst_ip": "10.0.0.4",
        "protocol": "TCP", "src_port": 40000, "dst_port": 23,
        "tcp_flags": "S", "length": 56,
    })
    # Single SYN to SMB (445) from 10.0.0.11 -> SUSPICIOUS_PORT
    nids.on_packet({
        "timestamp": "2026-11-03T20:11:00",
        "src_ip": "10.0.0.11", "dst_ip": "10.0.0.5",
        "protocol": "TCP", "src_port": 40001, "dst_port": 445,
        "tcp_flags": "S", "length": 56,
    })
    nids.summary()
    return 0
def mode_live(args: argparse.Namespace, rules_path: Path) -> int:
    ensure_admin()
    print_interfaces()
    iface = args.iface
    if iface is None:
        loopback = find_loopback_interface()
        if loopback:
            print(f'\nTip: for localhost tests use --iface "{loopback}"')
        print("\nNo --iface given; Scapy will use its default interface.")
    nids = LiveNIDS(rules_path)
    print(f"\n Rules        : {rules_path}")
    print(f" Logs         : logs/alerts.csv, logs/alerts.json")
    print(f" BPF filter   : {args.filter}")
    print(f" Packet limit : {args.limit if args.limit else 'unlimited'}")
    print(f" Duration     : {args.duration if args.duration else 'until Ctrl+C'}")
    try:
        start_sniffing(
            callback=nids.on_packet,
            iface=iface,
            bpf_filter=args.filter,
            packet_limit=args.limit,
            timeout=args.duration,
        )
    finally:
        nids.summary()
    return 0
# ---------------------------------------------------------------------- #
# CLI
# ---------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="main.py",
        description="CodeAlpha NIDS - live network intrusion detection",
    )
    p.add_argument("--iface", help='e.g. "Wi-Fi" or "Loopback Pseudo-Interface 1"')
    p.add_argument("--filter", default="tcp or udp or icmp",
                   help="BPF filter (default: 'tcp or udp or icmp')")
    p.add_argument("--limit", type=int, default=0, help="Stop after N packets")
    p.add_argument("--duration", type=int, default=None, help="Stop after N seconds")
    p.add_argument("--synthetic", action="store_true",
                   help="Feed fake alerts through the pipeline (no admin)")
    p.add_argument("--stats", action="store_true",
                   help="Print current log stats and exit")
    p.add_argument("--clear", action="store_true", help="Clear logs/ and exit")
    return p
def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.clear:
        return mode_clear()
    if args.stats:
        return mode_stats()
    if args.synthetic:
        return mode_synthetic(RULES_PATH)
    return mode_live(args, RULES_PATH)
if __name__ == "__main__":
    sys.exit(main())