"""
packet_sniffer.py
=================
CodeAlpha Cybersecurity Internship - Task 4
Network Intrusion Detection System (NIDS) - Module 1: Network Traffic Monitoring
Responsibility
--------------
Capture live network packets with Scapy and convert each one into a plain
Python dict containing only the fields the detector needs:
    timestamp, src_ip, dst_ip, protocol, src_port, dst_port, tcp_flags, length
This module does NOT detect anything - it only observes. Detection lives in
intrusion_detector.py.
Windows requirements
--------------------
    * Npcap installed          -> https://npcap.com
    * PowerShell as Administrator (raw capture needs admin on Windows)
    * scapy                    -> pip install -r requirements.txt
Run the demo:
    python packet_sniffer.py
    python packet_sniffer.py "Wi-Fi"
    python packet_sniffer.py "Loopback Pseudo-Interface 1"
"""
from __future__ import annotations
import ctypes
import os
import sys
from datetime import datetime
from typing import Callable, Dict, List, Optional
from scapy.all import IP, TCP, UDP, conf, sniff
# --------------------------------------------------------------------------- #
# 1. Admin check + interface listing
# --------------------------------------------------------------------------- #
def is_admin() -> bool:
    """Return True if the current process has Administrator privileges."""
    if os.name != "nt":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False
def ensure_admin() -> None:
    """Exit with a clear message if we are not running as Administrator."""
    if not is_admin():
        print("=" * 70)
        print(" ERROR: Administrator privileges required.")
        print(" Raw packet capture needs elevated rights (Npcap kernel driver).")
        print(" Fix  : close PowerShell, right-click -> 'Run as Administrator',")
        print("        then re-activate the venv and run again.")
        print("=" * 70)
        sys.exit(1)
def print_interfaces() -> None:
    """Pretty-print every capture-capable interface Scapy can see."""
    print("\nAvailable capture interfaces:")
    print("-" * 70)
    for i, iface in enumerate(conf.ifaces.values()):
        desc = getattr(iface, "description", "") or ""
        net_name = getattr(iface, "network_name", "") or ""
        print(f" [{i}] {iface.name}")
        if desc and desc != iface.name:
            print(f"       desc: {desc}")
        if net_name and net_name != iface.name:
            print(f"       dev : {net_name}")
    print("-" * 70)
def find_loopback_interface() -> Optional[str]:
    """
    Find the loopback adapter - works with both friendly Windows names
    ('Loopback Pseudo-Interface 1') and NPF device names ('\\Device\\NPF_Loopback').
    """
    for iface in conf.ifaces.values():
        name = (iface.name or "").lower()
        desc = (getattr(iface, "description", "") or "").lower()
        net_name = (getattr(iface, "network_name", "") or "").lower()
        if "loopback" in name or "loopback" in desc or "loopback" in net_name:
            return iface.name
    return None
# --------------------------------------------------------------------------- #
# 2. Packet parsing - core of this module
# --------------------------------------------------------------------------- #
PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}
def parse_packet(pkt) -> Optional[Dict]:
    """
    Convert a Scapy packet into a flat dict, or return None if it is not IP.
    """
    if IP not in pkt:
        return None
    ip_layer = pkt[IP]
    record: Dict = {
        "timestamp": datetime.fromtimestamp(float(pkt.time)).isoformat(timespec="seconds"),
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "protocol": PROTOCOL_NAMES.get(ip_layer.proto, f"OTHER({ip_layer.proto})"),
        "src_port": None,
        "dst_port": None,
        "tcp_flags": None,
        "length": len(pkt),
    }
    if TCP in pkt:
        tcp = pkt[TCP]
        record["src_port"] = int(tcp.sport)
        record["dst_port"] = int(tcp.dport)
        record["tcp_flags"] = str(tcp.flags)
    elif UDP in pkt:
        udp = pkt[UDP]
        record["src_port"] = int(udp.sport)
        record["dst_port"] = int(udp.dport)
    return record
# --------------------------------------------------------------------------- #
# 3. Sniffing entry point
# --------------------------------------------------------------------------- #
def start_sniffing(
    callback: Callable[[Dict], None],
    iface: Optional[str] = None,
    bpf_filter: Optional[str] = None,
    packet_limit: int = 0,
    timeout: Optional[int] = None,
) -> None:
    """
    Capture packets and pass each parsed record to `callback`.
    Ctrl+C stops cleanly.
    """
    def _handle(pkt) -> None:
        record = parse_packet(pkt)
        if record is not None:
            try:
                callback(record)
            except Exception as exc:
                print(f"[sniffer] callback error: {exc}")
    print("\n[sniffer] Starting capture...")
    print(f"[sniffer] Interface  : {iface or '(default)'}")
    print(f"[sniffer] BPF filter : {bpf_filter or '(none)'}")
    print("[sniffer] Press Ctrl+C to stop.\n")
    try:
        sniff(
            prn=_handle,
            store=False,
            iface=iface,
            filter=bpf_filter,
            count=packet_limit,
            timeout=timeout,
        )
    except KeyboardInterrupt:
        print("\n[sniffer] Stopped by user (Ctrl+C).")
    except PermissionError:
        ensure_admin()
    except OSError as exc:
        print(f"[sniffer] OSError: {exc}")
        print("[sniffer] Check Npcap install and interface name validity.")
        sys.exit(1)
# --------------------------------------------------------------------------- #
# 4. Demo - run this file directly to test capture
# --------------------------------------------------------------------------- #
def _demo_printer(record: Dict) -> None:
    sport = record["src_port"] if record["src_port"] is not None else "-"
    dport = record["dst_port"] if record["dst_port"] is not None else "-"
    flags = record["tcp_flags"] or "-"
    print(
        f"{record['timestamp']}  "
        f"{record['src_ip']:>15}:{str(sport):<5} -> "
        f"{record['dst_ip']:>15}:{str(dport):<5}  "
        f"{record['protocol']:<6} flags={flags:<3} len={record['length']}"
    )
if __name__ == "__main__":
    ensure_admin()
    print_interfaces()
    chosen_iface = sys.argv[1] if len(sys.argv) > 1 else None
    loopback = find_loopback_interface()
    if loopback:
        print(f'\nTip: for localhost tests use:  python packet_sniffer.py "{loopback}"')
    print("\nCapturing 20 packets for the demo...")
    start_sniffing(
        callback=_demo_printer,
        iface=chosen_iface,
        bpf_filter="ip",
        packet_limit=20,
        timeout=30,
    )
    print("\n[demo] Done.")
