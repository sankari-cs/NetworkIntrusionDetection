"""
intrusion_detector.py
=====================
CodeAlpha Cybersecurity Internship - Task 4
Network Intrusion Detection System (NIDS) - Module 2: Intrusion Detection
Responsibility
--------------
Receive parsed packet records (dicts from packet_sniffer.parse_packet)
and apply stateful detection rules to spot malicious patterns:
    1. PORT_SCAN             - one source hitting many distinct ports
    2. REPEATED_CONNECTIONS  - many connection attempts to the same target
    3. POSSIBLE_DOS          - high packet rate from one source
    4. SUSPICIOUS_PORT       - traffic to a curated list of risky ports
    5. NULL_SCAN             - TCP packets with no flags set
Each detection produces an alert dict with a consistent shape, ready for
alert_manager.py to persist and the dashboard to render.
This module does NOT capture packets - feed it output from packet_sniffer.
This module does NOT write logs - hand its alerts to alert_manager.
"""
from __future__ import annotations
import json
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
class IntrusionDetector:
    """
    Stateful rule engine for network intrusion detection.
    Usage
    -----
        detector = IntrusionDetector("rules/detection_rules.json")
        for record in packets:
            alerts = detector.ingest(record)
            for alert in alerts:
                print(alert)
    """
    def __init__(self, rules_path: str = "rules/detection_rules.json"):
        self.rules = self._load_rules(rules_path)
        # Per-source state. Each deque holds recent observation timestamps.
        self._port_scan_track: Dict[str, deque] = defaultdict(deque)
        self._repeated_track: Dict[tuple, deque] = defaultdict(deque)
        self._dos_track: Dict[str, deque] = defaultdict(deque)
        # Per-(source, attack_type) last alert time, for cooldown suppression
        self._cooldown: Dict[tuple, float] = {}
        # Lightweight counters (used by the dashboard later)
        self.packets_ingested = 0
        self.alerts_emitted = 0
    # ------------------------------------------------------------------ #
    # Rule loading
    # ------------------------------------------------------------------ #
    @staticmethod
    def _load_rules(path: str) -> dict:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Rules file not found: {path}")
        with p.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    # ------------------------------------------------------------------ #
    # Public entry point
    # ------------------------------------------------------------------ #
    def ingest(self, record: Dict, now_ts: Optional[float] = None) -> List[Dict]:
        """
        Process one packet record and return a list of alert dicts.
        `now_ts` is optional and defaults to wall-clock time. Tests pass
        synthetic timestamps to exercise time-windowed rules deterministically.
        """
        now = now_ts if now_ts is not None else time.time()
        self.packets_ingested += 1
        alerts: List[Dict] = []
        alerts += self._check_port_scan(record, now)
        alerts += self._check_repeated_connections(record, now)
        alerts += self._check_dos(record, now)
        alerts += self._check_suspicious_port(record, now)
        alerts += self._check_null_scan(record, now)
        alerts = self._apply_cooldown(alerts, now)
        self.alerts_emitted += len(alerts)
        return alerts
    # ------------------------------------------------------------------ #
    # Detector 1: port scan
    # ------------------------------------------------------------------ #
    def _check_port_scan(self, record: Dict, now: float) -> List[Dict]:
        cfg = self.rules["port_scan"]
        if not cfg["enabled"]:
            return []
        if record.get("protocol") != "TCP":
            return []
        flags = record.get("tcp_flags") or ""
        if "S" not in flags or "A" in flags:   # SYN only (not SYN-ACK)
            return []
        dport = record.get("dst_port")
        if dport is None:
            return []
        window = cfg["window_seconds"]
        threshold = cfg["distinct_ports_threshold"]
        src_ip = record["src_ip"]
        tracker = self._port_scan_track[src_ip]
        tracker.append((now, dport))
        # Prune expired entries
        while tracker and now - tracker[0][0] > window:
            tracker.popleft()
        distinct = {p for _, p in tracker}
        if len(distinct) >= threshold:
            return [self._make_alert(
                record, "PORT_SCAN", cfg["severity"],
                {
                    "distinct_ports": len(distinct),
                    "window_seconds": window,
                    "sample_ports": sorted(distinct)[:20],
                },
            )]
        return []
    # ------------------------------------------------------------------ #
    # Detector 2: repeated connections to the same target
    # ------------------------------------------------------------------ #
    def _check_repeated_connections(self, record: Dict, now: float) -> List[Dict]:
        cfg = self.rules["repeated_connections"]
        if not cfg["enabled"]:
            return []
        if record.get("protocol") != "TCP":
            return []
        if record.get("tcp_flags") != "S":     # only fresh SYN attempts
            return []
        if record.get("dst_port") is None:
            return []
        window = cfg["window_seconds"]
        threshold = cfg["connection_threshold"]
        key = (record["src_ip"], record["dst_ip"], record["dst_port"])
        tracker = self._repeated_track[key]
        tracker.append(now)
        while tracker and now - tracker[0] > window:
            tracker.popleft()
        if len(tracker) >= threshold:
            return [self._make_alert(
                record, "REPEATED_CONNECTIONS", cfg["severity"],
                {
                    "attempts": len(tracker),
                    "window_seconds": window,
                    "target": f"{record['dst_ip']}:{record['dst_port']}",
                },
            )]
        return []
    # ------------------------------------------------------------------ #
    # Detector 3: possible DoS
    # ------------------------------------------------------------------ #
    def _check_dos(self, record: Dict, now: float) -> List[Dict]:
        cfg = self.rules["dos_activity"]
        if not cfg["enabled"]:
            return []
        window = cfg["window_seconds"]
        threshold = cfg["packets_in_window_threshold"]
        src_ip = record["src_ip"]
        tracker = self._dos_track[src_ip]
        tracker.append(now)
        while tracker and now - tracker[0] > window:
            tracker.popleft()
        if len(tracker) >= threshold:
            pps = round(len(tracker) / window, 2)
            return [self._make_alert(
                record, "POSSIBLE_DOS", cfg["severity"],
                {
                    "packets_in_window": len(tracker),
                    "window_seconds": window,
                    "approx_pps": pps,
                },
            )]
        return []
    # ------------------------------------------------------------------ #
    # Detector 4: traffic to suspicious ports
    # ------------------------------------------------------------------ #
    def _check_suspicious_port(self, record: Dict, now: float) -> List[Dict]:
        cfg = self.rules["suspicious_ports"]
        if not cfg["enabled"]:
            return []
        dport = record.get("dst_port")
        if dport is None or dport not in cfg["ports"]:
            return []
        port_name = cfg.get("port_names", {}).get(str(dport), "unknown")
        return [self._make_alert(
            record, "SUSPICIOUS_PORT", cfg["severity"],
            {"dst_port": dport, "port_name": port_name},
        )]
    # ------------------------------------------------------------------ #
    # Detector 5: NULL scan (no TCP flags)
    # ------------------------------------------------------------------ #
    def _check_null_scan(self, record: Dict, now: float) -> List[Dict]:
        cfg = self.rules["null_scan"]
        if not cfg["enabled"]:
            return []
        if record.get("protocol") != "TCP":
            return []
        flags = (record.get("tcp_flags") or "").strip()
        if flags in ("", "0", "None"):
            return [self._make_alert(
                record, "NULL_SCAN", cfg["severity"],
                {"note": "TCP packet with no flags set"},
            )]
        return []
    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _make_alert(record: Dict, attack_type: str, severity: str,
                    details: Dict) -> Dict:
        return {
            "timestamp": record.get("timestamp",
                                    datetime.now().isoformat(timespec="seconds")),
            "src_ip": record.get("src_ip"),
            "dst_ip": record.get("dst_ip"),
            "src_port": record.get("src_port"),
            "dst_port": record.get("dst_port"),
            "protocol": record.get("protocol"),
            "attack_type": attack_type,
            "severity": severity,
            "details": details,
        }
    def _apply_cooldown(self, alerts: List[Dict], now: float) -> List[Dict]:
        """Suppress repeated identical alerts from the same source."""
        cooldown = self.rules.get("cooldown_seconds", 30)
        kept: List[Dict] = []
        for alert in alerts:
            key = (alert["src_ip"], alert["attack_type"])
            last = self._cooldown.get(key, 0.0)
            if now - last >= cooldown:
                kept.append(alert)
                self._cooldown[key] = now
        return kept
# ---------------------------------------------------------------------- #
# Standalone self-test (run `python intrusion_detector.py`)
# ---------------------------------------------------------------------- #
def _demo_record(src, dst, sport, dport, proto="TCP", flags="S",
                 ts="2026-11-03T20:00:00", length=56):
    return {
        "timestamp": ts,
        "src_ip": src,
        "dst_ip": dst,
        "protocol": proto,
        "src_port": sport,
        "dst_port": dport,
        "tcp_flags": flags,
        "length": length,
    }
def _run_scenario(name, records, expected_attacks):
    """Feed records into a fresh detector and print a pass/fail line."""
    detector = IntrusionDetector("rules/detection_rules.json")
    attacks = []
    for rec, ts in records:
        attacks += [a["attack_type"] for a in detector.ingest(rec, now_ts=ts)]
    attacks = sorted(set(attacks))
    expected = sorted(set(expected_attacks))
    status = "PASS" if attacks == expected else "FAIL"
    print(f"[{status}] {name}")
    print(f"        expected: {expected}")
    print(f"        got     : {attacks}")
    return status == "PASS"
if __name__ == "__main__":
    print("Intrusion Detector - self-test\n" + "=" * 50)
    passes = 0
    # 1. Port scan - 15 SYNs from same src to 15 distinct ports
    base = 1_700_000_000.0
    records = [
        (_demo_record("10.0.0.99", "10.0.0.1", 40000 + i, 10000 + i),
         base + i * 0.1)
        for i in range(15)
    ]
    passes += _run_scenario("Port scan detection", records, ["PORT_SCAN"])
    # 2. Repeated connections - 20 SYNs to same target port
    records = [
        (_demo_record("10.0.0.50", "10.0.0.2", 40000 + i, 9999),
         base + i * 0.1)
        for i in range(20)
    ]
    passes += _run_scenario("Repeated connections", records,
                            ["REPEATED_CONNECTIONS"])
    # 3. DoS - 200 UDP packets from one source in 2 seconds
    records = [
        (_demo_record("10.0.0.77", "10.0.0.3", 50000, 80,
                      proto="UDP", flags=None),
         base + i * 0.01)
        for i in range(200)
    ]
    passes += _run_scenario("Possible DoS", records, ["POSSIBLE_DOS"])
    # 4. Suspicious port - one SYN to telnet (23)
    records = [(_demo_record("10.0.0.10", "10.0.0.4", 40000, 23), base)]
    passes += _run_scenario("Suspicious port (telnet)",
                            records, ["SUSPICIOUS_PORT"])
    # 5. Clean traffic - normal HTTPS traffic, no alerts expected
    records = [
        (_demo_record("10.0.0.20", "10.0.0.5", 40000 + i, 443, flags="PA"),
         base + i * 0.1)
        for i in range(5)
    ]
    passes += _run_scenario("Clean HTTPS traffic", records, [])
    total = 5
    print("\n" + "=" * 50)
    print(f"Result: {passes}/{total} scenarios passed")
    if passes == total:
        print("All detection rules working correctly.")
    else:
        print("Some scenarios failed - check thresholds or logic.")