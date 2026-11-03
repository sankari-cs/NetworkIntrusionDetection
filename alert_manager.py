"""
alert_manager.py
================
CodeAlpha Cybersecurity Internship - Task 4
Network Intrusion Detection System (NIDS) - Module 3: Alert Management
Responsibility
--------------
Persist alerts produced by intrusion_detector.py to disk and give the
dashboard an easy way to read them back.
Files written
-------------
    logs/alerts.csv   - header row + append-only. Pandas-friendly.
    logs/alerts.json  - JSON array of alert objects. Pretty-printed.
Public API
----------
    AlertManager(csv_path, json_path)    - create/verify files on init
    save_alert(alert: Dict)              - persist one alert
    save_alerts(alerts: List[Dict])      - persist many
    load_alerts() -> List[Dict]          - read all (dashboard uses this)
    stats() -> Dict                      - pre-aggregated counters
    clear()                              - reset both files
Thread-safe: the sniffer callback runs on a background thread, so all
writes go through a Lock.
"""
from __future__ import annotations
import csv
import json
import threading
from pathlib import Path
from typing import Dict, List
CSV_FIELDS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "attack_type",
    "severity",
    "details",
]
class AlertManager:
    """Write and read alert logs. One instance per process is fine."""
    def __init__(
        self,
        csv_path: str = "logs/alerts.csv",
        json_path: str = "logs/alerts.json",
    ):
        self.csv_path = Path(csv_path)
        self.json_path = Path(json_path)
        # Create parent directories if missing
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
        self.json_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._ensure_csv_header()
        self._ensure_json_array()
    # ------------------------------------------------------------------ #
    # Initialisation helpers
    # ------------------------------------------------------------------ #
    def _ensure_csv_header(self) -> None:
        """Create alerts.csv with header row if it doesn't exist yet."""
        if not self.csv_path.exists() or self.csv_path.stat().st_size == 0:
            with self.csv_path.open("w", newline="", encoding="utf-8") as fh:
                csv.DictWriter(fh, fieldnames=CSV_FIELDS).writeheader()
    def _ensure_json_array(self) -> None:
        """Create alerts.json with an empty array if it doesn't exist yet."""
        if not self.json_path.exists() or self.json_path.stat().st_size == 0:
            self.json_path.write_text("[]", encoding="utf-8")
    # ------------------------------------------------------------------ #
    # Public write methods
    # ------------------------------------------------------------------ #
    def save_alert(self, alert: Dict) -> None:
        """Append a single alert to both CSV and JSON."""
        with self._lock:
            self._write_csv(alert)
            self._write_json(alert)
    def save_alerts(self, alerts: List[Dict]) -> None:
        """Append many alerts in one lock acquisition (faster than one-by-one)."""
        with self._lock:
            for alert in alerts:
                self._write_csv(alert)
                self._write_json(alert)
    def _write_csv(self, alert: Dict) -> None:
        """Append one data row. writerow() does NOT re-write the header."""
        row = {field: alert.get(field, "") for field in CSV_FIELDS}
        row["details"] = json.dumps(alert.get("details", {}), ensure_ascii=False)
        with self.csv_path.open("a", newline="", encoding="utf-8") as fh:
            csv.DictWriter(fh, fieldnames=CSV_FIELDS).writerow(row)
    def _write_json(self, alert: Dict) -> None:
        """Read the current array, append, write back."""
        try:
            with self.json_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, list):
                data = []
        except (json.JSONDecodeError, FileNotFoundError):
            data = []
        data.append(alert)
        with self.json_path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
    # ------------------------------------------------------------------ #
    # Public read / aggregate methods
    # ------------------------------------------------------------------ #
    def load_alerts(self) -> List[Dict]:
        """Return every alert as a list of dicts (empty list on error)."""
        if not self.json_path.exists():
            return []
        try:
            with self.json_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            return []
    def stats(self) -> Dict:
        """Pre-aggregated counters for the dashboard's headline metrics."""
        alerts = self.load_alerts()
        by_attack: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        by_source: Dict[str, int] = {}
        for alert in alerts:
            attack = alert.get("attack_type", "UNKNOWN")
            by_attack[attack] = by_attack.get(attack, 0) + 1
            sev = alert.get("severity", "UNKNOWN")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            src = alert.get("src_ip", "UNKNOWN")
            by_source[src] = by_source.get(src, 0) + 1
        return {
            "total_alerts": len(alerts),
            "by_attack": by_attack,
            "by_severity": by_severity,
            "by_source": by_source,
            "last_alert": alerts[-1] if alerts else None,
        }
    def clear(self) -> None:
        """Reset both files. Use before a demo or fresh test run."""
        with self._lock:
            for path in (self.csv_path, self.json_path):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            self._ensure_csv_header()
            self._ensure_json_array()
# ---------------------------------------------------------------------- #
# Self-test - run `python alert_manager.py`
# ---------------------------------------------------------------------- #
if __name__ == "__main__":
    import shutil
    test_dir = Path("logs/_selftest")
    if test_dir.exists():
        shutil.rmtree(test_dir)
    csv_path = test_dir / "alerts.csv"
    json_path = test_dir / "alerts.json"
    print("Alert Manager - self-test\n" + "=" * 50)
    # 1. Initialise - files auto-created
    mgr = AlertManager(csv_path=str(csv_path), json_path=str(json_path))
    assert csv_path.exists(), "CSV file was not created"
    assert json_path.exists(), "JSON file was not created"
    print("[PASS] Files created on init")
    # 2. CSV has exactly one header line
    with csv_path.open("r", encoding="utf-8") as fh:
        lines = fh.read().strip().splitlines()
    assert lines[0].split(",") == CSV_FIELDS, "CSV header wrong"
    assert len(lines) == 1, "CSV should have 1 line (header) only"
    print("[PASS] CSV header written correctly")
    # 3. JSON starts as an empty array
    assert json.loads(json_path.read_text(encoding="utf-8")) == [], "JSON not []"
    print("[PASS] JSON initialised to empty array")
    # 4. Save three alerts
    samples = [
        {
            "timestamp": "2026-11-03T20:01:00",
            "src_ip": "10.0.0.99", "dst_ip": "10.0.0.1",
            "src_port": 50000, "dst_port": 10001,
            "protocol": "TCP", "attack_type": "PORT_SCAN",
            "severity": "HIGH",
            "details": {"distinct_ports": 15, "window_seconds": 10},
        },
        {
            "timestamp": "2026-11-03T20:01:05",
            "src_ip": "10.0.0.50", "dst_ip": "10.0.0.2",
            "src_port": 50001, "dst_port": 9999,
            "protocol": "TCP", "attack_type": "REPEATED_CONNECTIONS",
            "severity": "MEDIUM",
            "details": {"attempts": 20, "window_seconds": 10},
        },
        {
            "timestamp": "2026-11-03T20:01:10",
            "src_ip": "10.0.0.77", "dst_ip": "10.0.0.3",
            "src_port": 50002, "dst_port": 80,
            "protocol": "UDP", "attack_type": "POSSIBLE_DOS",
            "severity": "HIGH",
            "details": {"packets_in_window": 200, "approx_pps": 100.0},
        },
    ]
    for a in samples:
        mgr.save_alert(a)
    print("[PASS] Three alerts saved")
    # 5. CSV now has header + 3 rows = 4 lines
    with csv_path.open("r", encoding="utf-8") as fh:
        lines = [ln for ln in fh.read().strip().splitlines() if ln]
    assert len(lines) == 4, f"CSV should have 4 lines, has {len(lines)}"
    print("[PASS] CSV has header + 3 data rows")
    # 6. JSON array has 3 items
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert len(data) == 3, f"JSON should have 3 alerts, has {len(data)}"
    assert data[0]["attack_type"] == "PORT_SCAN"
    print("[PASS] JSON array has 3 alerts")
    # 7. load_alerts() returns 3
    loaded = mgr.load_alerts()
    assert len(loaded) == 3, f"load_alerts returned {len(loaded)}"
    print("[PASS] load_alerts() returns all 3")
    # 8. stats() aggregates correctly
    s = mgr.stats()
    assert s["total_alerts"] == 3
    assert s["by_attack"]["PORT_SCAN"] == 1
    assert s["by_severity"]["HIGH"] == 2
    assert s["by_source"]["10.0.0.99"] == 1
    assert s["last_alert"]["attack_type"] == "POSSIBLE_DOS"
    print("[PASS] stats() aggregated correctly")
    print(f"        total_alerts={s['total_alerts']}")
    print(f"        by_attack   ={s['by_attack']}")
    print(f"        by_severity ={s['by_severity']}")
    print(f"        by_source   ={s['by_source']}")
    # 9. clear() resets both files
    mgr.clear()
    assert mgr.load_alerts() == [], "clear() did not empty JSON"
    with csv_path.open("r", encoding="utf-8") as fh:
        assert len(fh.read().strip().splitlines()) == 1, "CSV not reset to header only"
    print("[PASS] clear() reset both files")
    # cleanup
    shutil.rmtree(test_dir, ignore_errors=True)
    print("\n" + "=" * 50)
    print("Result: 9/9 alert-manager checks passed")