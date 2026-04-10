#!/usr/bin/env python3
"""
parse_alerts.py  —  Unified Radware Alert Log Parser

Combines DefensePro session parsing and Kentik attack-cycle parsing into a
single interactive tool.  A main menu lets you pick which parser to run; a
time-range wizard (or INI config) scopes the report to a specific window.

Usage:
    python parse_alerts.py                     # full interactive menu
    python parse_alerts.py --config alert_parser.ini
    python parse_alerts.py --parser dp         # skip main menu, run DefensePro
    python parse_alerts.py --parser kentik     # skip main menu, run Kentik
    python parse_alerts.py --parser both       # run both without asking
    python parse_alerts.py --parser dp --interactive
    python parse_alerts.py --parser kentik --log-dir ./logs --out-file ./out.csv
"""

import argparse
import configparser
import csv
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from itertools import groupby
from pathlib import Path

TS_FMT       = "%Y-%m-%d %H:%M:%S"
DATE_FMT     = "%Y-%m-%d"
DATETIME_FMT = "%Y-%m-%d_%H-%M-%S"
SCRIPT_DIR   = Path(__file__).parent
DEFAULT_CFG  = SCRIPT_DIR / "alert_parser.ini"

# ══════════════════════════════════════════════════════════════════
#  Shared helpers
# ══════════════════════════════════════════════════════════════════

def human_bw(bps: int) -> str:
    if bps >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.2f} Gbps"
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:.1f} Mbps"
    if bps > 0:
        return f"{bps} bps"
    return "N/A"


def human_pps(pps: int) -> str:
    if pps >= 1_000_000:
        return f"{pps / 1_000_000:.2f}M pps"
    if pps >= 1_000:
        return f"{pps / 1_000:.1f}K pps"
    return f"{pps} pps"


def _parse_dt(value: str) -> datetime:
    for fmt in (TS_FMT, DATE_FMT):
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            pass
    raise ValueError(f"Cannot parse '{value}' — use 'YYYY-MM-DD HH:MM:SS' or 'YYYY-MM-DD'.")


def _prompt(label: str, required: bool = True) -> str:
    while True:
        val = input(f"  {label}: ").strip()
        if val or not required:
            return val
        print("  Value is required, please try again.")


def _separator(char: str = "─", width: int = 52) -> str:
    return char * width


# ══════════════════════════════════════════════════════════════════
#  Time-range
# ══════════════════════════════════════════════════════════════════

class TimeRange:
    """Optional inclusive [start, end] filter applied to attack/session start."""

    def __init__(self, start: datetime | None, end: datetime | None):
        self.start = start
        self.end   = end

    @property
    def active(self) -> bool:
        return self.start is not None or self.end is not None

    def contains_dt(self, dt: datetime) -> bool:
        if self.start and dt < self.start:
            return False
        if self.end   and dt > self.end:
            return False
        return True

    def contains_str(self, ts_str: str) -> bool:
        """Convenience wrapper for string timestamps."""
        if not self.active:
            return True
        if not ts_str:
            return False
        try:
            return self.contains_dt(datetime.strptime(ts_str, TS_FMT))
        except ValueError:
            return False

    def label(self) -> str:
        s = self.start.strftime(TS_FMT) if self.start else "—"
        e = self.end.strftime(TS_FMT)   if self.end   else "—"
        return f"{s}  →  {e}"


def _range_from_last_hours(n: float) -> TimeRange:
    end   = datetime.now().replace(second=59, microsecond=0)
    start = end - timedelta(hours=n)
    return TimeRange(start, end)


def _range_from_last_days(n: float) -> TimeRange:
    end   = datetime.now().replace(hour=23, minute=59, second=59, microsecond=0)
    start = (end - timedelta(days=n)).replace(hour=0, minute=0, second=0)
    return TimeRange(start, end)


def range_from_config(cfg: configparser.ConfigParser) -> TimeRange:
    """Build a TimeRange from the [range] section of the config."""
    if not cfg.has_section("range"):
        return TimeRange(None, None)

    def _get(key: str) -> str:
        return cfg.get("range", key, fallback="").strip()

    start_str = _get("start")
    end_str   = _get("end")
    if start_str:
        try:
            start = _parse_dt(start_str)
            end   = _parse_dt(end_str) if end_str else datetime.now()
            return TimeRange(start, end)
        except ValueError as exc:
            print(f"WARNING: Config [range] start/end invalid — {exc}", file=sys.stderr)

    hours_str = _get("last_hours")
    if hours_str:
        try:
            return _range_from_last_hours(float(hours_str))
        except ValueError:
            print("WARNING: Config [range] last_hours invalid — ignoring.", file=sys.stderr)

    days_str = _get("last_days")
    if days_str:
        try:
            return _range_from_last_days(float(days_str))
        except ValueError:
            print("WARNING: Config [range] last_days invalid — ignoring.", file=sys.stderr)

    return TimeRange(None, None)


def interactive_range() -> TimeRange:
    """Prompt the user to define a time-range filter."""
    print()
    print("┌" + _separator("─", 48) + "┐")
    print("│          Time Range Filter Setup               │")
    print("└" + _separator("─", 48) + "┘")
    print()
    print("  [1] Fixed date/time range")
    print("  [2] Last N hours")
    print("  [3] Last N days")
    print("  [4] No filter  (include all records)")
    print()

    choice = ""
    while choice not in ("1", "2", "3", "4"):
        choice = input("  Selection [1-4]: ").strip()

    if choice == "1":
        print()
        print("  Format: YYYY-MM-DD HH:MM:SS  or  YYYY-MM-DD")
        while True:
            try:
                start = _parse_dt(_prompt("Start (inclusive)"))
                break
            except ValueError as exc:
                print(f"  ERROR: {exc}")
        while True:
            try:
                end_raw = _prompt("End   (inclusive, Enter = now)", required=False)
                end = _parse_dt(end_raw) if end_raw else datetime.now()
                break
            except ValueError as exc:
                print(f"  ERROR: {exc}")
        if end < start:
            print("  WARNING: end is before start — swapping.")
            start, end = end, start
        return TimeRange(start, end)

    if choice == "2":
        while True:
            try:
                hours = float(_prompt("Hours back (e.g. 24)"))
                if hours <= 0:
                    raise ValueError("Must be > 0")
                return _range_from_last_hours(hours)
            except ValueError as exc:
                print(f"  ERROR: {exc}")

    if choice == "3":
        while True:
            try:
                days = float(_prompt("Days back (e.g. 7)"))
                if days <= 0:
                    raise ValueError("Must be > 0")
                return _range_from_last_days(days)
            except ValueError as exc:
                print(f"  ERROR: {exc}")

    return TimeRange(None, None)


# ══════════════════════════════════════════════════════════════════
#  Config helpers
# ══════════════════════════════════════════════════════════════════

def load_config(path: Path) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(path, encoding="utf-8")
    return cfg


def _cfg_str(cfg: configparser.ConfigParser, section: str, key: str) -> str:
    return cfg.get(section, key, fallback="").strip()


def _cfg_int(cfg: configparser.ConfigParser, section: str, key: str, default: int) -> int:
    val = _cfg_str(cfg, section, key)
    try:
        return int(val) if val else default
    except ValueError:
        return default


# ══════════════════════════════════════════════════════════════════
#  DefensePro parser
# ══════════════════════════════════════════════════════════════════

def dp_parse_logs(log_files: list) -> tuple[list, list]:
    start_events, end_events = [], []
    for log_file in log_files:
        with open(log_file, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "DEFENSE_PRO" not in line:
                    continue
                m = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
                if not m:
                    continue
                try:
                    ts = datetime.strptime(m.group(1), TS_FMT)
                except ValueError:
                    continue

                m2 = re.search(r"detection source name (\S+?)[\s.]", line)
                sensor = m2.group(1) if m2 else "Unknown"
                m3 = re.search(r"Protected object (\S+):", line)
                po = m3.group(1) if m3 else "Unknown"
                m4 = re.search(r"attack (?:started|ended) on network (\S+)", line)
                net = m4.group(1) if m4 else "Unknown"
                m5 = re.search(r"protocol (\S+) external", line)
                proto = m5.group(1) if m5 else "N/A"
                m_bw = re.search(r"bandwidth (\d+)\(bps\)", line)
                bw = int(m_bw.group(1)) if m_bw else 0

                event = dict(ts=ts, sensor=sensor, po=po, net=net,
                             proto=proto, bw=bw, file=log_file.name)
                if "DFC00701" in line:
                    start_events.append(event)
                elif "DFC00703" in line:
                    end_events.append(event)
    return start_events, end_events


def dp_build_sessions(start_events: list, gap: timedelta) -> list:
    start_events.sort(key=lambda e: (e["sensor"], e["po"], e["net"], e["ts"]))
    sessions = []

    for _key, group_iter in groupby(
        start_events, key=lambda e: (e["sensor"], e["po"], e["net"])
    ):
        evts      = list(group_iter)
        ses_start = evts[0]["ts"]
        ses_end   = evts[0]["ts"]
        max_bw    = 0
        event_cnt = 0
        sensor    = evts[0]["sensor"]
        po        = evts[0]["po"]
        net       = evts[0]["net"]
        proto     = evts[0]["proto"]
        src_file  = evts[0]["file"]

        def _close():
            dur_min = int((ses_end - ses_start).total_seconds() / 60)
            sessions.append({
                "Sensor":          sensor,
                "ProtectedObject": po,
                "TargetNetwork":   net,
                "Protocol":        proto,
                "SessionStart":    ses_start.strftime(TS_FMT),
                "SessionEnd":      ses_end.strftime(TS_FMT),
                "_start_dt":       ses_start,
                "DurationMin":     dur_min,
                "EventCount":      event_cnt,
                "PeakBW_human":    human_bw(max_bw),
                "PeakBW_bps":      max_bw,
                "SourceLogFile":   src_file,
            })

        for i, e in enumerate(evts):
            if i > 0 and (e["ts"] - ses_end) > gap:
                _close()
                ses_start = e["ts"]; ses_end = e["ts"]
                max_bw = 0; event_cnt = 0; src_file = e["file"]
            ses_end = e["ts"]
            if e["bw"] > max_bw:
                max_bw = e["bw"]
            event_cnt += 1

        _close()

    return sessions


def dp_print_summary(sessions: list, start_cnt: int, end_cnt: int) -> None:
    if not sessions:
        print("  No sessions matched.")
        return

    total   = len(sessions)
    durs    = [s["DurationMin"] for s in sessions if s["DurationMin"] > 0]
    avg_dur = sum(durs) / len(durs) if durs else 0

    print()
    print("══════════════════════════════════════════════════════")
    print("  DEFENSEPRO ATTACK SESSION SUMMARY")
    print("══════════════════════════════════════════════════════")
    print(f"  Period      : {sessions[0]['SessionStart']} → {sessions[-1]['SessionStart']}")
    print(f"  Sessions    : {total}")
    print(f"  Raw events  : {start_cnt} start / {end_cnt} end")
    print(f"  Avg duration: {avg_dur:.0f} min")

    def _tbl(label: str, counter: dict) -> None:
        print(f"\n── {label}")
        for name, cnt in sorted(counter.items(), key=lambda x: -x[1]):
            print(f"    {name:<38}  {cnt:>4}  ({cnt / total * 100:.1f}%)")

    by_sensor: dict[str, int] = defaultdict(int)
    by_po:     dict[str, int] = defaultdict(int)
    by_proto:  dict[str, int] = defaultdict(int)
    for s in sessions:
        by_sensor[s["Sensor"]]           += 1
        by_po[s["ProtectedObject"]]      += 1
        by_proto[s["Protocol"]]          += 1

    _tbl("By Sensor",           by_sensor)
    _tbl("By Protected Object", by_po)
    _tbl("By Protocol",         by_proto)

    print(f"\n── Top 15 Most Targeted Networks")
    by_net: dict[str, list] = defaultdict(list)
    for s in sessions:
        by_net[s["TargetNetwork"]].append(s)
    print(f"    {'Network':<22}  {'Sess':>5}  {'Sensors':<28}  {'Protocols':<18}  PeakBW")
    print(f"    {'-'*22}  {'-'*5}  {'-'*28}  {'-'*18}  {'-'*12}")
    for net, grp in sorted(by_net.items(), key=lambda x: -len(x[1]))[:15]:
        sensors   = ", ".join(sorted({s["Sensor"]   for s in grp}))
        protocols = ", ".join(sorted({s["Protocol"] for s in grp}))
        peak      = max(grp, key=lambda s: s["PeakBW_bps"])["PeakBW_human"]
        print(f"    {net:<22}  {len(grp):>5}  {sensors:<28}  {protocols:<18}  {peak}")

    def _row(s: dict) -> str:
        return (
            f"    {s['Sensor']:<18}  {s['ProtectedObject']:<18}  {s['TargetNetwork']:<22}  "
            f"{s['Protocol']:<10}  {s['SessionStart']:<20}  {s['DurationMin']:>7} min  "
            f"{s['EventCount']:>6} evts  {s['PeakBW_human']}"
        )

    hdr = (
        f"    {'Sensor':<18}  {'ProtectedObject':<18}  {'TargetNetwork':<22}  "
        f"{'Protocol':<10}  {'SessionStart':<20}  {'DurMin':>7}      {'Evts':>6}  PeakBW"
    )
    sep = f"    {_separator('-', 130)}"

    print(f"\n── Top 10 Longest Sessions")
    print(hdr); print(sep)
    for s in sorted(sessions, key=lambda s: -s["DurationMin"])[:10]:
        print(_row(s))

    print(f"\n── Top 10 by Peak Bandwidth")
    print(hdr); print(sep)
    for s in sorted(sessions, key=lambda s: -s["PeakBW_bps"])[:10]:
        print(_row(s))

    print(f"\n── Sensor × Protected Object Matrix")
    by_pair: dict[str, int] = defaultdict(int)
    for s in sessions:
        by_pair[f"{s['Sensor']} × {s['ProtectedObject']}"] += 1
    for pair, cnt in sorted(by_pair.items(), key=lambda x: -x[1]):
        print(f"    {pair:<55}  {cnt:>4}")


def run_defensepro(
    log_dir: Path,
    out_file: Path,
    time_range: TimeRange,
    gap_minutes: int,
) -> None:
    print()
    print("┌" + _separator("─", 48) + "┐")
    print("│          DefensePro Attack Session Parser      │")
    print("└" + _separator("─", 48) + "┘")
    print(f"  Log directory : {log_dir}")
    print(f"  Gap threshold : {gap_minutes} minutes")
    print(f"  Output file   : {out_file}")
    print(f"  Time filter   : {time_range.label() if time_range.active else 'none'}")
    print()

    out_file.parent.mkdir(parents=True, exist_ok=True)
    log_files = sorted(log_dir.glob("alert*.log"))
    if not log_files:
        print(f"  ERROR: No alert*.log files found in {log_dir}", file=sys.stderr)
        return

    print(f"  Found {len(log_files)} log file(s): {', '.join(f.name for f in log_files)}")
    print("  Parsing DEFENSE_PRO events...")

    start_events, end_events = dp_parse_logs(log_files)
    print(f"    Start events (DFC00701) : {len(start_events)}")
    print(f"    End events   (DFC00703) : {len(end_events)}")

    gap = timedelta(minutes=gap_minutes)
    all_sessions = dp_build_sessions(start_events, gap)
    print(f"  Total sessions built      : {len(all_sessions)}")

    if time_range.active:
        sessions = [s for s in all_sessions if time_range.contains_dt(s["_start_dt"])]
        print(f"  Sessions within filter    : {len(sessions)}")
    else:
        sessions = all_sessions

    for s in sessions:
        s.pop("_start_dt", None)

    sessions.sort(key=lambda s: s["SessionStart"])

    fieldnames = [
        "Sensor", "ProtectedObject", "TargetNetwork", "Protocol",
        "SessionStart", "SessionEnd", "DurationMin", "EventCount",
        "PeakBW_human", "PeakBW_bps", "SourceLogFile",
    ]
    with open(out_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(sessions)

    print(f"\n  CSV exported: {out_file}  ({len(sessions)} rows)")
    dp_print_summary(sessions, len(start_events), len(end_events))


# ══════════════════════════════════════════════════════════════════
#  Kentik parser
# ══════════════════════════════════════════════════════════════════

def kentik_parse_logs(log_files: list) -> dict:
    attacks: dict = {}
    for log_file in log_files:
        with open(log_file, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "kentik" not in line.lower():
                    continue

                m_ts = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
                ts   = m_ts.group(1) if m_ts else ""

                m_id = re.search(r"(kentik_\d+)", line)
                if not m_id:
                    continue
                kid = m_id.group(1)

                if kid not in attacks:
                    attacks[kid] = {
                        "id": kid, "start": "", "end": "",
                        "net": "", "proto": "",
                        "bw_bps": 0, "pps": 0,
                        "up": [], "down": [],
                        "source_file": log_file.name,
                    }
                a = attacks[kid]

                m = re.search(
                    r"DFC00701.*attack started on network (\S+) protocol (\S+) external ID", line)
                if m:
                    if not a["start"]: a["start"] = ts
                    a["net"] = m.group(1); a["proto"] = m.group(2)
                    m_bw = re.search(r"bandwidth (\d+)\(bps\)", line)
                    if m_bw:
                        bw = int(m_bw.group(1))
                        if bw > a["bw_bps"]: a["bw_bps"] = bw
                    continue

                if re.search(r"DFC00703.*attack ended", line):
                    if not a["end"]: a["end"] = ts
                    continue

                m = re.search(
                    r"DFC00360.*for protected object (\S+)\. Criteria.*bandwidth (\S+) bps rate (\d+) pps", line)
                if m:
                    po, bw2_str, pps = m.group(1), m.group(2), int(m.group(3))
                    if pps > a["pps"]: a["pps"] = pps
                    if bw2_str not in ("N/A", "0"):
                        try:
                            b = int(bw2_str)
                            if b > a["bw_bps"]: a["bw_bps"] = b
                        except ValueError:
                            pass
                    if po not in a["up"]: a["up"].append(po)
                    continue

                m = re.search(r"DFC00361.*for protected object (\S+)\. Criteria", line)
                if m:
                    po = m.group(1)
                    if po not in a["down"]: a["down"].append(po)

    return attacks


def kentik_build_rows(attacks: dict, time_range: TimeRange) -> list:
    rows = []
    for kid in sorted(attacks):
        a = attacks[kid]
        if not time_range.contains_str(a["start"]):
            continue

        dur_min, status = "", "Open"
        if a["start"] and a["end"]:
            try:
                s = datetime.strptime(a["start"], TS_FMT)
                e = datetime.strptime(a["end"],   TS_FMT)
                dur_min = int((e - s).total_seconds() / 60)
                status  = "Completed"
            except ValueError:
                pass

        rows.append({
            "Kentik_ID":          kid,
            "Status":             status,
            "Target_Network":     a["net"],
            "Protocol":           a["proto"],
            "Peak_Bandwidth":     human_bw(a["bw_bps"]) if a["bw_bps"] > 0 else "0 bps",
            "Peak_Bandwidth_bps": a["bw_bps"],
            "Peak_PPS":           human_pps(a["pps"]) if a["pps"] > 0 else "",
            "Peak_PPS_raw":       a["pps"],
            "Attack_Start":       a["start"],
            "Attack_End":         a["end"],
            "Duration_min":       dur_min,
            "Mitigation_UP":      " | ".join(a["up"]),
            "Mitigation_DOWN":    " | ".join(a["down"]),
            "Source_Log_File":    a["source_file"],
        })
    return rows


def kentik_print_summary(rows: list) -> None:
    if not rows:
        print("  No attacks matched.")
        return

    completed    = [r for r in rows if r["Status"] == "Completed"]
    open_attacks = [r for r in rows if r["Status"] == "Open"]
    durs         = [r["Duration_min"] for r in rows if isinstance(r["Duration_min"], int)]
    avg_dur      = sum(durs) / len(durs) if durs else 0

    print()
    print("══════════════════════════════════════════════════════")
    print("  KENTIK ATTACK CYCLE SUMMARY")
    print("══════════════════════════════════════════════════════")
    print(f"  Total attacks   : {len(rows)}")
    print(f"  Completed cycles: {len(completed)}")
    print(f"  Open (no end)   : {len(open_attacks)}")
    print(f"  Avg duration    : {avg_dur:.0f} min")

    top5 = sorted(rows, key=lambda r: -(r["Peak_Bandwidth_bps"] or 0))[:5]
    print(f"\n── Top 5 by Bandwidth")
    print(
        f"    {'Kentik_ID':<20}  {'Target_Network':<22}  "
        f"{'Peak_Bandwidth':<15}  {'Attack_Start':<20}  Duration_min"
    )
    print(f"    {_separator('-', 100)}")
    for r in top5:
        print(
            f"    {r['Kentik_ID']:<20}  {r['Target_Network']:<22}  "
            f"{r['Peak_Bandwidth']:<15}  {r['Attack_Start']:<20}  {r['Duration_min']}"
        )


def run_kentik(
    log_dir: Path,
    out_file: Path,
    time_range: TimeRange,
) -> None:
    print()
    print("┌" + _separator("─", 48) + "┐")
    print("│          Kentik Attack Cycle Parser            │")
    print("└" + _separator("─", 48) + "┘")
    print(f"  Log directory : {log_dir}")
    print(f"  Output file   : {out_file}")
    print(f"  Time filter   : {time_range.label() if time_range.active else 'none'}")
    print()

    out_file.parent.mkdir(parents=True, exist_ok=True)
    log_files = sorted(log_dir.glob("alert*.log"))
    if not log_files:
        print(f"  ERROR: No alert*.log files found in {log_dir}", file=sys.stderr)
        return

    print(f"  Found {len(log_files)} log file(s): {', '.join(f.name for f in log_files)}")
    print("  Parsing Kentik events...")

    attacks = kentik_parse_logs(log_files)
    print(f"  Unique Kentik attack IDs  : {len(attacks)}")

    rows = kentik_build_rows(attacks, time_range)
    if time_range.active:
        print(f"  Attacks within filter     : {len(rows)}")

    fieldnames = [
        "Kentik_ID", "Status", "Target_Network", "Protocol",
        "Peak_Bandwidth", "Peak_Bandwidth_bps", "Peak_PPS", "Peak_PPS_raw",
        "Attack_Start", "Attack_End", "Duration_min",
        "Mitigation_UP", "Mitigation_DOWN", "Source_Log_File",
    ]
    with open(out_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n  CSV exported: {out_file}  ({len(rows)} rows)")
    kentik_print_summary(rows)


# ══════════════════════════════════════════════════════════════════
#  Main menu
# ══════════════════════════════════════════════════════════════════

def main_menu() -> str:
    """Prompt for which parser(s) to run.  Returns 'dp', 'kentik', or 'both'."""
    print()
    print("╔" + _separator("═", 50) + "╗")
    print("║       Radware Alert Log Parser                   ║")
    print("╚" + _separator("═", 50) + "╝")
    print()
    print("  Select report type:")
    print("    [1] DefensePro  — attack session report")
    print("    [2] Kentik      — attack cycle report")
    print("    [3] Both        — run both reports")
    print("    [Q] Quit")
    print()

    while True:
        choice = input("  Selection [1/2/3/Q]: ").strip().upper()
        if choice in ("1", "2", "3", "Q"):
            break
    if choice == "Q":
        print("  Bye.")
        sys.exit(0)
    return {"1": "dp", "2": "kentik", "3": "both"}[choice]


# ══════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        description="Unified Radware Alert Log Parser",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python parse_alerts.py                        # full interactive menu\n"
            "  python parse_alerts.py --parser dp --interactive\n"
            "  python parse_alerts.py --parser both --config alert_parser.ini\n"
            "  python parse_alerts.py --parser kentik --log-dir ./logs\n"
        ),
    )
    parser.add_argument(
        "--parser", choices=["dp", "kentik", "both"],
        help="Parser to run (skips main menu).",
    )
    parser.add_argument(
        "--interactive", "-i", action="store_true",
        help="Prompt for time-range filter interactively.",
    )
    parser.add_argument(
        "--config", "-c",
        nargs="?",
        const=str(DEFAULT_CFG),
        metavar="FILE",
        help=f"INI config file (default: {DEFAULT_CFG.name}).",
    )
    parser.add_argument("--log-dir",     default="", help="Override log directory.")
    parser.add_argument("--out-file",    default="", help="Override output CSV path (single parser only).")
    parser.add_argument("--gap-minutes", type=int, default=0,
                        help="DefensePro session gap in minutes (overrides config, default 10).")
    return parser.parse_args()


# ══════════════════════════════════════════════════════════════════
#  Entry point
# ══════════════════════════════════════════════════════════════════

def main():
    args     = parse_args()
    now      = datetime.now()
    today    = now.strftime(DATE_FMT)
    now_str  = now.strftime(DATETIME_FMT)

    if args.interactive and args.config:
        print("ERROR: --interactive and --config are mutually exclusive.", file=sys.stderr)
        sys.exit(1)

    # ── Load config ───────────────────────────────────────────────
    cfg = configparser.ConfigParser()
    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"ERROR: Config file not found: {config_path}", file=sys.stderr)
            sys.exit(1)
        cfg.read(config_path, encoding="utf-8")
    elif DEFAULT_CFG.exists():
        cfg.read(DEFAULT_CFG, encoding="utf-8")

    # ── Resolve time range ────────────────────────────────────────
    if args.interactive:
        time_range = interactive_range()
    elif cfg.sections():
        time_range = range_from_config(cfg)
    else:
        time_range = TimeRange(None, None)

    # ── Determine which parser(s) to run ─────────────────────────
    parser_choice = args.parser or main_menu()

    # ── Resolve shared log directory ──────────────────────────────
    def _resolve_path(cli_val: str, cfg_section: str, cfg_key: str, default: str) -> Path:
        raw = cli_val or _cfg_str(cfg, cfg_section, cfg_key) or default
        return (SCRIPT_DIR / raw).resolve()

    do_dp     = parser_choice in ("dp",     "both")
    do_kentik = parser_choice in ("kentik", "both")

    # ── DefensePro paths ──────────────────────────────────────────
    if do_dp:
        dp_log_dir = _resolve_path(
            args.log_dir, "defensepro", "log_dir", "Input"
        )
        dp_out_str = (
            args.out_file if (do_dp and not do_kentik and args.out_file)
            else _cfg_str(cfg, "defensepro", "out_file")
            or f"Reports/defensepro_attack_sessions_{now_str}.csv"
        )
        dp_out_file = (
            SCRIPT_DIR / dp_out_str.replace("{datetime}", now_str).replace("{date}", today)
        ).resolve()
        dp_gap      = args.gap_minutes or _cfg_int(cfg, "defensepro", "gap_minutes", 10)

    # ── Kentik paths ──────────────────────────────────────────────
    if do_kentik:
        k_log_dir = _resolve_path(
            args.log_dir, "kentik", "log_dir", "Input"
        )
        k_out_str = (
            args.out_file if (do_kentik and not do_dp and args.out_file)
            else _cfg_str(cfg, "kentik", "out_file")
            or f"Reports/kentik_attack_cycles_{now_str}.csv"
        )
        k_out_file = (
            SCRIPT_DIR / k_out_str.replace("{datetime}", now_str).replace("{date}", today)
        ).resolve()

    # ── Run ───────────────────────────────────────────────────────
    if do_dp:
        run_defensepro(dp_log_dir, dp_out_file, time_range, dp_gap)

    if do_kentik:
        run_kentik(k_log_dir, k_out_file, time_range)

    print()
    print("═" * 52)
    print("  All done.")
    print("═" * 52)


if __name__ == "__main__":
    main()
