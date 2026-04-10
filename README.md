# DF / Kentik Alert Log Parsing

Python scripts for parsing Radware DefensePro and Kentik alert logs, grouping raw events into meaningful attack sessions, and exporting structured reports (CSV / HTML / Excel).

---

## Repository Layout

```
DF_Kentik_alert_log_parsing/
│
├── Input/                           ← Place alert*.log / explog_merged files here
├── Reports/                         ← All output files are written here (auto-created)
│
├── radware_reports.py               ← ★ Unified report tool — interactive menu (recommended)
├── alert_parser.ini                 ← ★ Global config for radware_reports.py
│
├── parse_import_processes.py        ← Import-process / BDoS profile parser → Excel
│
├── parse_defensepro_attacks.py      ← DefensePro session parser (basic, no filter)
├── parse_defensepro_attacks_v2.py   ← DefensePro session parser (time-range filter)
├── parse_kentik_attacks.py          ← Kentik attack cycle parser (basic, no filter)
├── parse_kentik_attacks_v2.py       ← Kentik attack cycle parser (time-range filter)
│
├── kentik_report.ini                ← Legacy config (used by the v2 individual scripts)
│
└── README.md
```

> The original PowerShell equivalents (`Parse-*.ps1`) are kept for reference.

---

## Requirements

- **Python 3.10 or later**
- **openpyxl** — required only by `parse_import_processes.py`

```bash
pip install openpyxl
```

---

## Quick-Start

```bash
# 1. Drop log files into Input/
#    alert*.log       → for DefensePro and Kentik parsers
#    explog_merged    → for the import-process parser

# 2. Run the unified report tool (interactive menu)
python radware_reports.py

# 3. Or run fully automated with the config file
python radware_reports.py --config alert_parser.ini

# 4. Find reports in Reports/
```

---

## `radware_reports.py` — Unified Report Tool ★

Single entry point combining DefensePro parsing, Kentik parsing, and weekly HTML trend reporting. Launched without arguments it shows a main menu, then a time-range wizard.

### Main menu

```
╔════════════════════════════════════════════════════════╗
║       Radware Report Tool                              ║
╚════════════════════════════════════════════════════════╝

  Select report type:
    [1] DefensePro   — parse logs → attack session CSV
    [2] Kentik       — parse logs → attack cycle CSV
    [3] Both         — run DefensePro + Kentik parsers
    [4] Weekly HTML  — attack cycle trends (HTML report)
    [Q] Quit
```

### Time-range wizard

```
  [1] Fixed date/time range
  [2] Last N hours
  [3] Last N days
  [4] No filter  (include all records)
```

### Usage

```bash
# Full interactive menu (report selection + time-range wizard)
python radware_reports.py

# Skip main menu — run a specific report
python radware_reports.py --report dp
python radware_reports.py --report kentik
python radware_reports.py --report both
python radware_reports.py --report weekly

# Weekly report with explicit date range
python radware_reports.py --report weekly --start 2026-03-01 --end 2026-03-30

# Automated via config file (no prompts)
python radware_reports.py --config alert_parser.ini
python radware_reports.py --report both --config alert_parser.ini

# Interactive time-range wizard, but skip report menu
python radware_reports.py --report dp --interactive
python radware_reports.py --report both --interactive

# Override paths on the command line
python radware_reports.py --report kentik --log-dir ./logs --out ./out.csv
python radware_reports.py --report dp --gap-minutes 5
python radware_reports.py --report weekly --csv-dir ./Reports --out ./weekly.html
```

### Flag reference

| Flag | Default | Description |
|---|---|---|
| `--report dp\|kentik\|both\|weekly` | *(menu)* | Skip report menu and run the specified report |
| `--interactive` / `-i` | — | Prompt for time-range filter interactively |
| `--config FILE` / `-c` | `alert_parser.ini` | INI config file |
| `--start DATE` | — | Start date for weekly report (`YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS`) |
| `--end DATE` | — | End date for weekly report (`YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS`) |
| `--log-dir DIR` | `Input/` | Override log directory for parser reports |
| `--csv-dir DIR` | `Reports/` | Override CSV source directory for weekly report |
| `--out FILE` | *(from config/default)* | Override output file path |
| `--gap-minutes N` | `10` | DefensePro session inactivity gap in minutes |

> `--interactive` and `--config` are mutually exclusive.  
> `--start` / `--end` take priority over `--interactive` and config for the time range.  
> CLI flags always override config-file values.

---

## Weekly HTML Report

Report type `[4] weekly` reads all `kentik_attack_cycles_*.csv` files from the `Reports/` directory and generates a self-contained HTML dashboard.

**Output:** `Reports/radware_weekly_report_YYYY-MM-DD_HH-MM-SS.html`

### What it contains

- **Overview cards** — total attack count, weeks covered, peak bandwidth/PPS (single attack), most targeted destination IP
- **Four weekly trend charts** (powered by Chart.js):
  - Attack count per week
  - Max peak bandwidth per week (Gbps)
  - Max peak PPS per week (K pps)
  - Top destination IP hit count per week
- **Weekly detail table** — per-week: attack count, max peak BW, max peak PPS, top DST IP, longest attack

### Deduplication

When multiple `kentik_attack_cycles_*.csv` files exist, attacks with the same `Kentik_ID` are deduplicated automatically — only the first occurrence is kept.

### Usage

```bash
# Interactive menu → select [4]
python radware_reports.py

# Skip menu
python radware_reports.py --report weekly

# Restrict to a date range
python radware_reports.py --report weekly --start 2026-03-01 --end 2026-03-30

# Custom CSV source directory and output file
python radware_reports.py --report weekly --csv-dir ./Reports --out ./weekly.html
```

---

## `alert_parser.ini` — Global Config

Used by `radware_reports.py`. Contains three sections.

```ini
# ── Time-range filter (applied to both parsers) ──────────────────
# Priority: start/end  >  last_hours  >  last_days
# Comment out all three to include all records (no filter).
[range]
# start      = 2026-03-18 00:00:00
# end        = 2026-03-26 23:59:59
# last_hours = 24
last_days  = 7

# ── Kentik parser paths ──────────────────────────────────────────
[kentik]
log_dir  = Input
out_file = Reports/kentik_attack_cycles_{datetime}.csv

# ── DefensePro parser paths and settings ─────────────────────────
[defensepro]
log_dir     = Input
out_file    = Reports/defensepro_attack_sessions_{datetime}.csv
gap_minutes = 10
```

The `{datetime}` placeholder in `out_file` is replaced with the timestamp of when the script is run (`YYYY-MM-DD_HH-MM-SS`), so every execution produces a uniquely named file. The legacy `{date}` placeholder (`YYYY-MM-DD`) is also accepted for backwards compatibility.

#### `gap_minutes` explained

DefensePro does not log one record per attack — it emits a fresh `DFC00701 "attack started"` event repeatedly, on every internal reporting interval, for as long as the attack persists.  A single volumetric flood can therefore produce hundreds of individual log lines.

The `gap_minutes` setting controls how those raw events are stitched into a single **session**:

- Events for the same key (`Sensor + ProtectedObject + TargetNetwork`) that arrive within `gap_minutes` of each other are merged into one continuous session.
- When a new event arrives **more than** `gap_minutes` after the previous one, the current session is closed and a brand-new session begins — the silence was long enough to count as a separate attack episode.

```
Events:  ──●──●──●──●──────────────────●──●──●──▶ time
                         gap > 10 min
                        ↑ session split here ↑
Session:       [─── session 1 ───]  [─ session 2 ─]
```

**Choosing a value:**

| `gap_minutes` | Behaviour |
|---|---|
| `5` | Strict — even short pauses create separate sessions |
| `10` | Default — good balance for most environments |
| `20` | Lenient — keeps slow, intermittent floods as one session |

> **Rule of thumb:** set `gap_minutes` to roughly the longest quiet interval that still belongs to the same attack wave in your environment.

---

## Individual Scripts

### `parse_defensepro_attacks.py` / `parse_defensepro_attacks_v2.py`

Parses all `alert*.log` files for `DEFENSE_PRO`-sourced events (`DFC00701` start / `DFC00703` end) and groups individual detections into attack sessions using an inactivity-gap rule.

**Output:** `Reports/defensepro_attack_sessions_YYYY-MM-DD.csv`

#### Output columns

| Column | Description |
|---|---|
| Sensor | Detection source name |
| ProtectedObject | Protected object name |
| TargetNetwork | Target IP / network |
| Protocol | Attack protocol |
| SessionStart | Session start timestamp |
| SessionEnd | Session end timestamp |
| DurationMin | Session duration in minutes |
| EventCount | Number of raw detection events in the session |
| PeakBW_human | Peak bandwidth (human-readable, e.g. `1.2 Gbps`) |
| PeakBW_bps | Peak bandwidth in bps (numeric) |
| SourceLogFile | Originating log file name |

#### Usage

```bash
# Basic (no time filter)
python parse_defensepro_attacks.py
python parse_defensepro_attacks.py --log-dir ./logs --gap-minutes 5

# v2 — interactive time-range wizard
python parse_defensepro_attacks_v2.py --interactive

# v2 — config-file driven
python parse_defensepro_attacks_v2.py --config kentik_report.ini
```

| Flag | Default | Description |
|---|---|---|
| `--log-dir` | `Input/` | Directory containing `alert*.log` files |
| `--out-file` | `Reports/defensepro_attack_sessions_<date>.csv` | Output CSV path |
| `--gap-minutes` | `10` | Inactivity gap in minutes that splits two sessions |
| `--interactive` / `-i` | — | *(v2 only)* Interactive time-range wizard |
| `--config FILE` / `-c` | `kentik_report.ini` | *(v2 only)* INI config file |

---

### `parse_kentik_attacks.py` / `parse_kentik_attacks_v2.py`

Parses all `alert*.log` files for Kentik-originated attack cycles (`kentik_NNNN` IDs) and correlates start (`DFC00701`), end (`DFC00703`), and mitigation workflow events (`DFC00360` UP / `DFC00361` DOWN).

**Output:** `Reports/kentik_attack_cycles_YYYY-MM-DD.csv`

#### Output columns

| Column | Description |
|---|---|
| Kentik_ID | Unique Kentik attack identifier |
| Status | `Completed` or `Open` (no end event seen) |
| Target_Network | Target IP / network |
| Protocol | Attack protocol |
| Peak_Bandwidth | Peak bandwidth (human-readable) |
| Peak_Bandwidth_bps | Peak bandwidth in bps (numeric) |
| Peak_PPS | Peak packets-per-second (human-readable) |
| Peak_PPS_raw | Peak PPS (numeric) |
| Attack_Start | Attack start timestamp |
| Attack_End | Attack end timestamp |
| Duration_min | Duration in minutes |
| Mitigation_UP | Protected objects that triggered mitigation |
| Mitigation_DOWN | Protected objects that cleared mitigation |
| Source_Log_File | Originating log file name |

#### Usage

```bash
# Basic (no time filter)
python parse_kentik_attacks.py
python parse_kentik_attacks.py --log-dir ./logs --out-file ./out.csv

# v2 — interactive time-range wizard
python parse_kentik_attacks_v2.py --interactive

# v2 — config-file driven
python parse_kentik_attacks_v2.py --config kentik_report.ini
```

| Flag | Default | Description |
|---|---|---|
| `--log-dir` | `Input/` | Directory containing `alert*.log` files |
| `--out-file` | `Reports/kentik_attack_cycles_<date>.csv` | Output CSV path |
| `--interactive` / `-i` | — | *(v2 only)* Interactive time-range wizard |
| `--config FILE` / `-c` | `kentik_report.ini` | *(v2 only)* INI config file |

---

### `parse_import_processes.py`

Parses a Radware `explog_merged` file and extracts import process details into a two-sheet Excel workbook.

**Output:** `Reports/import_processes.xlsx`

**Requires:** `pip install openpyxl`

#### Output sheets

| Sheet | Contents |
|---|---|
| Import Processes | Timestamp, policy name, IP/subnet, table key, signature, OOS profile, BDoS profile, action, port, failed steps, result, imported file |
| BDoS Profile Config | Full behavioral-DoS profile parameter set per import: SYN, UDP, ICMP, IGMP, RST, SA, frag rates, inbound/outbound thresholds, queue depths, tracking, profiling, sensitivity, rate limiting, burst suppression |

#### Usage

```bash
# Default: reads Input/explog_merged → writes Reports/import_processes.xlsx
python parse_import_processes.py

# Custom paths
python parse_import_processes.py --log-file ./path/to/explog_merged
python parse_import_processes.py --log-file ./explog_merged --output ./out.xlsx
```

| Flag | Default | Description |
|---|---|---|
| `--log-file` | `Input/explog_merged` | Path to the `explog_merged` file |
| `--output` | `Reports/import_processes.xlsx` | Output Excel file path |

---

## `kentik_report.ini` — Legacy Config

Used by the standalone `parse_defensepro_attacks_v2.py` and `parse_kentik_attacks_v2.py` scripts.

```ini
[range]
# start      = 2026-03-18 00:00:00
# end        = 2026-03-26 23:59:59
# last_hours = 24
last_days  = 7

[paths]
log_dir  = Input
out_file = Reports/kentik_attack_cycles_{datetime}.csv

[defensepro]
log_dir  = Input
out_file = Reports/defensepro_attack_sessions_{datetime}.csv
```

---

## Script Comparison

| Script | Reports | Time filter | Config file | Recommended |
|---|---|---|---|---|
| `radware_reports.py` | DP + Kentik + Weekly HTML | Interactive + config + CLI `--start`/`--end` | `alert_parser.ini` | ✅ Primary |
| `parse_defensepro_attacks_v2.py` | DefensePro | Interactive + config | `kentik_report.ini` | Standalone |
| `parse_kentik_attacks_v2.py` | Kentik | Interactive + config | `kentik_report.ini` | Standalone |
| `parse_defensepro_attacks.py` | DefensePro | None | — | Basic / scripting |
| `parse_kentik_attacks.py` | Kentik | None | — | Basic / scripting |
| `parse_import_processes.py` | Import log | N/A | — | Always |
