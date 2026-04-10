#!/usr/bin/env python3
"""
weekly_report.py  —  Kentik Weekly Attack Trends HTML Report

Reads all kentik_attack_cycles_*.csv files from the Reports/ folder,
deduplicates records by Kentik_ID, groups by calendar-month week (days 1–7, 8–14, 15–21, 22–28, 29–end), and
generates an HTML report with:
  • Attacks / detections count per week
  • Max peak bandwidth per week
  • Top-1 most targeted DST IP per week
  • Top-1 longest attack per week

Usage:
    python weekly_report.py
    python weekly_report.py --start 2026-03-01 --end 2026-03-30
    python weekly_report.py --csv-dir ./Reports --out ./Reports/weekly.html
    python weekly_report.py --config alert_parser.ini
"""

import argparse
import calendar
import configparser
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

SCRIPT_DIR   = Path(__file__).parent
REPORTS_DIR  = SCRIPT_DIR / "Reports"
TS_FMT       = "%Y-%m-%d %H:%M:%S"
DATE_FMT     = "%Y-%m-%d"
DATETIME_FMT = "%Y-%m-%d_%H-%M-%S"

# ══════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════

def human_bw(bps: int) -> str:
    if bps >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.2f} Gbps"
    if bps >= 1_000_000:
        return f"{bps / 1_000_000:.1f} Mbps"
    if bps > 0:
        return f"{bps:,} bps"
    return "N/A"


def human_pps(pps: int) -> str:
    if pps >= 1_000_000:
        return f"{pps / 1_000_000:.2f}M pps"
    if pps >= 1_000:
        return f"{pps / 1_000:.1f}K pps"
    if pps > 0:
        return f"{pps} pps"
    return "N/A"


def format_duration(minutes: int) -> str:
    if minutes <= 0:
        return "N/A"
    if minutes >= 60:
        h = minutes // 60
        m = minutes % 60
        return f"{h}h {m:02d}m" if m else f"{h}h"
    return f"{minutes} min"


def _parse_dt(s: str) -> "datetime | None":
    for fmt in (TS_FMT, DATE_FMT):
        try:
            return datetime.strptime(s.strip(), fmt)
        except ValueError:
            pass
    return None


# ══════════════════════════════════════════════════════════════════
#  Config
# ══════════════════════════════════════════════════════════════════

def load_config(path: Path) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(path, encoding="utf-8")
    return cfg


def _cfg(cfg: configparser.ConfigParser, section: str, key: str) -> str:
    return cfg.get(section, key, fallback="").strip()


def range_from_config(cfg: configparser.ConfigParser):
    """Returns (start_dt | None, end_dt | None)."""
    if not cfg.has_section("range"):
        return None, None
    start_s = _cfg(cfg, "range", "start")
    end_s   = _cfg(cfg, "range", "end")
    if start_s:
        start = _parse_dt(start_s)
        end   = _parse_dt(end_s) if end_s else datetime.now()
        if start:
            return start, end
    hours_s = _cfg(cfg, "range", "last_hours")
    if hours_s:
        try:
            n = float(hours_s)
            end   = datetime.now()
            start = end - timedelta(hours=n)
            return start, end
        except ValueError:
            pass
    days_s = _cfg(cfg, "range", "last_days")
    if days_s:
        try:
            n = float(days_s)
            end   = datetime.now().replace(hour=23, minute=59, second=59)
            start = (end - timedelta(days=n)).replace(hour=0, minute=0, second=0)
            return start, end
        except ValueError:
            pass
    return None, None


# ══════════════════════════════════════════════════════════════════
#  Data loading
# ══════════════════════════════════════════════════════════════════

def find_csv_files(csv_dir: Path) -> list:
    files = sorted(csv_dir.glob("kentik_attack_cycles_*.csv"))
    if not files:
        print(f"WARNING: no kentik_attack_cycles_*.csv found in {csv_dir}", file=sys.stderr)
    return files


def load_attacks(csv_files: list,
                 start: "datetime | None",
                 end:   "datetime | None") -> list:
    seen     = set()
    attacks  = []
    skipped_range = 0
    skipped_dup   = 0

    for f in csv_files:
        with open(f, encoding="utf-8", newline="", errors="replace") as fh:
            for row in csv.DictReader(fh):
                kid = row.get("Kentik_ID", "").strip()
                s   = row.get("Attack_Start", "").strip()
                dt  = _parse_dt(s) if s else None

                # Date-range filter
                if dt:
                    if start and dt < start:
                        skipped_range += 1
                        continue
                    if end and dt > end:
                        skipped_range += 1
                        continue

                # Deduplication by Kentik_ID
                if kid:
                    if kid in seen:
                        skipped_dup += 1
                        continue
                    seen.add(kid)

                row["_dt"] = dt
                attacks.append(row)

    print(f"  Loaded  : {len(attacks):,} unique attacks")
    if skipped_range:
        print(f"  Filtered: {skipped_range:,} outside date range")
    if skipped_dup:
        print(f"  Deduped : {skipped_dup:,} duplicates removed")
    return attacks


# ══════════════════════════════════════════════════════════════════
#  Weekly grouping & stats
# ══════════════════════════════════════════════════════════════════

def _month_week_num(dt: datetime) -> int:
    """Week-of-month: 1 = days 1-7, 2 = days 8-14, 3 = 15-21, 4 = 22-28, 5 = 29-end."""
    return (dt.day - 1) // 7 + 1


def _month_week_sort_key(dt: datetime) -> str:
    """Sortable string YYYY-MM-W# so it orders correctly across months and years."""
    return f"{dt.year:04d}-{dt.month:02d}-W{_month_week_num(dt)}"


def _month_week_label(dt: datetime) -> str:
    """Human label e.g. 'Mar Wk1  Mar 01–07'."""
    wn        = _month_week_num(dt)
    start_day = (wn - 1) * 7 + 1
    last_day  = calendar.monthrange(dt.year, dt.month)[1]
    end_day   = min(start_day + 6, last_day)
    start_dt  = dt.replace(day=start_day)
    end_dt    = dt.replace(day=end_day)
    return f"{start_dt.strftime('%b')} Wk{wn}  {start_dt.strftime('%b %d')}–{end_dt.strftime('%b %d')}"


def group_by_week(attacks: list) -> dict:
    """Returns dict {week_sort_key: {'label': str, 'rows': [...]}}.

    Weeks are aligned to calendar-month days:
      Wk1 = days  1-7    Wk2 = days  8-14
      Wk3 = days 15-21   Wk4 = days 22-28   Wk5 = days 29-end
    Spans multiple months correctly (each month has its own Wk1..Wk5).
    """
    buckets: dict[str, dict] = {}
    for row in attacks:
        dt = row.get("_dt")
        if dt is None:
            continue
        key   = _month_week_sort_key(dt)
        label = _month_week_label(dt)
        if key not in buckets:
            buckets[key] = {
                "label": label,
                "rows":  [],
            }
        buckets[key]["rows"].append(row)
    return dict(sorted(buckets.items()))


def compute_weekly_stats(rows: list) -> dict:
    count      = len(rows)
    max_bw_bps = 0
    max_pps    = 0
    top_dur_min = 0
    top_dur_ip  = "N/A"
    top_dur_start = ""
    dst_counts: dict[str, int] = defaultdict(int)

    for r in rows:
        bps = int(r.get("Peak_Bandwidth_bps") or 0)
        pps = int(r.get("Peak_PPS_raw")       or 0)
        dur = int(r.get("Duration_min")        or 0)
        ip  = (r.get("Target_Network") or "").split("/")[0].strip() or "N/A"

        if bps > max_bw_bps:
            max_bw_bps = bps
        if pps > max_pps:
            max_pps = pps
        if dur > top_dur_min:
            top_dur_min   = dur
            top_dur_ip    = ip
            top_dur_start = r.get("Attack_Start", "")
        dst_counts[ip] += 1

    top_dst_ip, top_dst_cnt = (
        max(dst_counts.items(), key=lambda x: x[1])
        if dst_counts else ("N/A", 0)
    )

    return {
        "count":         count,
        "max_bw_bps":    max_bw_bps,
        "max_bw_human":  human_bw(max_bw_bps),
        "max_pps":       max_pps,
        "max_pps_human": human_pps(max_pps),
        "top_dst_ip":    top_dst_ip,
        "top_dst_count": top_dst_cnt,
        "top_dur_ip":    top_dur_ip,
        "top_dur_min":   top_dur_min,
        "top_dur_human": format_duration(top_dur_min),
        "top_dur_start": top_dur_start,
    }


# ══════════════════════════════════════════════════════════════════
#  HTML generation
# ══════════════════════════════════════════════════════════════════

def _bw_for_chart(bps: int) -> float:
    """Convert bps → Gbps for chart axis (easier to read)."""
    return round(bps / 1_000_000_000, 3)


def generate_html(weeks: dict, start_dt, end_dt, csv_files: list) -> str:
    now_str      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    start_label  = start_dt.strftime("%Y-%m-%d") if start_dt else "All time"
    end_label    = end_dt.strftime("%Y-%m-%d")   if end_dt   else "All time"
    range_label  = f"{start_label}  →  {end_label}"

    # Aggregate across all weeks
    all_rows      = [r for w in weeks.values() for r in w["rows"]]
    total_attacks = len(all_rows)
    total_weeks   = len(weeks)

    global_max_bw  = max((int(r.get("Peak_Bandwidth_bps") or 0) for r in all_rows), default=0)
    global_max_pps = max((int(r.get("Peak_PPS_raw")       or 0) for r in all_rows), default=0)

    global_dst: dict[str, int] = defaultdict(int)
    for r in all_rows:
        ip = (r.get("Target_Network") or "").split("/")[0].strip()
        if ip:
            global_dst[ip] += 1
    global_top_dst, global_top_dst_cnt = (
        max(global_dst.items(), key=lambda x: x[1]) if global_dst else ("N/A", 0)
    )

    # Per-week computed stats
    week_stats = {}
    for key, w in weeks.items():
        week_stats[key] = compute_weekly_stats(w["rows"])

    # Chart data arrays
    chart_labels      = json.dumps([w["label"] for w in weeks.values()])
    chart_counts      = json.dumps([week_stats[k]["count"] for k in weeks])
    chart_bw_gbps     = json.dumps([_bw_for_chart(week_stats[k]["max_bw_bps"]) for k in weeks])
    chart_pps_k       = json.dumps([round(week_stats[k]["max_pps"] / 1000, 1) for k in weeks])
    chart_dst_counts  = json.dumps([week_stats[k]["top_dst_count"] for k in weeks])
    chart_dst_ips     = json.dumps([week_stats[k]["top_dst_ip"] for k in weeks])

    # Table rows
    table_rows_html = ""
    for i, (key, w) in enumerate(weeks.items()):
        s = week_stats[key]
        row_class = "even" if i % 2 == 0 else "odd"
        peak_display = s["max_bw_human"] if s["max_bw_bps"] > 0 else s["max_pps_human"]
        table_rows_html += f"""
            <tr class="{row_class}">
                <td class="week-col"><strong>{w["label"]}</strong></td>
                <td class="num-col">{s["count"]:,}</td>
                <td>{s["max_bw_human"]}</td>
                <td>{s["max_pps_human"]}</td>
                <td class="ip-col">{s["top_dst_ip"]}<span class="badge">{s["top_dst_count"]}x</span></td>
                <td class="ip-col">{s["top_dur_ip"]}<br><span class="sub">{s["top_dur_human"]}
                    {(" · " + s["top_dur_start"]) if s["top_dur_start"] else ""}</span></td>
            </tr>"""

    # Source files list
    file_list = "<br>".join(f.name for f in csv_files) if csv_files else "N/A"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Radware Weekly Attack Trends Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f0f2f5;
            color: #2c3e50;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1300px;
            margin: 0 auto;
            background: #fff;
            box-shadow: 0 4px 24px rgba(0,0,0,.12);
            border-radius: 10px;
            overflow: hidden;
        }}

        /* ─── Header ─── */
        .header {{
            background: linear-gradient(135deg, #003f7f 0%, #005bb5 60%, #0073e6 100%);
            color: #fff;
            padding: 36px 40px 28px;
        }}
        .header h1 {{ font-size: 26px; font-weight: 700; letter-spacing: .5px; }}
        .header .subtitle {{ margin-top: 6px; font-size: 14px; opacity: .85; }}
        .header .meta {{ margin-top: 14px; font-size: 12px; opacity: .7; display: flex; gap: 30px; flex-wrap: wrap; }}
        .header .meta span {{ display: flex; align-items: center; gap: 6px; }}

        /* ─── Content ─── */
        .content {{ padding: 32px 40px; }}
        .section {{ margin-bottom: 40px; }}
        .section-title {{
            font-size: 17px; font-weight: 700; color: #003f7f;
            border-left: 4px solid #0073e6; padding-left: 12px;
            margin-bottom: 18px;
        }}

        /* ─── Stat cards ─── */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 8px;
        }}
        .stat-card {{
            background: #f7f9fc;
            border: 1px solid #dde3ef;
            border-radius: 8px;
            padding: 20px 18px;
            text-align: center;
            transition: box-shadow .2s;
        }}
        .stat-card:hover {{ box-shadow: 0 4px 14px rgba(0,63,127,.12); }}
        .stat-value {{
            font-size: 26px; font-weight: 800;
            color: #003f7f; line-height: 1.1;
        }}
        .stat-value.large-text {{ font-size: 18px; }}
        .stat-value.xlarge-text {{ font-size: 14px; word-break: break-all; }}
        .stat-label {{
            font-size: 12px; color: #6c757d;
            margin-top: 6px; text-transform: uppercase; letter-spacing: .6px;
        }}
        .stat-sub {{ font-size: 11px; color: #999; margin-top: 3px; }}

        /* ─── Chart containers ─── */
        .chart-row {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-bottom: 8px;
        }}
        @media (max-width: 860px) {{ .chart-row {{ grid-template-columns: 1fr; }} }}
        .chart-box {{
            background: #f7f9fc;
            border: 1px solid #dde3ef;
            border-radius: 8px;
            padding: 20px;
        }}
        .chart-title {{
            font-size: 13px; font-weight: 600; color: #003f7f;
            margin-bottom: 14px; text-align: center;
        }}

        /* ─── Table ─── */
        table {{
            width: 100%; border-collapse: collapse; font-size: 13px;
        }}
        thead tr {{
            background: #003f7f; color: #fff;
        }}
        thead th {{
            padding: 11px 14px; text-align: left;
            font-weight: 600; white-space: nowrap;
        }}
        tbody tr.even {{ background: #f7f9fc; }}
        tbody tr.odd  {{ background: #fff; }}
        tbody tr:hover {{ background: #e8f0fa; }}
        tbody td {{
            padding: 10px 14px; border-bottom: 1px solid #e9ecef;
            vertical-align: top;
        }}
        .week-col  {{ font-size: 12px; white-space: nowrap; }}
        .num-col   {{ text-align: right; font-weight: 700; color: #003f7f; }}
        .ip-col    {{ font-family: 'Consolas', monospace; font-size: 12px; }}
        .badge {{
            display: inline-block; background: #0073e6; color: #fff;
            border-radius: 10px; padding: 1px 7px; font-size: 11px;
            margin-left: 6px; font-family: 'Segoe UI', sans-serif;
        }}
        .sub {{ font-size: 11px; color: #888; }}

        /* ─── Footer ─── */
        .footer {{
            background: #f0f2f5; border-top: 1px solid #dde3ef;
            padding: 16px 40px; font-size: 11px; color: #888;
            display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px;
        }}
    </style>
</head>
<body>
<div class="container">

    <!-- HEADER -->
    <div class="header">
        <h1>Radware Weekly Attack Trends Report</h1>
        <div class="subtitle">DDoS Detection &amp; Mitigation — Weekly Summary</div>
        <div class="meta">
            <span>&#128197; Period: <strong>{range_label}</strong></span>
            <span>&#128344; Generated: {now_str}</span>
            <span>&#128221; Source files: {len(csv_files)}</span>
        </div>
    </div>

    <div class="content">

        <!-- OVERVIEW STATS -->
        <div class="section">
            <div class="section-title">Overview</div>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{total_attacks:,}</div>
                    <div class="stat-label">Total Attacks</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{total_weeks}</div>
                    <div class="stat-label">Weeks Covered</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value{'  large-text' if len(human_bw(global_max_bw)) > 10 else ''}">{human_bw(global_max_bw)}</div>
                    <div class="stat-label">Peak Bandwidth (single attack)</div>
                    <div class="stat-sub">{human_pps(global_max_pps)} peak PPS</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value xlarge-text">{global_top_dst}</div>
                    <div class="stat-label">Most Targeted DST IP</div>
                    <div class="stat-sub">{global_top_dst_cnt:,} attacks</div>
                </div>
            </div>
        </div>

        <!-- CHARTS -->
        <div class="section">
            <div class="section-title">Weekly Trends</div>
            <div class="chart-row">
                <div class="chart-box">
                    <div class="chart-title">&#128200; Attack Count per Week</div>
                    <canvas id="chartCount"></canvas>
                </div>
                <div class="chart-box">
                    <div class="chart-title">&#9889; Max Peak Bandwidth per Week (Gbps)</div>
                    <canvas id="chartBW"></canvas>
                </div>
            </div>
            <div class="chart-row" style="margin-top:24px">
                <div class="chart-box">
                    <div class="chart-title">&#128246; Max Peak PPS per Week (K pps)</div>
                    <canvas id="chartPPS"></canvas>
                </div>
                <div class="chart-box">
                    <div class="chart-title">&#127919; Top DST IP Hit Count per Week</div>
                    <canvas id="chartDST"></canvas>
                </div>
            </div>
        </div>

        <!-- WEEKLY DETAIL TABLE -->
        <div class="section">
            <div class="section-title">Weekly Detail</div>
            <div style="overflow-x:auto">
                <table>
                    <thead>
                        <tr>
                            <th>Week</th>
                            <th style="text-align:right">Attacks</th>
                            <th>Max Peak BW</th>
                            <th>Max Peak PPS</th>
                            <th>Top DST IP (count)</th>
                            <th>Longest Attack</th>
                        </tr>
                    </thead>
                    <tbody>
                        {table_rows_html}
                    </tbody>
                </table>
            </div>
        </div>

    </div><!-- /content -->

    <!-- FOOTER -->
    <div class="footer">
        <span>Radware Weekly Attack Trends Report &mdash; {now_str}</span>
    </div>

</div><!-- /container -->

<script>
const LABELS    = {chart_labels};
const COUNTS    = {chart_counts};
const BW_GBPS   = {chart_bw_gbps};
const PPS_K     = {chart_pps_k};
const DST_CNT   = {chart_dst_counts};
const DST_IPS   = {chart_dst_ips};

const BLUE_PALETTE = [
    'rgba(0,  63, 127, 0.78)',
    'rgba(0, 115, 230, 0.78)',
    'rgba(0, 163, 224, 0.78)',
    'rgba(0, 191, 255, 0.78)',
    'rgba(0, 214, 198, 0.78)',
    'rgba(0, 230, 160, 0.78)',
];

function barColor(n) {{
    return Array.from({{length: n}}, (_, i) => BLUE_PALETTE[i % BLUE_PALETTE.length]);
}}

const commonOpts = {{
    responsive: true,
    plugins: {{
        legend: {{ display: false }},
        tooltip: {{ mode: 'index', intersect: false }},
    }},
    scales: {{
        x: {{
            ticks: {{ font: {{ size: 11 }}, maxRotation: 35 }},
            grid:  {{ color: 'rgba(0,0,0,.05)' }},
        }},
        y: {{
            beginAtZero: true,
            ticks: {{ font: {{ size: 11 }} }},
            grid:  {{ color: 'rgba(0,0,0,.05)' }},
        }},
    }},
}};

new Chart(document.getElementById('chartCount'), {{
    type: 'bar',
    data: {{
        labels: LABELS,
        datasets: [{{
            label: 'Attacks',
            data: COUNTS,
            backgroundColor: barColor(LABELS.length),
            borderRadius: 5,
        }}]
    }},
    options: commonOpts,
}});

new Chart(document.getElementById('chartBW'), {{
    type: 'bar',
    data: {{
        labels: LABELS,
        datasets: [{{
            label: 'Gbps',
            data: BW_GBPS,
            backgroundColor: barColor(LABELS.length),
            borderRadius: 5,
        }}]
    }},
    options: {{
        ...commonOpts,
        scales: {{
            ...commonOpts.scales,
            y: {{
                ...commonOpts.scales.y,
                ticks: {{
                    ...commonOpts.scales.y.ticks,
                    callback: v => v.toFixed(1) + ' G',
                }}
            }}
        }}
    }},
}});

new Chart(document.getElementById('chartPPS'), {{
    type: 'bar',
    data: {{
        labels: LABELS,
        datasets: [{{
            label: 'K pps',
            data: PPS_K,
            backgroundColor: barColor(LABELS.length),
            borderRadius: 5,
        }}]
    }},
    options: {{
        ...commonOpts,
        scales: {{
            ...commonOpts.scales,
            y: {{
                ...commonOpts.scales.y,
                ticks: {{
                    ...commonOpts.scales.y.ticks,
                    callback: v => v.toFixed(0) + ' K',
                }}
            }}
        }}
    }},
}});

new Chart(document.getElementById('chartDST'), {{
    type: 'bar',
    data: {{
        labels: DST_IPS,
        datasets: [{{
            label: 'Attacks on top DST IP',
            data: DST_CNT,
            backgroundColor: barColor(LABELS.length),
            borderRadius: 5,
        }}]
    }},
    options: {{
        ...commonOpts,
        plugins: {{
            ...commonOpts.plugins,
            tooltip: {{
                callbacks: {{
                    title: (items) => DST_IPS[items[0].dataIndex],
                    beforeLabel: (ctx) => 'Week: ' + LABELS[ctx.dataIndex],
                    label: (ctx) => 'Hit count: ' + ctx.parsed.y,
                }},
            }},
        }},
        scales: {{
            ...commonOpts.scales,
            x: {{
                ...commonOpts.scales.x,
                ticks: {{
                    font: {{ size: 11 }},
                    maxRotation: 35,
                }}
            }},
            y: {{
                ...commonOpts.scales.y,
                ticks: {{
                    ...commonOpts.scales.y.ticks,
                    callback: v => Number.isInteger(v) ? v : '',
                }}
            }}
        }}
    }},
}});
</script>

</body>
</html>
"""
    return html


# ══════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════

def build_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate Kentik weekly HTML report")
    p.add_argument("--config",  default=str(SCRIPT_DIR / "alert_parser.ini"),
                   help="INI config file (default: alert_parser.ini)")
    p.add_argument("--csv-dir", default=str(REPORTS_DIR),
                   help="Folder containing kentik_attack_cycles_*.csv files")
    p.add_argument("--start",   help="Start date/time  YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")
    p.add_argument("--end",     help="End date/time    YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")
    p.add_argument("--out",     help="Output HTML file (default: Reports/kentik_weekly_<ts>.html)")
    return p.parse_args()


def main() -> None:
    args = build_args()

    # ── resolve date range ──────────────────────────────────────
    start_dt: "datetime | None" = None
    end_dt:   "datetime | None" = None

    # CLI args override config
    if args.start:
        start_dt = _parse_dt(args.start)
        if not start_dt:
            sys.exit(f"ERROR: cannot parse --start '{args.start}'")
    if args.end:
        end_dt = _parse_dt(args.end)
        if not end_dt:
            sys.exit(f"ERROR: cannot parse --end '{args.end}'")
        # Date-only string → treat as end of that day
        if len(args.end.strip()) == 10:
            end_dt = end_dt.replace(hour=23, minute=59, second=59)

    # Fallback to config if not set by CLI
    if start_dt is None and end_dt is None:
        cfg_path = Path(args.config)
        if cfg_path.exists():
            cfg = load_config(cfg_path)
            start_dt, end_dt = range_from_config(cfg)

    # ── load CSV files ──────────────────────────────────────────
    csv_dir   = Path(args.csv_dir)
    csv_files = find_csv_files(csv_dir)
    if not csv_files:
        sys.exit("ERROR: no source CSV files found. Run parse_alerts.py first.")

    print(f"\nKentik Weekly Report Generator")
    print(f"  CSV dir : {csv_dir}")
    print(f"  Files   : {len(csv_files)}")
    print(f"  Range   : {start_dt or 'all'} → {end_dt or 'all'}")
    print()

    attacks = load_attacks(csv_files, start_dt, end_dt)
    if not attacks:
        sys.exit("ERROR: no attacks matched the specified date range.")

    weeks = group_by_week(attacks)
    print(f"  Weeks   : {len(weeks)}")

    # ── output file ─────────────────────────────────────────────
    if args.out:
        out_path = Path(args.out)
    else:
        ts       = datetime.now().strftime(DATETIME_FMT)
        out_path = REPORTS_DIR / f"kentik_weekly_report_{ts}.html"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    html = generate_html(weeks, start_dt, end_dt, csv_files)
    out_path.write_text(html, encoding="utf-8")
    print(f"\n  Report  : {out_path}")
    print("  Done.\n")


if __name__ == "__main__":
    main()
