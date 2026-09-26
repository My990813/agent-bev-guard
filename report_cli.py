#!/usr/bin/env python3
"""Agent BEV Guard -- report CLI (Step 5, part B).

Usage:
    python report_cli.py --log events.jsonl \
        --config examples/rules_config.json \
        --out report_out/ [--stat-sizes]

Pipeline:
    hash-chain verify -> rule engine (raw findings) ->
    incident aggregation (report layer) -> report.json / report.txt / graph.txt

The chain is verified FIRST: a broken audit log aborts the report,
because findings built on tampered evidence are worthless.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from core.events import EventLog                    # noqa: E402
from core.graph import build_graph                  # noqa: E402
from core.recon import Tolerance                    # noqa: E402
from core.report import build_report, write_report_files  # noqa: E402
from core.rules import RuleConfig                   # noqa: E402


def load_config(path: Path | None) -> RuleConfig:
    cfg = RuleConfig()
    if path is None:
        return cfg
    raw = json.loads(path.read_text(encoding="utf-8"))
    rules = raw.get("rules", raw)
    if "allowlist" in raw:
        cfg.allowlist = list(raw["allowlist"])
    if "window_seconds" in rules:
        cfg.window_seconds = float(rules["window_seconds"])
    if "tolerance" in rules:
        cfg.tolerance = Tolerance.from_config(rules["tolerance"])
    if "file_sizes" in rules:
        cfg.file_sizes = {str(k): int(v)
                          for k, v in rules["file_sizes"].items()}
    if raw.get("stat_missing_sizes"):
        cfg.stat_missing_sizes = True
    return cfg


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--log", required=True, help="fused events.jsonl")
    ap.add_argument("--config", default=None, help="rules config JSON")
    ap.add_argument("--out", default="report_out", help="output directory")
    ap.add_argument("--stat-sizes", action="store_true",
                    help="post-event os.stat for sizes not in config "
                         "(best_effort_current_size semantics)")
    args = ap.parse_args(argv)

    log_path = Path(args.log)
    if not log_path.exists():
        print(f"error: log not found: {log_path}", file=sys.stderr)
        return 2

    log = EventLog(log_path)
    ok, bad_idx = log.verify()
    if not ok:
        print(f"error: audit log hash chain BROKEN at record {bad_idx}; "
              "refusing to build a report on tampered evidence",
              file=sys.stderr)
        return 3
    records = list(log)

    cfg = load_config(Path(args.config) if args.config else None)
    if args.stat_sizes:
        cfg.stat_missing_sizes = True

    report = build_report(records, cfg, log_path=str(log_path),
                          chain_ok=ok)
    graph = build_graph(records)
    paths = write_report_files(report, graph, Path(args.out))

    print(f"events: {report['event_count']} (chain OK)")
    print(f"sensor health: {report['sensor_health']}")
    print(f"findings: {report['finding_count']} "
          f"({report['violation_count']} violations -> "
          f"{report['incident_count']} incident(s))")
    for p in paths.values():
        print(f"wrote: {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
