#!/usr/bin/env python3
"""Agent BEV Guard -- behavioral triage CLI (Step 6).

Usage:
    python triage_cli.py --baseline baseline_events.jsonl \
        --log target_events.jsonl \
        --config examples/rules_config.json \
        --out triage_out/

Pipeline:
    hash-chain verify (both logs) -> per-run feature extraction ->
    robust baseline -> deviation + novelty scoring -> Step 5 known-rule
    policy status -> triage report (text + JSON)

Scope (locked): the system detects and reconstructs behavior; it does
not determine intent, legality, or culpability. The report tells an
auditor WHICH runs to investigate first, and nothing else.

Both logs are chain-verified FIRST: a triage built on tampered
evidence (baseline or target) is refused.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from core.anomaly import TriageConfig, triage_runs, write_triage_reports  # noqa: E402
from core.baseline import extract_run_features  # noqa: E402
from core.events import EventLog  # noqa: E402
from core.recon import Tolerance  # noqa: E402
from core.rules import RuleConfig  # noqa: E402


def load_log_verified(path: Path) -> list[dict] | None:
    """Load a JSONL log and verify its hash chain; None if broken."""
    log = EventLog(path)
    ok, bad_idx = log.verify()
    if not ok:
        print(f"error: {path} hash chain BROKEN at record {bad_idx}; "
              "refusing to triage on tampered evidence", file=sys.stderr)
        return None
    return list(log)


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
    return cfg


def load_triage_config(path: Path | None) -> TriageConfig:
    cfg = TriageConfig()
    if path is None:
        return cfg
    raw = json.loads(path.read_text(encoding="utf-8"))
    tri = raw.get("triage", raw)
    if "z_threshold" in tri:
        cfg.z_threshold = float(tri["z_threshold"])
    if "high_flags" in tri:
        cfg.high_flags = int(tri["high_flags"])
    if "medium_flags" in tri:
        cfg.medium_flags = int(tri["medium_flags"])
    return cfg


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--baseline", required=True,
                    help="historical fused events.jsonl (baseline runs)")
    ap.add_argument("--log", required=True,
                    help="target fused events.jsonl (runs to triage)")
    ap.add_argument("--config", default=None, help="rules config JSON")
    ap.add_argument("--triage-config", default=None,
                    help="triage config JSON (z_threshold / flag counts)")
    ap.add_argument("--out", default="triage_out", help="output directory")
    args = ap.parse_args(argv)

    base_path, log_path = Path(args.baseline), Path(args.log)
    for p in (base_path, log_path):
        if not p.exists():
            print(f"error: log not found: {p}", file=sys.stderr)
            return 2

    baseline_records = load_log_verified(base_path)
    if baseline_records is None:
        return 3
    records = load_log_verified(log_path)
    if records is None:
        return 3

    baseline_runs = list(extract_run_features(baseline_records)[0].values())
    if not baseline_runs:
        print("error: baseline log contains no attributed runs",
              file=sys.stderr)
        return 4

    rule_cfg = load_config(Path(args.config) if args.config else None)
    tri_cfg = load_triage_config(
        Path(args.triage_config) if args.triage_config else None
    )

    result = triage_runs(records, baseline_runs, tri_cfg, rule_cfg)
    paths = write_triage_reports(result, Path(args.out))

    s = result["stats"]
    print(f"baseline: {result['baseline']['n_runs']} runs (chain OK)")
    print(f"scanned: {s['runs_scanned']} runs -> "
          f"{s['runs_flagged']} flagged "
          f"(HIGH {s['runs_high']}, MEDIUM {s['runs_medium']})")
    if s["unattributed_events"]:
        print(f"coverage: {s['unattributed_events']} unattributed events "
              f"excluded from triage (reported, not ignored)")
    for p in paths.values():
        print(f"wrote: {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
