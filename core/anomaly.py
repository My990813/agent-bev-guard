"""Behavioral anomaly scoring + triage report (Step 6, part 2).

Locked semantics (threat-model section 12):

    anomaly level  = heuristic ranking aid, NOT a probability,
                     NOT a calibrated threshold (same semantics as R19)
    behavior       = "inconsistent_with_baseline", NEVER "malicious"
    legal_status   = NOT_DETERMINED, always, on every triage item
    policy_status  = only what Step 5 known rules actually found;
                     "no rule fired" is UNKNOWN, never "compliant"

The output answers the auditor's question "which runs should I look
at first", and nothing else. Authorization, harm, and legality are
human decisions that this system never automates.

Numeric deviation uses the robust z-score
    robust_z = |x - median| / (1.4826 * MAD)
against the baseline (core/baseline.py). For constant baseline
features (MAD == 0) any deviation is flagged with robust_z=None and
an explicit note instead of an invented score.

Levels (configurable, recorded in every report -- R24 provenance
style): a run's level is HIGH / MEDIUM / LOW by the NUMBER of
independent flags, not by any single score. Flags are:
  - numeric deviation          (robust_z > z_threshold)
  - constant-feature deviation (baseline has zero variance)
  - novel external endpoint    (first-seen destination)
  - novel tool bigram          (unseen adjacent tool pair)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from core.baseline import (
    NUMERIC_FEATURES,
    Baseline,
    RunFeatures,
    tool_bigrams,
)
from core.rules import RuleConfig, RuleEngine

SCOPE_STATEMENT = (
    "The system detects and reconstructs behavior; it does not "
    "determine intent, legality, or culpability."
)

MAD_SCALE = 1.4826  # makes MAD a consistent std-dev estimator (normal)


@dataclass
class TriageConfig:
    z_threshold: float = 3.5
    high_flags: int = 3
    medium_flags: int = 1

    def to_dict(self) -> dict:
        return {
            "z_threshold": self.z_threshold,
            "high_flags": self.high_flags,
            "medium_flags": self.medium_flags,
            "semantics": "heuristic ranking aid, NOT a probability",
        }


@dataclass
class TriageItem:
    run_id: str
    anomaly_level: str  # HIGH / MEDIUM / LOW
    flags: list[dict] = field(default_factory=list)
    lineage: str = "UNKNOWN"  # strongest identity source among run events
    policy_status: str = "UNKNOWN"
    legal_status: str = "NOT_DETERMINED"
    event_count: int = 0

    @property
    def n_flags(self) -> int:
        return len(self.flags)

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "anomaly_level": self.anomaly_level,
            "behavior": "inconsistent_with_baseline"
            if self.flags else "within_baseline",
            "flags": self.flags,
            "lineage": self.lineage,
            "policy_status": self.policy_status,
            "legal_status": self.legal_status,
            "event_count": self.event_count,
            "note": "anomaly level is a heuristic ranking aid, "
                    "NOT a probability; NOT a determination of intent "
                    "or legality",
        }


def score_run(
    feat: RunFeatures,
    baseline: Baseline,
    cfg: TriageConfig,
) -> list[dict]:
    """Deviation + novelty flags for one run against the baseline."""
    flags: list[dict] = []

    for f in NUMERIC_FEATURES:
        value = float(getattr(feat, f))
        med, mad = baseline.median[f], baseline.mad[f]
        if mad > 0:
            rz = abs(value - med) / (MAD_SCALE * mad)
            if rz > cfg.z_threshold:
                flags.append({
                    "kind": "numeric_deviation",
                    "feature": f,
                    "value": value,
                    "baseline_median": med,
                    "robust_z": round(rz, 2),
                })
        elif value != med:
            # Constant baseline: any deviation is notable, but we do
            # NOT invent a z-score from zero variance.
            flags.append({
                "kind": "numeric_deviation",
                "feature": f,
                "value": value,
                "baseline_median": med,
                "robust_z": None,
                "note": "baseline has zero variance for this feature; "
                        "any deviation is flagged",
            })

    for ep in sorted(feat.external_endpoints - baseline.known_endpoints):
        flags.append({
            "kind": "novel_endpoint",
            "endpoint": ep,
            "note": "first-seen external destination (not in baseline)",
        })

    novel_bigrams = sorted(
        tool_bigrams(feat.tool_sequence) - baseline.known_tool_bigrams
    )
    if novel_bigrams:
        flags.append({
            "kind": "novel_tool_bigram",
            "bigrams": [" -> ".join(b) for b in novel_bigrams],
            "note": "adjacent tool pair(s) unseen in any baseline run",
        })

    return flags


def _level(n_flags: int, cfg: TriageConfig) -> str:
    if n_flags >= cfg.high_flags:
        return "HIGH"
    if n_flags >= cfg.medium_flags:
        return "MEDIUM"
    return "LOW"


def _lineage_of_run(records: list[dict]) -> str:
    """Lineage of a triage item = WEAKEST link among its events
    (same semantics as core/rules.py _lineage_of): any UNKNOWN makes
    the item UNKNOWN; else any INFERRED makes it INFERRED; DIRECT
    only if every event is DIRECT."""
    sources = {r.get("actor", {}).get("identity_source", "UNKNOWN")
               for r in records}
    if not sources or "UNKNOWN" in sources:
        return "UNKNOWN"
    if "INFERRED" in sources:
        return "INFERRED"
    return "DIRECT"


def policy_status_for_run(
    run_records: list[dict], rule_cfg: RuleConfig
) -> str:
    """Step 5 known-rule verdict for this run's events.

    "No rule fired" is UNKNOWN, never "compliant": the rules cover a
    finite, known policy set only (threat-model section 12).
    """
    out = RuleEngine(rule_cfg).run(run_records)
    violations = [f for f in out["findings"] if f.get("violation")]
    if violations:
        rules = sorted({v["rule"] for v in violations})
        return (f"VIOLATION_FOUND ({len(violations)} finding(s): "
                f"{', '.join(rules)})")
    return "UNKNOWN"


def triage_runs(
    records: list[dict],
    baseline_runs: list[RunFeatures],
    cfg: TriageConfig | None = None,
    rule_cfg: RuleConfig | None = None,
) -> dict:
    """Score every attributed run; return the full triage result.

    Returns {"items": [...], "baseline": ..., "config": ...,
             "stats": {...}} with items sorted by flag count desc.
    Unattributed events are surfaced in stats, never dropped silently.
    """
    cfg = cfg or TriageConfig()
    rule_cfg = rule_cfg or RuleConfig()

    from core.baseline import extract_run_features

    features, unattributed = extract_run_features(records)
    baseline = Baseline.build(baseline_runs)

    by_run: dict[str, list[dict]] = {}
    for rec in records:
        rid = rec.get("actor", {}).get("agent_run_id")
        if rid:
            by_run.setdefault(rid, []).append(rec)

    items: list[TriageItem] = []
    for run_id, feat in features.items():
        flags = score_run(feat, baseline, cfg)
        run_records = by_run.get(run_id, [])
        items.append(TriageItem(
            run_id=run_id,
            anomaly_level=_level(len(flags), cfg),
            flags=flags,
            lineage=_lineage_of_run(run_records),
            policy_status=policy_status_for_run(run_records, rule_cfg),
            event_count=len(run_records),
        ))

    items.sort(key=lambda it: (-it.n_flags, it.run_id))

    n_high = sum(1 for it in items if it.anomaly_level == "HIGH")
    n_medium = sum(1 for it in items if it.anomaly_level == "MEDIUM")
    return {
        "scope_statement": SCOPE_STATEMENT,
        "config": cfg.to_dict(),
        "baseline": baseline.to_dict(),
        "stats": {
            "runs_scanned": len(items),
            "runs_flagged": n_high + n_medium,
            "runs_high": n_high,
            "runs_medium": n_medium,
            "unattributed_events": unattributed,
            "note_unattributed": "events with no run attribution are "
                                 "excluded from triage and reported here; "
                                 "they are NOT ignored",
        },
        "items": [it.to_dict() for it in items],
    }


# ------------------------------------------------------------- rendering

def _fmt_flag(flag: dict) -> str:
    if flag["kind"] == "numeric_deviation":
        val = int(flag["value"]) if flag["value"] == int(flag["value"]) \
            else flag["value"]
        med = int(flag["baseline_median"]) \
            if flag["baseline_median"] == int(flag["baseline_median"]) \
            else flag["baseline_median"]
        line = (f"  - {flag['feature']}: {val} vs baseline median {med}")
        if flag.get("robust_z") is not None:
            line += f" (robust_z {flag['robust_z']})"
        else:
            line += " (baseline constant; any deviation flagged)"
        return line
    if flag["kind"] == "novel_endpoint":
        return f"  - novel external endpoint: {flag['endpoint']} " \
               f"(first-seen destination)"
    if flag["kind"] == "novel_tool_bigram":
        return f"  - novel tool sequence: {'; '.join(flag['bigrams'])}"
    return f"  - {flag}"


def render_triage_text(result: dict) -> str:
    lines: list[str] = []
    lines.append("AGENT BEHAVIORAL TRIAGE REPORT")
    lines.append("=" * 64)
    lines.append(f"Scope: {SCOPE_STATEMENT}")
    lines.append("")
    s = result["stats"]
    lines.append(
        f"Scanned {s['runs_scanned']} runs -> "
        f"{s['runs_flagged']} flagged for review "
        f"(HIGH: {s['runs_high']}, MEDIUM: {s['runs_medium']})"
    )
    lines.append(
        f"Baseline: {result['baseline']['n_runs']} runs | "
        f"z_threshold={result['config']['z_threshold']} "
        f"high_flags={result['config']['high_flags']} "
        f"medium_flags={result['config']['medium_flags']}"
    )
    if s["unattributed_events"]:
        lines.append(
            f"Coverage note: {s['unattributed_events']} events carry no "
            f"run attribution and are NOT triaged (see JSON stats)"
        )
    lines.append("")

    for i, item in enumerate(result["items"], start=1):
        if item["anomaly_level"] == "LOW" and not item["flags"]:
            continue  # triage compresses: within-baseline runs are listed
            # in the JSON only, keeping the text report for what to review
        lines.append("-" * 64)
        lines.append(f"Triage item TR-{i:03d}   run {item['run_id']}")
        lines.append(f"Behavioral anomaly: {item['anomaly_level']}")
        lines.append("Evidence:")
        for flag in item["flags"]:
            lines.append(_fmt_flag(flag))
        lines.append(f"Provenance: {item['lineage']}")
        lines.append(f"Policy violation: {item['policy_status']}")
        lines.append(f"Legal status: {item['legal_status']}")
        lines.append("")

    lines.append("-" * 64)
    lines.append(
        "Items marked LOW are within baseline on every measured feature; "
        "they remain in the JSON output. Anomaly level is a heuristic "
        "ranking aid, NOT a probability and NOT a determination of "
        "intent or legality. Authorization, harm, and legal consequence "
        "are human determinations outside this system."
    )
    return "\n".join(lines) + "\n"


def write_triage_reports(result: dict, out_dir: str | Path) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    txt = out / "triage_report.txt"
    jsn = out / "triage_report.json"
    txt.write_text(render_triage_text(result), encoding="utf-8")
    jsn.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return {"text": str(txt), "json": str(jsn)}
