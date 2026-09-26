"""Report layer (Step 5, part B).

Layer separation (R22, locked 2026-09-26):

    Evidence -> Rule -> Finding      (core/rules.py, NO aggregation)
    Findings -> Incident             (this module, report layer ONLY)

The rule engine emits raw independent findings; incidents are a
report-time grouping so "a rule fired 3 times" always stays
distinguishable from "3 findings were merged into 1". Each finding
keeps its own rule_id / evidence / confidence / sensor_health /
lineage inside the incident.

Three concepts are strictly separated in every report:

    Finding   = what one rule found
    Evidence  = why it was judged so (concrete event ids)
    Incident  = which findings belong to one investigation unit

Incident grouping (union-find) links two findings when they share:
  - an evidence event id, or
  - the same file path, endpoint, or claimant run in their details.
Only VIOLATION findings are grouped; non-violation findings (coverage /
inconclusive / not-applicable) are reported separately so the reader
always sees what was checked and what fired.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from core.graph import ProvenanceGraph, build_graph
from core.rules import RuleConfig, RuleEngine


# ---------------------------------------------------------------- incidents

class _UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _finding_link_keys(finding: dict) -> set[str]:
    keys: set[str] = set()
    for ev in finding.get("evidence", []):
        keys.add(f"event:{ev}")
    d = finding.get("details", {})
    if d.get("file"):
        keys.add(f"file:{d['file']}")
    if d.get("endpoint"):
        keys.add(f"endpoint:{d['endpoint']}")
    if d.get("claimant_run"):
        keys.add(f"run:{d['claimant_run']}")
    return keys


def aggregate_incidents(findings: list[dict]) -> dict:
    """Group violation findings into incidents; keep the rest separate.

    Returns {"incidents": [...], "non_violations": [...]} where each
    incident is {"incident_id", "findings": [finding dicts]} -- findings
    are NOT mutated or deduplicated, only grouped.
    """
    violations = [f for f in findings if f.get("violation")]
    others = [f for f in findings if not f.get("violation")]

    uf = _UnionFind(len(violations))
    key_owner: dict[str, int] = {}
    for i, f in enumerate(violations):
        for key in _finding_link_keys(f):
            if key in key_owner:
                uf.union(i, key_owner[key])
            else:
                key_owner[key] = i

    groups: dict[int, list[dict]] = {}
    for i, f in enumerate(violations):
        groups.setdefault(uf.find(i), []).append(f)

    incidents = []
    for root in sorted(groups):
        members = groups[root]
        incidents.append({
            "incident_id": f"INC-{len(incidents) + 1:03d}",
            "finding_count": len(members),
            "rules_fired": sorted({m["rule"] for m in members}),
            "findings": members,
        })
    return {"incidents": incidents, "non_violations": others}


# ---------------------------------------------------------------- rendering

CONFIDENCE_NOTE = "heuristic evidence score, NOT probability"

_RULE_LABELS = {
    "CONFIDENTIAL_FILE_TO_EXTERNAL_EGRESS":
        "confidential file access followed by external egress",
    "AGENT_CLAIM_CONTRADICTED":
        "agent self-claim contradicted by system observation",
    "EGRESS_TO_NON_ALLOWLIST":
        "egress to non-allowlisted endpoint",
}


def _fmt_bytes(n: int | None) -> str:
    if n is None:
        return "unknown"
    units = ["B", "KB", "MB", "GB"]
    v = float(n)
    for u in units:
        if v < 1024 or u == units[-1]:
            return f"{v:.1f} {u}" if u != "B" else f"{int(v)} B"
        v /= 1024
    return f"{n} B"


def render_finding_text(f: dict, indent: str = "  ") -> list[str]:
    """One finding in the locked structured-conclusion format."""
    lines = [
        f"{indent}Rule:        {f['rule']}",
        f"{indent}             ({_RULE_LABELS.get(f['rule'], f['rule'])})",
        f"{indent}Violation:   {'YES' if f['violation'] else 'NO'}",
        f"{indent}Lineage:     {f['lineage']}",
    ]
    if f.get("confidence") is not None:
        lines.append(f"{indent}Confidence:  {f['confidence']:.2f}"
                     f"  # {CONFIDENCE_NOTE}")
    else:
        lines.append(f"{indent}Confidence:  n/a")
    lines.append(f"{indent}Sensor:      {f['sensor_health']}")
    lines.append(f"{indent}Evidence:    {len(f['evidence'])} event(s): "
                 + ", ".join(f["evidence"][:8])
                 + (" ..." if len(f["evidence"]) > 8 else ""))
    d = f.get("details", {})
    if d.get("file"):
        lines.append(f"{indent}             file: {d['file']}")
    if d.get("endpoint"):
        lines.append(f"{indent}             endpoint: {d['endpoint']}")
    if d.get("bytes_sent") is not None:
        lines.append(f"{indent}             bytes_sent: "
                     f"{_fmt_bytes(d['bytes_sent'])} ({d['bytes_sent']})")
    vr = d.get("volume_reconciliation")
    if vr:
        lines.append(
            f"{indent}             volume: observed={_fmt_bytes(vr['observed_bytes'])}"
            f" expected={_fmt_bytes(vr['expected_bytes']) or 'unknown'}"
            f" tol={int(vr['tolerance_ratio'] * 100)}%"
            f" -> {vr['verdict']}")
    fs = d.get("file_size")
    if fs:
        lines.append(f"{indent}             size_source: {fs['size_source']}"
                     + (f" (observed {fs['size_observed_ts']})"
                        if fs.get("size_observed_ts") else ""))
    if "window_seconds" in d:
        lines.append(f"{indent}             window: {d['window_seconds']:.0f}s"
                     f" [{d['window_start_epoch']:.0f} .. "
                     f"{d['window_end_epoch']:.0f}]")
    lines.append(f"{indent}Conclusion:  {f['conclusion']}")
    return lines


def render_report_text(report: dict) -> str:
    """Full human-readable report."""
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("AGENT BEV GUARD -- DETECTION REPORT")
    lines.append("=" * 72)
    lines.append(f"generated:      {report['generated_at']}")
    lines.append(f"event log:      {report['log_path']} "
                 f"({report['event_count']} events, "
                 f"chain {'OK' if report['chain_ok'] else 'BROKEN'})")
    lines.append(f"sensor health:  {report['sensor_health']}")
    lines.append(f"findings:       {report['finding_count']} total, "
                 f"{report['violation_count']} violations, "
                 f"{report['incident_count']} incident(s)")
    lines.append("")
    lines.append("note: confidence values are heuristic evidence scores, "
                 "NOT probabilities;")
    lines.append("      alerts are decided by rule violation, not by "
                 "confidence thresholds.")
    lines.append("")

    # -- incidents
    for inc in report["incidents"]:
        lines.append("-" * 72)
        lines.append(f"INCIDENT {inc['incident_id']}  "
                     f"({inc['finding_count']} finding(s): "
                     f"{', '.join(inc['rules_fired'])})")
        lines.append("-" * 72)
        for i, f in enumerate(inc["findings"], 1):
            lines.append(f"  [{i}]")
            lines.extend(render_finding_text(f, indent="      "))
            lines.append("")

    if not report["incidents"]:
        lines.append("-" * 72)
        lines.append("NO INCIDENTS (no rule violations)")
        lines.append("-" * 72)
        lines.append("")

    # -- coverage / non-violations
    lines.append("-" * 72)
    lines.append("RULE COVERAGE (checked, no violation)")
    lines.append("-" * 72)
    for f in report["non_violations"]:
        lines.extend(render_finding_text(f, indent="  "))
        lines.append("")
    return "\n".join(lines)


def render_graph_text(g: ProvenanceGraph) -> str:
    """Provenance graph as an adjacency-style text rendering."""
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("PROVENANCE GRAPH (who touched what)")
    lines.append("=" * 72)
    stats = g.stats()
    lines.append(f"nodes: {stats['nodes']}  edges: {stats['edges']}")
    lines.append("")
    for nid in sorted(g.nodes):
        node = g.nodes[nid]
        cls = f" [{node.classification}]" if node.classification else ""
        lines.append(f"({node.kind}) {node.label}{cls}")
        edges = g.edges_from(nid)
        for e in sorted(edges, key=lambda x: x.ts_epoch):
            conf = (f" conf={e.confidence:.2f}" if e.confidence is not None
                    else "")
            lines.append(
                f"    --{e.verb}--> {e.dst.split(':', 1)[1]}"
                f"  [{e.sensor}/{e.sensor_privilege},"
                f" {e.identity_source}{conf}, ts={e.ts_epoch:.0f},"
                f" ev={e.event_id}]")
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------- pipeline

def build_report(records: list[dict], cfg: RuleConfig,
                 log_path: str = "<memory>",
                 chain_ok: bool = True,
                 generated_at: str | None = None) -> dict:
    """Full pipeline: events -> findings (engine) -> incidents (report)."""
    from datetime import datetime, timezone
    engine_out = RuleEngine(cfg).run(records)
    grouped = aggregate_incidents(engine_out["findings"])
    graph = build_graph(records)
    return {
        "generated_at": generated_at
                        or datetime.now(timezone.utc).isoformat(),
        "log_path": str(log_path),
        "event_count": len(records),
        "chain_ok": chain_ok,
        "sensor_health": engine_out["sensor_health"],
        "finding_count": len(engine_out["findings"]),
        "violation_count": len(engine_out["alerts"]),
        "incident_count": len(grouped["incidents"]),
        "incidents": grouped["incidents"],
        "non_violations": grouped["non_violations"],
        "graph_stats": graph.stats(),
    }


def write_report_files(report: dict, graph: ProvenanceGraph,
                       outdir: Path) -> dict[str, Path]:
    """Machine-readable JSON + human-readable text + graph rendering."""
    outdir.mkdir(parents=True, exist_ok=True)
    json_path = outdir / "report.json"
    text_path = outdir / "report.txt"
    graph_path = outdir / "graph.txt"
    json_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8")
    text_path.write_text(render_report_text(report), encoding="utf-8")
    graph_path.write_text(render_graph_text(graph), encoding="utf-8")
    return {"json": json_path, "text": text_path, "graph": graph_path}
