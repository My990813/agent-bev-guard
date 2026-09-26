"""Consistency rule engine (Step 5, part A).

Alert semantics (locked 2026-09-26, threat-model section 10):

    Whether to alert is decided by WHETHER A RULE HOLDS.
    confidence describes evidence strength.
    sensor health describes observation completeness.
    The three are never merged into one score.

Findings are structured conclusions, never a single risk_score:

    rule / violation / lineage / confidence / sensor_health /
    evidence (event ids) / conclusion / details

Conclusions:
    ALERT                          (DIRECT lineage events)
    ALERT_WITH_INFERRED_LINEAGE    (INFERRED attribution)
    ALERT_WITH_UNKNOWN_LINEAGE     (linked by pid only, no run attribution)
    NO_VIOLATION
    INCONCLUSIVE_DUE_TO_SENSOR_LOSS  (rule found nothing BUT sensor degraded)
    NOT_APPLICABLE                 (rule has nothing to check)

Rules (plain-language definitions live in the step-5 delivery notes):

    R1 CONFIDENTIAL_FILE_TO_EXTERNAL_EGRESS
       confidential/secret file opened -> egress to a non-allowlisted
       endpoint within the time window, by the same process instance
       or run. Volume reconciled against file size when known
       (core/recon.py), honestly marked INSUFFICIENT_EVIDENCE otherwise.

    R2 AGENT_CLAIM_CONTRADICTED
       agent self-claims ("no upload") vs system-observed egress under
       the same run. Contradiction itself is the alert.

    R3 EGRESS_TO_NON_ALLOWLIST
       any connect to an endpoint outside the allowlist.

    Meta SENSOR_HEALTH_COUPLING
       no-violation conclusions downgrade to INCONCLUSIVE_DUE_TO_
       SENSOR_LOSS when sensor.health is DEGRADED or UNKNOWN.

Rulings locked 2026-09-26 (R21-R24):

    R21 PID REUSE: the causal attribution key is (pid, pid_start_ts),
    never pid alone. Attribution priority:
        same agent_run_id        -> strongest
        same process instance    -> strong
        pid only                 -> NOT used for automatic attribution
        time only                -> correlation only
    We prefer UNKNOWN over a fabricated causal chain.

    R22 NO AGGREGATION IN THE ENGINE: the rule engine emits raw,
    independent findings. Incident grouping is a report-layer concern
    (core/report.py), so "a rule fired 3 times" is always
    distinguishable from "3 findings were merged into 1".

    R23 FILE SIZE SEMANTICS: file sizes may come from config (exact)
    or a post-event os.stat (best_effort_current_size, observed at
    report time -- the file may have changed since the event). Deleted
    or missing files yield size_bytes=None / size_source="unavailable"
    and the reconciliation verdict is INSUFFICIENT_EVIDENCE, never a
    fabricated PASS. Missing evidence is not evidence of absence.

    R24 WINDOW PROVENANCE: the default window is 600s, configurable;
    every finding records the window actually used (seconds + start +
    end) so experiments with different windows stay reproducible.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

from core.fusion import ts_to_epoch
from core.recon import Tolerance, reconcile

CONFIDENTIAL_LEVELS = {"confidential", "secret"}

CONCLUSIONS = {
    "ALERT", "ALERT_WITH_INFERRED_LINEAGE", "ALERT_WITH_UNKNOWN_LINEAGE",
    "NO_VIOLATION", "INCONCLUSIVE_DUE_TO_SENSOR_LOSS", "NOT_APPLICABLE",
}


def same_process(actor_a: dict, actor_b: dict) -> bool:
    """R21: (pid, pid_start_ts) process-instance identity.

    pid equality alone NEVER confirms the same process instance --
    pids are reused. If either side lacks pid_start_ts (no exec record
    fused in), we cannot confirm the instance and refuse to attribute.
    UNKNOWN is preferred over a fabricated causal chain.
    """
    pa, pb = actor_a.get("pid"), actor_b.get("pid")
    if pa is None or pa != pb:
        return False
    sa, sb = actor_a.get("pid_start_ts"), actor_b.get("pid_start_ts")
    if sa is None or sb is None:
        return False
    return abs(float(sa) - float(sb)) < 1e-6


@dataclass
class SizeInfo:
    """R23: file size with explicit measurement semantics."""
    size_bytes: int | None
    size_source: str  # config_provided / post_event_stat / unavailable
    observed_ts: str | None = None
    semantics: str = "best_effort_current_size"

    def to_dict(self) -> dict:
        return {
            "size_bytes": self.size_bytes,
            "size_source": self.size_source,
            "size_observed_ts": self.observed_ts,
            "size_semantics": self.semantics,
        }


def stat_size(path: str) -> SizeInfo:
    """Best-effort post-event os.stat (R23). Never fabricates a value:
    a deleted/missing file returns size_bytes=None, source=unavailable."""
    try:
        st = os.stat(path)
        return SizeInfo(
            size_bytes=st.st_size,
            size_source="post_event_stat",
            observed_ts=datetime.now(timezone.utc).isoformat(),
            semantics="best_effort_current_size; file may have changed "
                      "since the observed event",
        )
    except OSError:
        return SizeInfo(size_bytes=None, size_source="unavailable")


@dataclass
class RuleConfig:
    allowlist: list[str] = field(default_factory=list)  # ip, ip:port, or cidr
    window_seconds: float = 600.0  # R24: default, configurable, recorded per finding
    tolerance: Tolerance = field(default_factory=Tolerance)
    file_sizes: dict[str, int] = field(default_factory=dict)  # path -> bytes (config, exact)
    stat_missing_sizes: bool = False  # R23: os.stat fallback for paths not in file_sizes

    def size_info(self, path: str) -> SizeInfo:
        if path in self.file_sizes:
            return SizeInfo(
                size_bytes=int(self.file_sizes[path]),
                size_source="config_provided",
                semantics="exact size provided by configuration at analysis time",
            )
        if self.stat_missing_sizes:
            return stat_size(path)
        return SizeInfo(size_bytes=None, size_source="unavailable")


@dataclass
class Finding:
    rule: str
    violation: bool
    lineage: str  # DIRECT / INFERRED / UNKNOWN / N/A
    confidence: float | None
    sensor_health: str
    evidence: list[str]  # event ids
    conclusion: str
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "violation": self.violation,
            "lineage": self.lineage,
            "confidence": self.confidence,
            "confidence_semantics": "heuristic evidence score, NOT probability",
            "sensor_health": self.sensor_health,
            "evidence": self.evidence,
            "conclusion": self.conclusion,
            "details": self.details,
        }


def endpoint_allowed(endpoint: str, allowlist: list[str]) -> bool:
    """endpoint is 'ip:port'. Allowlist entries: ip, ip:port, cidr."""
    ip_str, _, port = endpoint.rpartition(":")
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for entry in allowlist:
        if entry == endpoint:
            return True
        if ":" not in entry:
            try:
                if "/" in entry:
                    if ip in ipaddress.ip_network(entry, strict=False):
                        return True
                elif ipaddress.ip_address(entry) == ip:
                    return True
            except ValueError:
                continue
    return False


def sensor_health(records: list[dict]) -> str:
    """Latest sensor.health status. Absent telemetry -> UNKNOWN (R20).

    Only tokens whose value is a known status count; the HEALTHY caveat
    text also contains 'health=...' (necessary-not-sufficient) and must
    not be mistaken for the status itself.
    """
    statuses = {"HEALTHY", "MINOR_LOSS", "DEGRADED", "UNKNOWN"}
    status = "UNKNOWN"
    for r in records:
        if r.get("event_type") == "sensor.health":
            note = r.get("note") or ""
            for part in note.split():
                if part.startswith("health="):
                    val = part.split("=", 1)[1].rstrip(";")
                    if val in statuses:
                        status = val
    return status


def _assign_sends(records: list[dict]) -> dict[str, list[dict]]:
    """net.egress (SEND) events carry no destination; attach each to the
    most recent net.connect of the SAME PROCESS INSTANCE (R21) or the
    SAME RUN before it -- matching the attribution priority
    (run strongest, process instance strong, pid alone never).
    Returns endpoint -> [send records]. Unconfirmable sends stay under ''.
    """
    out: dict[str, list[dict]] = {}
    by_instance: dict[tuple, tuple[float, str]] = {}
    by_run: dict[str, tuple[float, str]] = {}
    for r in records:
        et = r.get("event_type")
        actor = r.get("actor", {})
        ts = ts_to_epoch(r.get("ts_wall", "")) or 0.0
        if et == "net.connect":
            peer = r.get("peer") or {}
            endpoint = peer.get("id", "")
            key = (actor.get("pid"), actor.get("pid_start_ts"))
            if None not in key:
                by_instance[key] = (ts, endpoint)
            run = actor.get("agent_run_id")
            if run:
                by_run[run] = (ts, endpoint)
        elif et == "net.egress":
            endpoint = ""
            key = (actor.get("pid"), actor.get("pid_start_ts"))
            hit = None
            if None not in key:
                hit = by_instance.get(key)
            if hit is None:
                run = actor.get("agent_run_id")
                if run:
                    hit = by_run.get(run)
            if hit:
                endpoint = hit[1]
            out.setdefault(endpoint, []).append(r)
    return out


def _lineage_of(events: list[dict]) -> tuple[str, float | None]:
    """Aggregate lineage over the events backing one finding.
    Weakest link wins: any UNKNOWN -> UNKNOWN; else any INFERRED ->
    INFERRED; DIRECT only if all DIRECT."""
    sources = {e.get("actor", {}).get("identity_source", "UNKNOWN")
               for e in events}
    if "UNKNOWN" in sources or not sources:
        return "UNKNOWN", None
    if "INFERRED" in sources:
        confs = [e.get("actor", {}).get("identity_confidence")
                 for e in events
                 if e.get("actor", {}).get("identity_source") == "INFERRED"]
        confs = [c for c in confs if c is not None]
        return "INFERRED", min(confs) if confs else None
    return "DIRECT", None


def _alert_conclusion(lineage: str) -> str:
    if lineage == "INFERRED":
        return "ALERT_WITH_INFERRED_LINEAGE"
    if lineage == "UNKNOWN":
        return "ALERT_WITH_UNKNOWN_LINEAGE"
    return "ALERT"


def _connects_by_endpoint(records: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for r in records:
        if r.get("event_type") == "net.connect":
            peer = r.get("peer") or {}
            if peer.get("id"):
                out.setdefault(peer["id"], []).append(r)
    return out


def rule1_confidential_egress(records: list[dict], cfg: RuleConfig,
                              health: str) -> list[Finding]:
    findings: list[Finding] = []
    sends_by_endpoint = _assign_sends(records)
    connects_by_endpoint = _connects_by_endpoint(records)

    opens = [r for r in records
             if r.get("event_type") == "file.open"
             and any(e.get("classification") in CONFIDENTIAL_LEVELS
                     for e in (r.get("entities") or []))
             and r.get("action", {}).get("outcome") == "success"]

    for op in opens:
        path = next(e["id"] for e in op["entities"]
                    if e.get("classification") in CONFIDENTIAL_LEVELS)
        op_ts = ts_to_epoch(op.get("ts_wall", "")) or 0.0
        op_actor = op["actor"]
        op_run = op_actor.get("agent_run_id")

        for endpoint, sends in sends_by_endpoint.items():
            if not endpoint or endpoint_allowed(endpoint, cfg.allowlist):
                continue
            for send in sends:
                s_ts = ts_to_epoch(send.get("ts_wall", "")) or 0.0
                if not (op_ts <= s_ts <= op_ts + cfg.window_seconds):
                    continue
                s_actor = send["actor"]
                s_run = s_actor.get("agent_run_id")
                # R21 attribution priority:
                #   same run_id -> strongest; same process instance -> strong;
                #   pid alone -> NOT used (prefer UNKNOWN over fake causality)
                same = (op_run and s_run == op_run) or same_process(op_actor, s_actor)
                if not same:
                    continue

                def _in_window_and_attributable(s: dict) -> bool:
                    st = ts_to_epoch(s.get("ts_wall", "")) or 0.0
                    if not (op_ts <= st <= op_ts + cfg.window_seconds):
                        return False
                    sa = s["actor"]
                    return ((op_run and sa.get("agent_run_id") == op_run)
                            or same_process(op_actor, sa))

                window_sends = [s for s in sends if _in_window_and_attributable(s)]
                sent = sum(s["action"].get("bytes", 0) for s in window_sends)
                size_info = cfg.size_info(path)  # R23: semantics included
                recon = reconcile(sent, size_info.size_bytes, cfg.tolerance)
                connects = connects_by_endpoint.get(endpoint, [])
                backing = [op] + connects + window_sends
                lineage, conf = _lineage_of(backing)
                findings.append(Finding(
                    rule="CONFIDENTIAL_FILE_TO_EXTERNAL_EGRESS",
                    violation=True,
                    lineage=lineage,
                    confidence=conf,
                    sensor_health=health,
                    evidence=[b["event_id"] for b in backing],
                    conclusion=_alert_conclusion(lineage),
                    details={
                        "file": path,
                        "classification": "confidential",
                        "endpoint": endpoint,
                        "bytes_sent": sent,
                        "volume_reconciliation": recon.to_dict(),
                        "file_size": size_info.to_dict(),
                        # R24: record the window actually used
                        "window_seconds": cfg.window_seconds,
                        "window_start_epoch": op_ts,
                        "window_end_epoch": op_ts + cfg.window_seconds,
                    },
                ))
                break  # one finding per (file, endpoint) pair

    if not findings:
        if not opens:
            return [Finding(
                rule="CONFIDENTIAL_FILE_TO_EXTERNAL_EGRESS", violation=False,
                lineage="N/A", confidence=None, sensor_health=health,
                evidence=[], conclusion="NOT_APPLICABLE",
                details={"reason": "no confidential file access observed"})]
        return [_no_violation("CONFIDENTIAL_FILE_TO_EXTERNAL_EGRESS", health)]
    return findings


def rule2_claim_contradiction(records: list[dict], cfg: RuleConfig,
                              health: str) -> list[Finding]:
    claims = [r for r in records
              if r.get("sensor") == "agent_self"
              and r.get("event_type") == "agent.claim"
              and any((e.get("id") or "").startswith("claim:no_upload")
                      for e in (r.get("entities") or []))]
    if not claims:
        return [Finding(
            rule="AGENT_CLAIM_CONTRADICTED", violation=False, lineage="N/A",
            confidence=None, sensor_health=health, evidence=[],
            conclusion="NOT_APPLICABLE",
            details={"reason": "no self-reported claims to check"})]

    egress = [r for r in records if r.get("event_type") == "net.egress"]
    findings: list[Finding] = []
    for claim in claims:
        claim_run = claim["actor"].get("agent_run_id")
        if not claim_run:
            findings.append(Finding(
                rule="AGENT_CLAIM_CONTRADICTED", violation=False,
                lineage="UNKNOWN", confidence=None, sensor_health=health,
                evidence=[claim["event_id"]], conclusion="NOT_APPLICABLE",
                details={"reason": "claim cannot be correlated to any run"}))
            continue
        matched = [e for e in egress
                   if e["actor"].get("agent_run_id") == claim_run]
        if matched:
            sent = sum(e["action"].get("bytes", 0) for e in matched)
            findings.append(Finding(
                rule="AGENT_CLAIM_CONTRADICTED", violation=True,
                lineage="INFERRED",
                confidence=claim["actor"].get("identity_confidence"),
                sensor_health=health,
                evidence=[claim["event_id"]] + [e["event_id"] for e in matched],
                conclusion="ALERT_WITH_INFERRED_LINEAGE",
                details={
                    "claim": "no_upload",
                    "claimant_run": claim_run,
                    "observed_egress_events": len(matched),
                    "observed_egress_bytes": sent,
                }))
        else:
            findings.append(Finding(
                rule="AGENT_CLAIM_CONTRADICTED", violation=False,
                lineage="INFERRED", confidence=None, sensor_health=health,
                evidence=[claim["event_id"]], conclusion="NO_VIOLATION",
                details={"claim": "no_upload", "claimant_run": claim_run,
                         "note": "no egress observed under this run"}))
    return findings


def rule3_non_allowlist_egress(records: list[dict], cfg: RuleConfig,
                               health: str) -> list[Finding]:
    sends_by_endpoint = _assign_sends(records)
    findings: list[Finding] = []
    for r in records:
        if r.get("event_type") != "net.connect":
            continue
        peer = r.get("peer") or {}
        endpoint = peer.get("id", "")
        if not endpoint or endpoint_allowed(endpoint, cfg.allowlist):
            continue
        pid = r["actor"]["pid"]
        c_ts = ts_to_epoch(r.get("ts_wall", "")) or 0.0
        window_sends = [s for s in sends_by_endpoint.get(endpoint, [])
                        if same_process(r["actor"], s["actor"])  # R21
                        and (ts_to_epoch(s.get("ts_wall", "")) or 0.0) >= c_ts]
        sent = sum(s["action"].get("bytes", 0) for s in window_sends)
        backing = [r] + window_sends
        lineage, conf = _lineage_of(backing)
        findings.append(Finding(
            rule="EGRESS_TO_NON_ALLOWLIST", violation=True,
            lineage=lineage, confidence=conf, sensor_health=health,
            evidence=[b["event_id"] for b in backing],
            conclusion=_alert_conclusion(lineage),
            details={"endpoint": endpoint, "bytes_sent": sent,
                     "connects": 1}))
    if not findings:
        return [_no_violation("EGRESS_TO_NON_ALLOWLIST", health)]
    return findings


def _no_violation(rule: str, health: str) -> Finding:
    conclusion = "NO_VIOLATION"
    if health in ("DEGRADED", "UNKNOWN"):
        conclusion = "INCONCLUSIVE_DUE_TO_SENSOR_LOSS"
    return Finding(rule=rule, violation=False, lineage="N/A", confidence=None,
                   sensor_health=health, evidence=[], conclusion=conclusion,
                   details={"sensor_health": health})


class RuleEngine:
    def __init__(self, cfg: RuleConfig):
        self.cfg = cfg

    def run(self, records: list[dict]) -> dict:
        health = sensor_health(records)
        findings: list[Finding] = []
        findings += rule1_confidential_egress(records, self.cfg, health)
        findings += rule2_claim_contradiction(records, self.cfg, health)
        findings += rule3_non_allowlist_egress(records, self.cfg, health)
        return {
            "sensor_health": health,
            "findings": [f.to_dict() for f in findings],
            "alerts": [f.to_dict() for f in findings if f.violation],
        }
