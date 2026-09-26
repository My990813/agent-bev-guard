"""Behavioral baseline (Step 6, part 1).

Scope (threat-model section 12, locked 2026-09-26):

    The system detects and reconstructs behavior; it does not
    determine intent, legality, or culpability.

This module answers ONE machine-answerable question:

    "How unusual was this run, relative to an established baseline
     of past runs, and what evidence supports that assessment?"

It never answers "was it malicious" or "was it legal".

Feature extraction groups fused events by agent_run_id. Events that
carry no run attribution are NOT silently dropped -- they are counted
and surfaced as unattributed coverage, because a triage system that
quietly ignores what it cannot attribute would fabricate completeness.

Baseline statistics are robust (median + MAD), because run-level
features are heavy-tailed: one chatty run should not drag the mean
and mask the next chatty run. For features where the baseline has
zero variance (MAD == 0), ANY deviation is flagged with robust_z=None
and an explicit note -- we do not invent a z-score from a constant.

Novelty sets (known endpoints, known tool bigrams) capture what
counts cannot: first-seen destinations and unseen tool sequences.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from core.fusion import ts_to_epoch

CONFIDENTIAL_LEVELS = {"confidential", "secret"}

NUMERIC_FEATURES = (
    "tool_calls",
    "process_spawns",
    "outbound_bytes",
    "confidential_opens",
)


@dataclass
class RunFeatures:
    run_id: str
    tool_calls: int = 0
    process_spawns: int = 0
    outbound_bytes: int = 0
    confidential_opens: int = 0
    external_endpoints: set[str] = field(default_factory=set)
    tool_sequence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "tool_calls": self.tool_calls,
            "process_spawns": self.process_spawns,
            "outbound_bytes": self.outbound_bytes,
            "confidential_opens": self.confidential_opens,
            "external_endpoints": sorted(self.external_endpoints),
            "tool_sequence": list(self.tool_sequence),
        }


def _sorted_records(records: list[dict]) -> list[dict]:
    def key(r: dict) -> float:
        return ts_to_epoch(r.get("ts_wall", "")) or 0.0

    return sorted(records, key=key)


def extract_run_features(
    records: list[dict],
) -> tuple[dict[str, RunFeatures], int]:
    """Group fused records into per-run features.

    Returns (features_by_run_id, unattributed_event_count).
    Unattributed events (no agent_run_id) are counted, never dropped
    silently -- see module docstring.
    """
    features: dict[str, RunFeatures] = {}
    unattributed = 0

    for rec in _sorted_records(records):
        actor = rec.get("actor", {})
        run_id = actor.get("agent_run_id")
        if not run_id:
            unattributed += 1
            continue
        feat = features.setdefault(run_id, RunFeatures(run_id=run_id))

        et = rec.get("event_type")
        if et == "tool.call":
            feat.tool_calls += 1
            feat.tool_sequence.append(rec.get("action", {}).get("verb", "call"))
        elif et == "process.exec":
            feat.process_spawns += 1
        elif et == "net.connect":
            peer = rec.get("peer") or {}
            if peer.get("id"):
                feat.external_endpoints.add(peer["id"])
        elif et == "net.egress":
            feat.outbound_bytes += rec.get("action", {}).get("bytes", 0)
        elif et == "file.open":
            for ent in rec.get("entities") or []:
                if ent.get("classification") in CONFIDENTIAL_LEVELS:
                    feat.confidential_opens += 1
                    break

    return features, unattributed


def _median(values: list[float]) -> float:
    s = sorted(values)
    n = len(s)
    if n == 0:
        return 0.0
    mid = n // 2
    if n % 2:
        return float(s[mid])
    return (s[mid - 1] + s[mid]) / 2.0


def _mad(values: list[float], med: float) -> float:
    return _median([abs(v - med) for v in values])


def tool_bigrams(sequence: list[str]) -> set[tuple[str, str]]:
    return {(a, b) for a, b in zip(sequence, sequence[1:])}


@dataclass
class Baseline:
    """Robust behavioral baseline built from historical runs."""

    n_runs: int
    median: dict[str, float]
    mad: dict[str, float]
    known_endpoints: set[str]
    known_tool_bigrams: set[tuple[str, str]]
    constant_features: list[str]  # features with MAD == 0 in baseline

    @classmethod
    def build(cls, runs: list[RunFeatures]) -> "Baseline":
        if not runs:
            raise ValueError("baseline requires at least one run")
        median: dict[str, float] = {}
        mad: dict[str, float] = {}
        constant: list[str] = []
        for f in NUMERIC_FEATURES:
            values = [float(getattr(r, f)) for r in runs]
            med = _median(values)
            m = _mad(values, med)
            median[f] = med
            mad[f] = m
            if m == 0.0:
                constant.append(f)
        return cls(
            n_runs=len(runs),
            median=median,
            mad=mad,
            known_endpoints=set().union(
                *(r.external_endpoints for r in runs)
            ) if runs else set(),
            known_tool_bigrams=set().union(
                *(tool_bigrams(r.tool_sequence) for r in runs)
            ) if runs else set(),
            constant_features=constant,
        )

    def to_dict(self) -> dict:
        return {
            "n_runs": self.n_runs,
            "median": self.median,
            "mad": self.mad,
            "constant_features": list(self.constant_features),
            "known_endpoints": sorted(self.known_endpoints),
            "known_tool_bigram_count": len(self.known_tool_bigrams),
        }
