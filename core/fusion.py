"""Fusion layer: entity resolution + clock alignment (Step 4).

Fixed principle (2026-09-26):

    Every event must have a WELL-DEFINED identity state --
    not necessarily an identity. The system is allowed to be
    uncertain; it is never allowed to fabricate certainty.

What this module does:

1. Clock alignment (R18): all window comparisons use epoch seconds
   parsed from ts_wall (ts_epoch). ISO string comparison was a
   correctness bug -- mixed timezone suffixes (+08:00 vs Z) sort
   incorrectly even on a single VM. ts_wall is kept for audit display
   only. align_clocks() exists as the future hook for cross-host
   clock_offset (out of MVP scope).

2. Process lineage (R17): EXEC events now carry ppid. The fusion layer
   builds a full (pid, pid_start_ts) -> ppid map and can walk a pid's
   ancestry. A gateway-spawned MCP server (child of the gateway pid)
   is attributed to the run that was active when the server exec'd.

3. Run attribution with evidence semantics (R19):
   identity_confidence is a HEURISTIC EVIDENCE SCORE, NOT a probability
   that the attribution is correct:

       DIRECT (gateway self-observed)          -> 0.99
       client_pid direct match + in window     -> 0.90  strong evidence
       process lineage to gateway/client pid   -> 0.70  medium evidence
       time-only correlation                   -> 0.30  weak evidence (unused in MVP)
       no defensible attribution               -> None / UNKNOWN

   Downstream consumers (Step 5) may use the score ONLY for ranking,
   display, and conflict resolution -- NEVER as a hard alert threshold.
   There is no calibration behind these numbers yet.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

CONF_DIRECT = 0.99
CONF_PID_WINDOW = 0.90
CONF_LINEAGE = 0.70
CONF_TIME_ONLY = 0.30


def ts_to_epoch(ts_wall: str) -> float | None:
    """Parse ISO 8601 wall time to epoch seconds. None if unparsable.

    Handles mixed timezone suffixes correctly (R18): both
    2026-09-26T14:00:00+08:00 and 2026-09-26T06:00:00Z map to the
    same epoch value.
    """
    if not ts_wall:
        return None
    try:
        return datetime.fromisoformat(ts_wall.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


@dataclass
class ExecRecord:
    pid: int
    pid_start_ts: float
    filename: str
    ppid: int


@dataclass
class RunRecord:
    run_id: str
    client_pid: int
    start_epoch: float
    end_epoch: float | None
    gateway_pid: int | None = None
    server_pids: set[int] = field(default_factory=set)


class Fusion:
    def __init__(self, records: list[dict]):
        self.records = records
        self.execs: list[ExecRecord] = []
        self.execs_by_pid: dict[int, list[ExecRecord]] = {}
        self.runs: list[RunRecord] = []
        self._load()

    @classmethod
    def load(cls, path: str | Path) -> "Fusion":
        with Path(path).open("r", encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh if line.strip()]
        return cls(records)

    def _load(self) -> None:
        for r in self.records:
            et = r.get("event_type")
            sensor = r.get("sensor")
            actor = r.get("actor", {})
            if et == "process.exec" and sensor == "process":
                rec = ExecRecord(
                    pid=actor["pid"],
                    pid_start_ts=actor.get("pid_start_ts") or 0.0,
                    filename=(r.get("entities") or [{}])[0].get("id", ""),
                    ppid=actor.get("ppid") or 0,
                )
                self.execs.append(rec)
                self.execs_by_pid.setdefault(rec.pid, []).append(rec)
            elif et in ("gateway.session_start", "gateway.session_end") \
                    and sensor == "tool_gateway":
                run_id = actor.get("agent_run_id")
                client_pid = actor.get("client_pid")
                if run_id is None or client_pid is None:
                    continue
                rec = self._run_by_id(run_id)
                if rec is None:
                    rec = RunRecord(
                        run_id=run_id,
                        client_pid=client_pid,
                        start_epoch=ts_to_epoch(r["ts_wall"]) or 0.0,
                        end_epoch=None,
                        gateway_pid=actor.get("pid"),
                    )
                    self.runs.append(rec)
                if et == "gateway.session_end":
                    rec.end_epoch = ts_to_epoch(r["ts_wall"])

        # lineage: gateway-spawned MCP servers belong to the run whose
        # session window contains their exec time (R17).
        for pid, recs in self.execs_by_pid.items():
            for ex in recs:
                if ex.ppid == 0:
                    continue
                parent_execs = self.execs_by_pid.get(ex.ppid, [])
                for run in self.runs:
                    if run.gateway_pid is None:
                        continue
                    parent_is_gateway = (
                        ex.ppid == run.gateway_pid
                        or any(p.ppid == run.gateway_pid for p in parent_execs)
                    )
                    if not parent_is_gateway:
                        continue
                    if self._epoch_in_window(ex.pid_start_ts, run):
                        run.server_pids.add(pid)
                        break

    def _run_by_id(self, run_id: str) -> RunRecord | None:
        for rec in self.runs:
            if rec.run_id == run_id:
                return rec
        return None

    def exec_for_pid(self, pid: int, at_ts: float | None) -> ExecRecord | None:
        """Latest exec of this pid at or before at_ts (None = any)."""
        candidates = self.execs_by_pid.get(pid, [])
        if not candidates:
            return None
        if at_ts is None:
            return max(candidates, key=lambda e: e.pid_start_ts)
        before = [e for e in candidates if e.pid_start_ts <= at_ts]
        if not before:
            return None
        return max(before, key=lambda e: e.pid_start_ts)

    @staticmethod
    def _epoch_in_window(epoch: float | None, run: RunRecord) -> bool:
        if epoch is None:
            return False
        if epoch < run.start_epoch:
            return False
        if run.end_epoch is not None and epoch > run.end_epoch:
            return False
        return True

    def attribute(self, rec: dict) -> dict:
        """Return a copy of rec with identity fields possibly enriched.

        Never overwrites DIRECT identity. Never invents identity when
        attribution is not defensible -- leaves UNKNOWN (R12).
        """
        actor = rec.get("actor", {})
        if actor.get("identity_source") == "DIRECT":
            return rec
        if rec.get("sensor") not in ("process", "file", "network"):
            return rec

        pid = actor.get("pid")
        if pid is None:
            return rec
        epoch = ts_to_epoch(rec.get("ts_wall", ""))

        out = json.loads(json.dumps(rec))
        out_actor = out["actor"]

        exec_rec = self.exec_for_pid(pid, None)
        if exec_rec is not None:
            if out_actor.get("pid_start_ts") is None:
                out_actor["pid_start_ts"] = exec_rec.pid_start_ts
            if out_actor.get("ppid") is None and exec_rec.ppid:
                out_actor["ppid"] = exec_rec.ppid

        best: tuple[float, str] | None = None
        for run in self.runs:
            if pid == run.client_pid and self._epoch_in_window(epoch, run):
                best = (CONF_PID_WINDOW, run.run_id)
                break
            if pid in run.server_pids and self._epoch_in_window(epoch, run):
                if best is None:
                    best = (CONF_LINEAGE, run.run_id)

        if best is not None:
            conf, run_id = best
            out_actor["agent_run_id"] = run_id
            out_actor["identity_source"] = "INFERRED"
            out_actor["identity_confidence"] = conf
        # else: stays UNKNOWN -- a valid state, not an error (R12)

        return out

    def enrich_all(self) -> list[dict]:
        return [self.attribute(r) for r in self.records]


def align_clocks() -> float:
    """Clock offset between gateway clock and kernel clock.

    Single-VM MVP: both are the same OS clock, offset = 0. Kept as a
    function so a future NTP-based estimate can be swapped in without
    changing consumers.
    """
    return 0.0
