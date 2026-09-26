"""Unified event model for Agent BEV Guard.

Every sensor (kernel-level, gateway-level, or self-reported) normalizes its
observations into Event objects before anything else happens. Fusion,
entity resolution, and detection all consume these records only.

Design notes:
- No payload/content field anywhere: the audit log itself must not become
  a leak channel.
- Dual timestamps: ts_wall for cross-source alignment, ts_mono for
  same-host causal ordering.
- Actor identity is (pid, pid_start_ts) because pids get reused.
- sensor_privilege is a *declared* label (registry claim), NOT a verified
  trust root. Downstream rules may use it as metadata weighting only;
  attestation is a later milestone.
- Identity resolution is deferred: kernel sensors cannot see agent_run_id.
  Resolved identities must carry identity_source (DIRECT / INFERRED /
  UNKNOWN) and, when inferred, identity_confidence. An inferred identity
  is never treated as fact.
- run_id vs authentication are separate concepts: run_id_source records
  who issued the id (gateway_issued / client_declared) and run_id_verified
  records whether it was cryptographically verified (always False in MVP).
  client_pid_source distinguishes system-observed values (observed_ppid)
  from client-claimed ones (client_declared).
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

GENESIS_HASH = "0" * 64

SENSOR_PRIVILEGE = {
    "process": "kernel",
    "file": "kernel",
    "network": "kernel",
    "identity": "system",
    "tool_gateway": "gateway",
    "external_service": "external",
    "agent_self": "untrusted",
}

PRIVILEGE_RANK = {"kernel": 4, "system": 3, "gateway": 2, "external": 1, "untrusted": 0}

ENTITY_KINDS = {"file", "socket", "process", "tool", "dataset", "object"}
ENTITY_ROLES = {"src", "dst"}
CLASSIFICATIONS = {"public", "internal", "confidential", "secret"}


class EventValidationError(ValueError):
    pass


IDENTITY_SOURCES = {"DIRECT", "INFERRED", "UNKNOWN"}


@dataclass
class Actor:
    pid: int
    pid_start_ts: float | None = None
    user: str | None = None
    agent_run_id: str | None = None
    session_id: str | None = None
    identity_source: str = "UNKNOWN"
    identity_confidence: float | None = None
    client_pid: int | None = None
    client_pid_source: str | None = None
    client_name: str | None = None
    run_id_source: str | None = None
    run_id_verified: bool = False
    ppid: int | None = None


@dataclass
class Entity:
    role: str
    kind: str
    id: str
    classification: str | None = None


@dataclass
class Peer:
    kind: str = "network_endpoint"
    id: str | None = None
    sni: str | None = None


@dataclass
class Action:
    verb: str
    bytes: int = 0
    outcome: str = "success"


@dataclass
class Event:
    sensor: str
    event_type: str
    actor: Actor
    action: Action
    entities: list[Entity] = field(default_factory=list)
    peer: Peer | None = None
    ts_wall: str | None = None
    ts_mono: float | None = None
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    note: str | None = None

    def __post_init__(self) -> None:
        if self.ts_wall is None:
            self.ts_wall = datetime.now(timezone.utc).isoformat()
        if self.ts_mono is None:
            self.ts_mono = time.monotonic()

    @property
    def sensor_privilege(self) -> str:
        return SENSOR_PRIVILEGE[self.sensor]

    @property
    def trust_rank(self) -> int:
        return PRIVILEGE_RANK[self.sensor_privilege]

    def validate(self) -> None:
        if self.sensor not in SENSOR_PRIVILEGE:
            raise EventValidationError(f"unknown sensor: {self.sensor}")
        if not self.event_type or any(
            ch not in "abcdefghijklmnopqrstuvwxyz0123456789_." for ch in self.event_type
        ):
            raise EventValidationError(f"bad event_type: {self.event_type!r}")
        if self.actor.pid < 1:
            raise EventValidationError(f"bad pid: {self.actor.pid}")
        if self.actor.identity_source not in IDENTITY_SOURCES:
            raise EventValidationError(
                f"bad identity_source: {self.actor.identity_source}"
            )
        if self.actor.identity_confidence is not None and not (
            0.0 <= self.actor.identity_confidence <= 1.0
        ):
            raise EventValidationError(
                f"identity_confidence out of range: {self.actor.identity_confidence}"
            )
        if self.actor.run_id_source is not None and self.actor.run_id_source not in {
            "gateway_issued",
            "client_declared",
        }:
            raise EventValidationError(
                f"bad run_id_source: {self.actor.run_id_source}"
            )
        if self.actor.client_pid is not None and self.actor.client_pid < 1:
            raise EventValidationError(f"bad client_pid: {self.actor.client_pid}")
        if self.actor.client_pid_source is not None and self.actor.client_pid_source not in {
            "observed_ppid",
            "client_declared",
        }:
            raise EventValidationError(
                f"bad client_pid_source: {self.actor.client_pid_source}"
            )
        if not isinstance(self.actor.run_id_verified, bool):
            raise EventValidationError("run_id_verified must be a bool")
        if self.actor.ppid is not None and self.actor.ppid < 1:
            raise EventValidationError(f"bad ppid: {self.actor.ppid}")
        if self.action.verb and any(
            ch not in "abcdefghijklmnopqrstuvwxyz0123456789_." for ch in self.action.verb
        ):
            raise EventValidationError(f"bad verb: {self.action.verb!r}")
        if self.action.bytes < 0:
            raise EventValidationError("bytes must be >= 0")
        if self.action.outcome not in {"success", "failure", "denied"}:
            raise EventValidationError(f"bad outcome: {self.action.outcome}")
        for ent in self.entities:
            if ent.role not in ENTITY_ROLES:
                raise EventValidationError(f"bad entity role: {ent.role}")
            if ent.kind not in ENTITY_KINDS:
                raise EventValidationError(f"bad entity kind: {ent.kind}")
            if not ent.id:
                raise EventValidationError("entity id must be non-empty")
            if ent.classification is not None and ent.classification not in CLASSIFICATIONS:
                raise EventValidationError(f"bad classification: {ent.classification}")
        if self.peer is not None and not self.peer.id:
            raise EventValidationError("peer id must be non-empty")

    def to_dict(self, include_integrity: bool = False) -> dict:
        d = {
            "event_id": self.event_id,
            "ts_wall": self.ts_wall,
            "ts_mono": self.ts_mono,
            "sensor": self.sensor,
            "sensor_privilege": self.sensor_privilege,
            "event_type": self.event_type,
            "actor": asdict(self.actor),
            "entities": [asdict(e) for e in self.entities],
            "action": asdict(self.action),
            "peer": asdict(self.peer) if self.peer is not None else None,
            "note": self.note,
        }
        if include_integrity:
            d["integrity"] = self.integrity
        return d

    integrity: dict = field(default_factory=dict, repr=False, compare=False)


def canonical_json(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def event_hash(event_dict: dict, prev_hash: str) -> str:
    body = {k: v for k, v in event_dict.items() if k != "integrity"}
    return hashlib.sha256((prev_hash + canonical_json(body)).encode("utf-8")).hexdigest()


class EventLog:
    """Append-only JSONL event log with a tamper-evident hash chain.

    Each record stores the hash of (previous hash + canonical event body).
    Any edit, deletion, or insertion breaks the chain and is detectable by
    verify().
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.seq = 0
        self.prev_hash = GENESIS_HASH
        self._records: list[dict] = []
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                self._records.append(rec)
                self.seq = rec["integrity"]["seq"]
                self.prev_hash = rec["integrity"]["hash"]

    def append(self, event: Event) -> dict:
        event.validate()
        record = event.to_dict()
        h = event_hash(record, self.prev_hash)
        record["integrity"] = {
            "seq": self.seq + 1,
            "prev_hash": self.prev_hash,
            "hash": h,
        }
        self.seq += 1
        self.prev_hash = h
        self._records.append(record)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(canonical_json(record) + "\n")
        return record

    def verify(self) -> tuple[bool, int | None]:
        prev = GENESIS_HASH
        for idx, rec in enumerate(self._records, start=1):
            integ = rec.get("integrity", {})
            if integ.get("seq") != idx:
                return False, idx
            if integ.get("prev_hash") != prev:
                return False, idx
            if event_hash(rec, prev) != integ.get("hash"):
                return False, idx
            prev = integ["hash"]
        return True, None

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self):
        return iter(self._records)
