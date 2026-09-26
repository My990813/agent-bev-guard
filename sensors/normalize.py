"""Kernel sensor output normalizer (Step 3).

Converts raw bpftrace output lines (from the sensors/bpftrace/*.bt probes,
collected by sensors/collect.sh inside the Linux VM) into unified Events
appended to the append-only hash-chained EventLog.

Raw line formats (pipe-separated to survive commas in paths):

    EXEC|pid|ppid|uid|nsecs|filename
    FILE|pid|uid|nsecs|flags|ret|path
    CONNECT|pid|nsecs|saddr|daddr|dport
    SEND|pid|nsecs|bytes

nsecs is monotonic-since-boot; wall time is reconstructed as
btime + nsecs/1e9 where btime comes from /proc/stat. This is the single
clock anchor for all kernel sensor events (R1: single VM).

Sensor telemetry (R13): every normalize run emits a sensor.health event
carrying the collection window, per-probe event counts, lost-event
counters (bpftrace "@lost" lines) and a derived health status. Step 5
downgrades negative findings when loss_ratio exceeds a threshold --
absence of evidence is not evidence of absence.

Tolerance model (R14): volume reconciliation uses a configurable
tolerance with an explicit reason, never a hardcoded constant. See
core/recon.py.

Deferred identity (R2): pid/pid_start_ts are recorded where visible;
agent_run_id stays null and identity_source stays UNKNOWN until the
fusion layer resolves runs -- and even then only with confidence labels.
UNKNOWN is a valid state, not an error (R12).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.events import Action, Actor, Entity, Event, EventLog, Peer

O_ACCMODE = 0o3  # O_RDONLY=0, O_WRONLY=1, O_RDWR=2
VERB_BY_MODE = {0: "read", 1: "write", 2: "read_write"}


class Classifier:
    """Longest-prefix path classifier. Path prefixes -> classification."""

    def __init__(self, mapping: dict[str, str] | None = None):
        self.mapping = dict(sorted((mapping or {}).items(), key=lambda kv: -len(kv[0])))

    @classmethod
    def load(cls, path: str | Path | None) -> "Classifier":
        if path is None:
            return cls()
        with Path(path).open("r", encoding="utf-8") as fh:
            return cls(json.load(fh))

    def classify(self, path: str) -> str | None:
        for prefix, level in self.mapping.items():
            if path.startswith(prefix):
                return level
        return None


def bswap16(v: int) -> int:
    return ((v & 0xFF) << 8) | (v >> 8)


def _mk_event(sensor: str, event_type: str, verb: str, pid: int,
              pid_start_ts: float | None, entities: list[Entity] | None = None,
              peer: Peer | None = None, bytes_: int = 0,
              outcome: str = "success", ppid: int | None = None) -> Event:
    return Event(
        sensor=sensor,
        event_type=event_type,
        actor=Actor(pid=pid, pid_start_ts=pid_start_ts, identity_source="UNKNOWN",
                    ppid=ppid),
        action=Action(verb=verb, bytes=bytes_, outcome=outcome),
        entities=entities or [],
        peer=peer,
    )


def parse_exec(fields: list[str], btime: int) -> Event:
    pid, ppid, uid, nsecs, filename = (
        int(fields[0]), int(fields[1]), int(fields[2]), int(fields[3]), fields[4],
    )
    return _mk_event(
        sensor="process",
        event_type="process.exec",
        verb="exec",
        pid=pid,
        pid_start_ts=btime + nsecs / 1e9,
        entities=[Entity(role="dst", kind="process", id=filename)],
        ppid=ppid,
    )


def parse_file(fields: list[str], classifier: Classifier) -> Event | None:
    pid, uid, nsecs, flags, ret, path = (
        int(fields[0]), int(fields[1]), int(fields[2]), int(fields[3]),
        int(fields[4]), fields[5],
    )
    if not path.startswith("/"):
        return None  # relative fd reopens and anon files: skip in MVP
    mode = flags & O_ACCMODE
    verb = VERB_BY_MODE.get(mode, "read")
    outcome = "success" if ret >= 0 else "failure"
    return _mk_event(
        sensor="file",
        event_type="file.open",
        verb=verb,
        pid=pid,
        pid_start_ts=None,  # deferred to fusion layer (R2)
        entities=[Entity(role="src", kind="file", id=path,
                         classification=classifier.classify(path))],
        outcome=outcome,
    )


def parse_connect(fields: list[str], btime: int, bswap: bool) -> Event:
    pid, nsecs, saddr, daddr, dport = (
        int(fields[0]), int(fields[1]), fields[2], fields[3], int(fields[4]),
    )
    if bswap:
        dport = bswap16(dport)
    return _mk_event(
        sensor="network",
        event_type="net.connect",
        verb="connect",
        pid=pid,
        pid_start_ts=btime + nsecs / 1e9,
        peer=Peer(kind="network_endpoint", id=f"{daddr}:{dport}", sni=None),
    )


def parse_send(fields: list[str]) -> Event:
    pid, nsecs, nbytes = int(fields[0]), int(fields[1]), int(fields[2])
    return _mk_event(
        sensor="network",
        event_type="net.egress",
        verb="send",
        pid=pid,
        pid_start_ts=None,
        bytes_=nbytes,
    )


def normalize_line(line: str, btime: int, classifier: Classifier,
                   bswap: bool) -> Event | None:
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("@"):
        return None  # bpftrace headers, lost-event counters, blank lines
    parts = line.split("|")
    kind, fields = parts[0], parts[1:]
    try:
        if kind == "EXEC":
            return parse_exec(fields, btime)
        if kind == "FILE":
            return parse_file(fields, classifier)
        if kind == "CONNECT":
            return parse_connect(fields, btime, bswap)
        if kind == "SEND":
            return parse_send(fields)
    except (ValueError, IndexError):
        return None  # malformed line: skip, count in stats
    return None


def normalize_dir(raw_dir: Path, log: EventLog, classifier: Classifier,
                  bswap: bool) -> dict[str, int]:
    btime = int((raw_dir / "btime.txt").read_text().strip())
    stats = {"lines": 0, "events": 0, "skipped": 0, "lost": 0}
    window = None
    window_file = raw_dir / "window.txt"
    if window_file.exists():
        parts = window_file.read_text().split()
        if len(parts) >= 2:
            window = (int(parts[0]), int(parts[1]))

    for name in ("process.raw", "file.raw", "network.raw"):
        f = raw_dir / name
        if not f.exists():
            continue
        for line in f.read_text().splitlines():
            if line.strip().startswith("@lost"):
                try:
                    stats["lost"] += int(line.split(":")[1].strip().split()[0])
                except (ValueError, IndexError):
                    pass
                continue
            stats["lines"] += 1
            ev = normalize_line(line, btime, classifier, bswap)
            if ev is None:
                stats["skipped"] += 1
                continue
            log.append(ev)
            stats["events"] += 1

    log.append(_sensor_health_event(stats, window))
    return stats


def _sensor_health_event(stats: dict, window: tuple[int, int] | None) -> Event:
    seen = stats["events"]
    lost = stats["lost"]
    loss_ratio = (lost / (seen + lost)) if (seen + lost) else 0.0
    if window is None:
        # no window recorded: we cannot even bound the observation interval
        health = "UNKNOWN"
    elif loss_ratio > 0.05:
        health = "DEGRADED"
    elif lost > 0:
        health = "MINOR_LOSS"
    else:
        health = "HEALTHY"
    note = (
        (f"window={window[0]}..{window[1]} " if window else "window=unknown ")
        + f"events_seen={seen} events_lost={lost} "
        f"loss_ratio={loss_ratio:.4f} health={health}"
    )
    # R20 semantics: health is a NECESSARY but NOT SUFFICIENT signal.
    # HEALTHY means "no loss indicators were observed", NOT "no events
    # were lost". Blind spots not covered by @lost: attach failure, VM
    # suspension, probe malfunction, sensor startup gap.
    if health == "HEALTHY":
        note += "; health=necessary-not-sufficient; blindspots=attach,vm-suspend,startup-gap"
    return Event(
        sensor="process",
        event_type="sensor.health",
        actor=Actor(pid=1, identity_source="UNKNOWN"),  # pid 1 = init/system self
        action=Action(verb="health", outcome="success"),
        entities=[],
        note=note,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="kernel sensor normalizer")
    ap.add_argument("--raw-dir", required=True,
                    help="directory with process.raw/file.raw/network.raw/btime.txt")
    ap.add_argument("--log", required=True, help="path to events.jsonl")
    ap.add_argument("--classes", default=None,
                    help="path classification JSON (prefix -> level)")
    ap.add_argument("--bswap-port", action="store_true",
                    help="apply network-byte-order swap to CONNECT dport")
    args = ap.parse_args()

    log = EventLog(args.log)
    stats = normalize_dir(
        Path(args.raw_dir), log, Classifier.load(args.classes), args.bswap_port
    )
    ok, bad_idx = log.verify()
    print(
        f"raw lines: {stats['lines']}  events: {stats['events']}  "
        f"skipped: {stats['skipped']}  lost: {stats['lost']}  chain ok: {ok}"
        + ("" if ok else f" (broken at {bad_idx})")
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
