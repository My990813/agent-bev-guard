#!/usr/bin/env python3
"""Generate demo baseline + target logs for the triage CLI (Step 6).

Story: 30 historical runs form the behavioral baseline (normal tool
sequence, known endpoint, ~0.4MB egress each). The target day has 25
runs: 23 within baseline, 1 with a novel endpoint only (MEDIUM), and
the motivating scenario -- confidential read -> novel endpoint ->
8.2MB egress -> agent claims "no upload" (HIGH + policy violations).

Both logs are written as append-only hash-chained EventLogs, exactly
like real sensor output, so the CLI's chain-verification path runs.

Usage:
    python examples/make_triage_demo.py examples/triage_baseline.jsonl \
                                       examples/triage_target.jsonl
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.events import (  # noqa: E402
    Action,
    Actor,
    Entity,
    Event,
    EventLog,
    Peer,
)

T0 = 1758850000.0
KNOWN_EP = "93.184.216.34:443"       # inside baseline, allowlisted
NOVEL_EP = "198.51.100.9:443"        # novel but harmless-ish (MEDIUM)
EVIL_EP = "203.0.113.7:443"          # novel + high volume (HIGH)

NORMAL_TOOLS = ["web_search", "read_file"]
PID_START = 1758849000.0


def normal_run(log: EventLog, run_id: str, base_ts: float, pid: int,
               bytes_out: int = 400_000) -> None:
    log.append(Event(
        sensor="tool_gateway", event_type="tool.call",
        actor=Actor(pid=pid, pid_start_ts=PID_START, agent_run_id=run_id,
                    identity_source="DIRECT"),
        action=Action(verb=NORMAL_TOOLS[0]),
        entities=[Entity(role="dst", kind="tool", id=NORMAL_TOOLS[0])],
        ts_wall=None, ts_mono=base_ts,
    ))
    log.append(Event(
        sensor="tool_gateway", event_type="tool.call",
        actor=Actor(pid=pid, pid_start_ts=PID_START, agent_run_id=run_id,
                    identity_source="DIRECT"),
        action=Action(verb=NORMAL_TOOLS[1]),
        entities=[Entity(role="dst", kind="tool", id=NORMAL_TOOLS[1])],
        ts_wall=None, ts_mono=base_ts + 5,
    ))
    log.append(Event(
        sensor="network", event_type="net.connect",
        actor=Actor(pid=pid, pid_start_ts=PID_START, agent_run_id=run_id,
                    identity_source="INFERRED", identity_confidence=0.90),
        action=Action(verb="net.connect"),
        peer=Peer(id=KNOWN_EP),
        ts_wall=None, ts_mono=base_ts + 10,
    ))
    log.append(Event(
        sensor="network", event_type="net.egress",
        actor=Actor(pid=pid, pid_start_ts=PID_START, agent_run_id=run_id,
                    identity_source="INFERRED", identity_confidence=0.90),
        action=Action(verb="net.egress", bytes=bytes_out),
        ts_wall=None, ts_mono=base_ts + 11,
    ))


def novel_endpoint_run(log: EventLog, run_id: str, base_ts: float,
                       pid: int) -> None:
    """Within-baseline volume, but a first-seen destination (MEDIUM)."""
    log.append(Event(
        sensor="tool_gateway", event_type="tool.call",
        actor=Actor(pid=pid, pid_start_ts=PID_START, agent_run_id=run_id,
                    identity_source="DIRECT"),
        action=Action(verb=NORMAL_TOOLS[0]),
        entities=[Entity(role="dst", kind="tool", id=NORMAL_TOOLS[0])],
        ts_wall=None, ts_mono=base_ts,
    ))
    log.append(Event(
        sensor="tool_gateway", event_type="tool.call",
        actor=Actor(pid=pid, pid_start_ts=PID_START, agent_run_id=run_id,
                    identity_source="DIRECT"),
        action=Action(verb=NORMAL_TOOLS[1]),
        entities=[Entity(role="dst", kind="tool", id=NORMAL_TOOLS[1])],
        ts_wall=None, ts_mono=base_ts + 5,
    ))
    log.append(Event(
        sensor="network", event_type="net.connect",
        actor=Actor(pid=pid, pid_start_ts=PID_START, agent_run_id=run_id,
                    identity_source="INFERRED", identity_confidence=0.90),
        action=Action(verb="net.connect"),
        peer=Peer(id=NOVEL_EP),
        ts_wall=None, ts_mono=base_ts + 10,
    ))
    log.append(Event(
        sensor="network", event_type="net.egress",
        actor=Actor(pid=pid, pid_start_ts=PID_START, agent_run_id=run_id,
                    identity_source="INFERRED", identity_confidence=0.90),
        action=Action(verb="net.egress", bytes=390_000),
        ts_wall=None, ts_mono=base_ts + 11,
    ))


def anomalous_run(log: EventLog, run_id: str, base_ts: float,
                  pid: int) -> None:
    """The motivating scenario: confidential file read -> novel
    endpoint -> 8.2MB egress -> agent self-claims 'no upload'."""
    log.append(Event(
        sensor="tool_gateway", event_type="tool.call",
        actor=Actor(pid=pid, pid_start_ts=PID_START, agent_run_id=run_id,
                    identity_source="DIRECT"),
        action=Action(verb="web_search"),
        entities=[Entity(role="dst", kind="tool", id="web_search")],
        ts_wall=None, ts_mono=base_ts,
    ))
    log.append(Event(
        sensor="tool_gateway", event_type="tool.call",
        actor=Actor(pid=pid, pid_start_ts=PID_START, agent_run_id=run_id,
                    identity_source="DIRECT"),
        action=Action(verb="upload_file"),
        entities=[Entity(role="dst", kind="tool", id="upload_file")],
        ts_wall=None, ts_mono=base_ts + 5,
    ))
    log.append(Event(
        sensor="file", event_type="file.open",
        actor=Actor(pid=pid, pid_start_ts=PID_START, agent_run_id=run_id,
                    identity_source="INFERRED", identity_confidence=0.90),
        action=Action(verb="read"),
        entities=[Entity(role="dst", kind="file",
                         id="/home/mengyan/Docs/image_123.jpg",
                         classification="confidential")],
        ts_wall=None, ts_mono=base_ts + 20,
    ))
    log.append(Event(
        sensor="network", event_type="net.connect",
        actor=Actor(pid=pid, pid_start_ts=PID_START, agent_run_id=run_id,
                    identity_source="INFERRED", identity_confidence=0.90),
        action=Action(verb="net.connect"),
        peer=Peer(id=EVIL_EP),
        ts_wall=None, ts_mono=base_ts + 30,
    ))
    log.append(Event(
        sensor="network", event_type="net.egress",
        actor=Actor(pid=pid, pid_start_ts=PID_START, agent_run_id=run_id,
                    identity_source="INFERRED", identity_confidence=0.90),
        action=Action(verb="net.egress", bytes=8_388_608),
        ts_wall=None, ts_mono=base_ts + 31,
    ))
    log.append(Event(
        sensor="agent_self", event_type="agent.claim",
        actor=Actor(pid=pid, pid_start_ts=PID_START, agent_run_id=run_id,
                    identity_source="INFERRED", identity_confidence=0.90),
        action=Action(verb="claim"),
        entities=[Entity(role="dst", kind="object", id="claim:no_upload")],
        ts_wall=None, ts_mono=base_ts + 40,
    ))


def main() -> int:
    base_path = Path(sys.argv[1]) if len(sys.argv) > 1 else \
        Path("examples/triage_baseline.jsonl")
    target_path = Path(sys.argv[2]) if len(sys.argv) > 2 else \
        Path("examples/triage_target.jsonl")
    for p in (base_path, target_path):
        if p.exists():
            p.unlink()

    # baseline: 30 normal runs with realistic volume variance
    base_log = EventLog(base_path)
    sizes = [380_000, 390_000, 400_000, 410_000, 420_000] * 6
    for i in range(30):
        normal_run(base_log, f"base-{i:03d}", T0 + i * 600, 3000 + i,
                   bytes_out=sizes[i])

    # target day: 23 normal + 1 novel-endpoint + 1 anomalous
    tgt_log = EventLog(target_path)
    for i in range(23):
        normal_run(tgt_log, f"day2-{i:03d}", T0 + 100_000 + i * 600,
                   5000 + i, bytes_out=sizes[i % 5])
    novel_endpoint_run(tgt_log, "day2-novel", T0 + 120_000, 5100)
    anomalous_run(tgt_log, "day2-evil", T0 + 121_000, 5101)

    print(f"baseline: {len(base_log)} events, 30 runs -> {base_path}")
    print(f"target:   {len(tgt_log)} events, 25 runs -> {target_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
