#!/usr/bin/env python3
"""Build a demo fused event log for the report CLI.

This is the original motivating scenario, expressed as real Event
objects and appended to a genuine hash-chained EventLog:

    agent run-abc (client pid 4242, gateway pid 5000)
      -> opens confidential /home/mengyan/Docs/image_123.jpg
      -> connects to 203.0.113.7:443 (non-allowlisted)
      -> sends 2,300,000 bytes
      -> self-claims "no files were uploaded"

Usage:
    python examples/make_demo_log.py [output.jsonl]
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.events import (          # noqa: E402
    Action, Actor, Entity, Event, EventLog, Peer,
)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def build_demo_events() -> list[Event]:
    return [
        Event(
            sensor="tool_gateway", event_type="gateway.session_start",
            actor=Actor(
                pid=5000, pid_start_ts=800.0, user="mengyan",
                agent_run_id="run-abc", identity_source="DIRECT",
                client_pid=4242, client_pid_source="observed_ppid",
                client_name="fake-agent",
                run_id_source="gateway_issued", run_id_verified=False,
            ),
            action=Action(verb="session.start"),
            ts_wall=_iso(1000), ts_mono=1000.0,
            event_id="gw-session-start-1000",
        ),
        Event(
            sensor="file", event_type="file.open",
            actor=Actor(pid=4242, pid_start_ts=900.0,
                        agent_run_id="run-abc",
                        identity_source="INFERRED",
                        identity_confidence=0.90),
            action=Action(verb="read"),
            entities=[Entity(role="src", kind="file",
                             id="/home/mengyan/Docs/image_123.jpg",
                             classification="confidential")],
            ts_wall=_iso(1050), ts_mono=1050.0,
            event_id="ev-file-open-1050",
        ),
        Event(
            sensor="network", event_type="net.connect",
            actor=Actor(pid=4242, pid_start_ts=900.0,
                        agent_run_id="run-abc",
                        identity_source="INFERRED",
                        identity_confidence=0.90),
            action=Action(verb="connect"),
            peer=Peer(kind="network_endpoint", id="203.0.113.7:443",
                      sni=None),
            ts_wall=_iso(1051), ts_mono=1051.0,
            event_id="ev-net-connect-1051",
        ),
        Event(
            sensor="network", event_type="net.egress",
            actor=Actor(pid=4242, pid_start_ts=900.0,
                        agent_run_id="run-abc",
                        identity_source="INFERRED",
                        identity_confidence=0.90),
            action=Action(verb="send", bytes=2300000),
            ts_wall=_iso(1052), ts_mono=1052.0,
            event_id="ev-net-egress-1052",
        ),
        Event(
            sensor="agent_self", event_type="agent.claim",
            actor=Actor(pid=4242, pid_start_ts=900.0,
                        agent_run_id="run-abc",
                        identity_source="INFERRED",
                        identity_confidence=0.90),
            action=Action(verb="claim"),
            entities=[Entity(role="dst", kind="object",
                             id="claim:no_upload")],
            ts_wall=_iso(1053), ts_mono=1053.0,
            event_id="claim-1",
            note="agent stated: no files were uploaded",
        ),
        Event(
            sensor="process", event_type="sensor.health",
            actor=Actor(pid=1, identity_source="UNKNOWN"),
            action=Action(verb="health"),
            ts_wall=_iso(1200), ts_mono=1200.0,
            event_id="health-1200",
            note="window=1000..1200 events_seen=6 events_lost=0 "
                 "loss_ratio=0.0000 health=HEALTHY; "
                 "health=necessary-not-sufficient; "
                 "blindspots=attach,vm-suspend,startup-gap",
        ),
        Event(
            sensor="tool_gateway", event_type="gateway.session_end",
            actor=Actor(
                pid=5000, pid_start_ts=800.0, user="mengyan",
                agent_run_id="run-abc", identity_source="DIRECT",
                client_pid=4242, client_pid_source="observed_ppid",
                client_name="fake-agent",
                run_id_source="gateway_issued", run_id_verified=False,
            ),
            action=Action(verb="session.end"),
            ts_wall=_iso(1100), ts_mono=1100.0,
            event_id="gw-session-end-1100",
        ),
    ]


def write_demo_log(path: Path) -> int:
    log = EventLog(path)
    for ev in build_demo_events():
        log.append(ev)
    ok, bad = log.verify()
    if not ok:
        raise RuntimeError(f"demo log chain broken at {bad}")
    return len(log)


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else \
        ROOT / "examples" / "demo_events.jsonl"
    n = write_demo_log(out)
    print(f"wrote {n} events to {out} (hash chain OK)")
