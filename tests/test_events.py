"""Step 1 sanity tests: event model, validation, hash-chain tamper detection.

Run: python tests/test_events.py
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.events import Actor, Action, Entity, Event, EventLog, EventValidationError, Peer


def make_events() -> list[Event]:
    pid = 4242
    return [
        Event(
            sensor="file",
            event_type="file.read",
            actor=Actor(pid=pid, pid_start_ts=1758873600.0, user="mengyan"),
            action=Action(verb="read", bytes=2300000),
            entities=[Entity(role="src", kind="file", id="/Users/mengyan/Docs/image_123.jpg",
                             classification="confidential")],
        ),
        Event(
            sensor="network",
            event_type="net.egress",
            actor=Actor(pid=pid, pid_start_ts=1758873600.0, user="mengyan"),
            action=Action(verb="post", bytes=2300000),
            peer=Peer(kind="network_endpoint", id="203.0.113.7:443", sni="image-host.com"),
        ),
        Event(
            sensor="agent_self",
            event_type="agent.claim",
            actor=Actor(pid=pid, pid_start_ts=1758873600.0, user="mengyan",
                        agent_run_id="run-abc"),
            action=Action(verb="claim", bytes=0),
            entities=[Entity(role="dst", kind="object", id="claim:no_upload")],
            note="no files were uploaded",
        ),
    ]


def test_validation_rejects_bad_events():
    bad = Event(
        sensor="file",
        event_type="file read!",
        actor=Actor(pid=0),
        action=Action(verb="read"),
    )
    try:
        bad.validate()
    except EventValidationError:
        pass
    else:
        raise AssertionError("bad event_type / pid should be rejected")

    bad_cls = Event(
        sensor="file",
        event_type="file.read",
        actor=Actor(pid=1),
        action=Action(verb="read"),
        entities=[Entity(role="src", kind="file", id="x", classification="top_secret")],
    )
    try:
        bad_cls.validate()
    except EventValidationError:
        pass
    else:
        raise AssertionError("unknown classification should be rejected")


def test_hash_chain_and_tamper_detection():
    with tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "events.jsonl"
        log = EventLog(log_path)
        for ev in make_events():
            log.append(ev)

        assert len(log) == 3
        ok, bad_idx = log.verify()
        assert ok and bad_idx is None, f"clean chain should verify, got {bad_idx}"

        rel = EventLog(log_path)
        assert len(rel) == 3 and rel.verify()[0]

        records = [json.loads(line) for line in log_path.read_text().splitlines() if line]
        records[1]["action"]["bytes"] = 1
        log_path.write_text("\n".join(json.dumps(r) for r in records) + "\n")

        reloaded = EventLog(log_path)
        ok, bad_idx = reloaded.verify()
        assert not ok and bad_idx == 2, f"tamper at record 2 should be detected, got {bad_idx}"

    print("all step-1 tests passed")


if __name__ == "__main__":
    test_validation_rejects_bad_events()
    test_hash_chain_and_tamper_detection()
