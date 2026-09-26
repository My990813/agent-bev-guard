"""Step 4 tests: entity resolution, clock alignment, sensor health telemetry,
tolerance model.

Run: python tests/test_fusion.py
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.fusion import Fusion, align_clocks
from core.recon import Tolerance, reconcile
from sensors.normalize import normalize_dir

BTIME = 1758850000


def _iso(seconds: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()


def make_log(records: list[dict]) -> Path:
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
    )
    for r in records:
        tmp.write(json.dumps(r) + "\n")
    tmp.close()
    return Path(tmp.name)


def kernel_event(pid, ts, event_type="file.open", sensor="file", **kw):
    ev = {
        "event_id": kw.get("event_id", f"ev-{pid}-{ts}"),
        "ts_wall": kw.get("ts_wall", _iso(ts)),
        "ts_mono": float(ts),
        "sensor": sensor,
        "sensor_privilege": "kernel",
        "event_type": event_type,
        "actor": {
            "pid": pid, "pid_start_ts": None, "user": None,
            "agent_run_id": None, "session_id": None,
            "identity_source": "UNKNOWN", "identity_confidence": None,
            "ppid": kw.get("ppid"),
        },
        "entities": kw.get("entities", []),
        "action": {"verb": kw.get("verb", "read"), "bytes": kw.get("bytes", 0),
                   "outcome": "success"},
        "peer": kw.get("peer"),
        "note": None,
    }
    return ev


def gateway_events(run_id="run-abc", client_pid=4242, start=1000, end=1100):
    def gw(event_type, ts):
        return {
            "event_id": f"gw-{event_type}-{ts}",
            "ts_wall": _iso(ts),
            "ts_mono": float(ts),
            "sensor": "tool_gateway",
            "sensor_privilege": "gateway",
            "event_type": event_type,
            "actor": {
                "pid": 5000, "pid_start_ts": None, "user": "u",
                "agent_run_id": run_id, "session_id": None,
                "identity_source": "DIRECT", "identity_confidence": None,
                "client_pid": client_pid, "client_pid_source": "observed_ppid",
                "client_name": "fake-agent",
                "run_id_source": "gateway_issued", "run_id_verified": False,
            },
            "entities": [],
            "action": {"verb": "session", "bytes": 0, "outcome": "success"},
            "peer": None,
            "note": None,
        }
    return gw("gateway.session_start", start), gw("gateway.session_end", end)


def test_attribute_pid_window():
    s, e = gateway_events()
    target = kernel_event(4242, 1050, sensor="network", event_type="net.egress",
                          bytes=2300000)
    f = Fusion([s, e, target])
    out = f.attribute(target)
    assert out["actor"]["agent_run_id"] == "run-abc"
    assert out["actor"]["identity_source"] == "INFERRED"
    assert abs(out["actor"]["identity_confidence"] - 0.9) < 1e-9


def test_outside_window_stays_unknown():
    s, e = gateway_events()
    early = kernel_event(4242, 500, sensor="network", event_type="net.egress")
    late = kernel_event(4242, 2000, sensor="network", event_type="net.egress")
    f = Fusion([s, e, early, late])
    for rec in (early, late):
        out = f.attribute(rec)
        assert out["actor"]["identity_source"] == "UNKNOWN"
        assert out["actor"]["agent_run_id"] is None


def test_unrelated_pid_stays_unknown_r12():
    s, e = gateway_events()
    orphan = kernel_event(9999, 1050, sensor="file", event_type="file.open")
    f = Fusion([s, e, orphan])
    out = f.attribute(orphan)
    assert out["actor"]["identity_source"] == "UNKNOWN"
    assert out["actor"]["agent_run_id"] is None


def test_direct_identity_never_overwritten():
    s, e = gateway_events()
    f = Fusion([s, e])
    out = f.attribute(s)
    assert out["actor"]["identity_source"] == "DIRECT"
    assert out is s


def test_exec_fills_pid_start_ts():
    s, e = gateway_events()
    exec_ev = kernel_event(4242, 900, event_type="process.exec", sensor="process",
                           entities=[{"role": "dst", "kind": "process",
                                      "id": "/usr/bin/python3", "classification": None}])
    exec_ev["actor"]["pid_start_ts"] = BTIME + 900
    target = kernel_event(4242, 1050, sensor="file")
    f = Fusion([s, e, exec_ev, target])
    out = f.attribute(target)
    assert out["actor"]["pid_start_ts"] == BTIME + 900


def test_clock_alignment_is_identity_in_mvp():
    assert align_clocks() == 0.0


def test_r18_mixed_timezone_strings_compare_correctly():
    """+08:00 and Z suffixes must not silently misorder window checks."""
    s, e = gateway_events()  # window in UTC via _iso
    # same instant as window start, expressed with +08:00 offset
    from datetime import datetime, timezone, timedelta
    ts_plus8 = datetime.fromtimestamp(
        1050, tz=timezone(timedelta(hours=8))
    ).isoformat()
    target = kernel_event(4242, 1050, sensor="network", event_type="net.egress")
    target["ts_wall"] = ts_plus8
    f = Fusion([s, e, target])
    out = f.attribute(target)
    assert out["actor"]["agent_run_id"] == "run-abc", (
        "event at 1050 with +08:00 suffix must still fall inside the window"
    )


def test_r17_lineage_attribution_via_ppid():
    """Gateway-spawned MCP server events attribute via process lineage."""
    s, e = gateway_events()
    # gateway pid is 5000 (see gateway_events). MCP server exec'd as its child.
    server_exec = kernel_event(
        6001, 1020, event_type="process.exec", sensor="process",
        entities=[{"role": "dst", "kind": "process", "id": "/usr/bin/node",
                   "classification": None}],
        ppid=5000,
    )
    server_exec["actor"]["pid_start_ts"] = 1020.0
    server_exec["actor"]["ppid"] = 5000
    # network egress by the MCP server, inside the run window
    server_net = kernel_event(6001, 1050, sensor="network",
                              event_type="net.egress", bytes=2300000)
    f = Fusion([s, e, server_exec, server_net])
    out = f.attribute(server_net)
    assert out["actor"]["agent_run_id"] == "run-abc"
    assert out["actor"]["identity_source"] == "INFERRED"
    assert abs(out["actor"]["identity_confidence"] - 0.70) < 1e-9


def test_r17_lineage_respects_window():
    """Server exec'd BEFORE the run started must not attribute."""
    s, e = gateway_events()
    server_exec = kernel_event(
        6002, 500, event_type="process.exec", sensor="process",
        entities=[{"role": "dst", "kind": "process", "id": "/usr/bin/node",
                   "classification": None}],
        ppid=5000,
    )
    server_exec["actor"]["pid_start_ts"] = 500.0
    server_exec["actor"]["ppid"] = 5000
    server_net = kernel_event(6002, 1050, sensor="network", event_type="net.egress")
    f = Fusion([s, e, server_exec, server_net])
    out = f.attribute(server_net)
    assert out["actor"]["identity_source"] == "UNKNOWN"
    assert out["actor"]["agent_run_id"] is None


def test_tolerance_and_reconciliation():
    tol = Tolerance()
    r = reconcile(2300000, 2300000, tol)
    assert r.verdict == "MATCH"
    assert r.tolerance_reason  # must record WHY

    r = reconcile(2600000, 2300000, tol)
    assert r.verdict == "OUT_OF_BAND"

    r = reconcile(2300000, None, Tolerance.from_config({}))
    assert r.verdict == "INSUFFICIENT_EVIDENCE"

    strict = Tolerance.from_config({"ratio": 0.01, "reason": "lab mode"})
    assert reconcile(2400000, 2300000, strict).verdict == "OUT_OF_BAND"
    assert reconcile(2300050, 2300000, strict).verdict == "MATCH"


def test_sensor_health_event_emitted():
    with tempfile.TemporaryDirectory() as tmp:
        raw = Path(tmp) / "vm_out"
        raw.mkdir()
        (raw / "btime.txt").write_text(f"{BTIME}\n")
        (raw / "window.txt").write_text("1758850100\n1758850200\n")
        (raw / "process.raw").write_text("")
        (raw / "file.raw").write_text(
            "FILE|4242|1000|150000000|0|3|/home/mengyan/Docs/image_123.jpg\n"
        )
        (raw / "network.raw").write_text(
            "CONNECT|4242|200000000|10.0.2.15|203.0.113.7|11555\n"
            "@lost: 5 events\n"
            "SEND|4242|200000100|2300000\n"
        )
        from core.events import EventLog
        from sensors.normalize import Classifier
        log = EventLog(Path(tmp) / "events.jsonl")
        stats = normalize_dir(raw, log, Classifier(), False)
        assert stats["lost"] == 5
        health = [r for r in log if r["event_type"] == "sensor.health"]
        assert len(health) == 1
        note = health[0]["note"]
        assert "health=" in note and "loss_ratio=0.6250" in note
        assert "window=1758850100..1758850200" in note
        assert "DEGRADED" in note


def test_r20_health_unknown_without_window():
    """No window.txt -> health must be UNKNOWN, never HEALTHY."""
    with tempfile.TemporaryDirectory() as tmp:
        raw = Path(tmp) / "vm_out"
        raw.mkdir()
        (raw / "btime.txt").write_text(f"{BTIME}\n")
        (raw / "process.raw").write_text("")
        (raw / "file.raw").write_text("")
        (raw / "network.raw").write_text("")
        from core.events import EventLog
        from sensors.normalize import Classifier
        log = EventLog(Path(tmp) / "events.jsonl")
        normalize_dir(raw, log, Classifier(), False)
        note = [r for r in log if r["event_type"] == "sensor.health"][0]["note"]
        assert "health=UNKNOWN" in note


def test_r20_healthy_carries_blindspot_caveat():
    with tempfile.TemporaryDirectory() as tmp:
        raw = Path(tmp) / "vm_out"
        raw.mkdir()
        (raw / "btime.txt").write_text(f"{BTIME}\n")
        (raw / "window.txt").write_text("1758850100\n1758850200\n")
        (raw / "process.raw").write_text("")
        (raw / "file.raw").write_text("")
        (raw / "network.raw").write_text("")
        from core.events import EventLog
        from sensors.normalize import Classifier
        log = EventLog(Path(tmp) / "events.jsonl")
        normalize_dir(raw, log, Classifier(), False)
        note = [r for r in log if r["event_type"] == "sensor.health"][0]["note"]
        assert "health=HEALTHY" in note
        assert "necessary-not-sufficient" in note


if __name__ == "__main__":
    test_attribute_pid_window()
    test_outside_window_stays_unknown()
    test_unrelated_pid_stays_unknown_r12()
    test_direct_identity_never_overwritten()
    test_exec_fills_pid_start_ts()
    test_clock_alignment_is_identity_in_mvp()
    test_r18_mixed_timezone_strings_compare_correctly()
    test_r17_lineage_attribution_via_ppid()
    test_r17_lineage_respects_window()
    test_tolerance_and_reconciliation()
    test_sensor_health_event_emitted()
    test_r20_health_unknown_without_window()
    test_r20_healthy_carries_blindspot_caveat()
    print("all step-4 fusion tests passed")
