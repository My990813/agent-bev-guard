"""Step 5 part-A tests: provenance graph + rule engine.

Run: python tests/test_rules.py

Scenario 1 is the original motivating example, end to end:
confidential image opened -> POST-sized egress to a non-allowlisted host
-> agent self-claims "no upload" -> all three rules must fire.
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.graph import build_graph
from core.rules import RuleConfig, RuleEngine, endpoint_allowed, sensor_health


def _iso(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()


def kernel_event(pid, ts, event_type, sensor, *, run_id=None, idsrc="UNKNOWN",
                 conf=None, bytes_=0, entities=None, peer=None, verb="read",
                 pstart=900.0):
    # pstart: pid_start_ts (post-fusion records carry it; None = no exec
    # record fused in, process instance unconfirmable per R21)
    return {
        "event_id": f"ev-{event_type}-{pid}-{int(ts)}-{pstart}",
        "ts_wall": _iso(ts),
        "ts_mono": float(ts),
        "sensor": sensor,
        "sensor_privilege": "kernel",
        "event_type": event_type,
        "actor": {
            "pid": pid, "pid_start_ts": pstart, "user": None,
            "agent_run_id": run_id, "session_id": None,
            "identity_source": idsrc, "identity_confidence": conf,
        },
        "entities": entities or [],
        "action": {"verb": verb, "bytes": bytes_, "outcome": "success"},
        "peer": peer,
        "note": None,
    }


def gateway_session(run_id="run-abc", client_pid=4242, gw_pid=5000,
                    start=1000, end=1100):
    def gw(event_type, ts):
        return {
            "event_id": f"gw-{event_type}-{int(ts)}",
            "ts_wall": _iso(ts), "ts_mono": float(ts),
            "sensor": "tool_gateway", "sensor_privilege": "gateway",
            "event_type": event_type,
            "actor": {
                "pid": gw_pid, "pid_start_ts": None, "user": "u",
                "agent_run_id": run_id, "session_id": None,
                "identity_source": "DIRECT", "identity_confidence": None,
                "client_pid": client_pid, "client_pid_source": "observed_ppid",
                "client_name": "fake-agent",
                "run_id_source": "gateway_issued", "run_id_verified": False,
            },
            "entities": [],
            "action": {"verb": "session", "bytes": 0, "outcome": "success"},
            "peer": None, "note": None,
        }
    return gw("gateway.session_start", start), gw("gateway.session_end", end)


def health_event(status="HEALTHY", ts=1200):
    note = f"window=1000..1200 events_seen=10 events_lost=0 loss_ratio=0.0000 health={status}"
    if status == "HEALTHY":
        note += "; health=necessary-not-sufficient; blindspots=attach,vm-suspend,startup-gap"
    return {
        "event_id": f"health-{int(ts)}", "ts_wall": _iso(ts), "ts_mono": float(ts),
        "sensor": "process", "sensor_privilege": "kernel",
        "event_type": "sensor.health",
        "actor": {"pid": 1, "pid_start_ts": None, "user": None,
                  "agent_run_id": None, "session_id": None,
                  "identity_source": "UNKNOWN", "identity_confidence": None},
        "entities": [],
        "action": {"verb": "health", "bytes": 0, "outcome": "success"},
        "peer": None, "note": note,
    }


def scenario_full():
    """The original example: image read -> egress -> 'no upload' claim."""
    s, e = gateway_session()
    return [
        s, e,
        kernel_event(4242, 1050, "file.open", "file", run_id="run-abc",
                     idsrc="INFERRED", conf=0.90,
                     entities=[{"role": "src", "kind": "file",
                                "id": "/home/mengyan/Docs/image_123.jpg",
                                "classification": "confidential"}]),
        kernel_event(4242, 1051, "net.connect", "network", run_id="run-abc",
                     idsrc="INFERRED", conf=0.90, verb="connect",
                     peer={"kind": "network_endpoint",
                           "id": "203.0.113.7:443", "sni": None}),
        kernel_event(4242, 1052, "net.egress", "network", run_id="run-abc",
                     idsrc="INFERRED", conf=0.90, bytes_=2300000, verb="send"),
        {
            "event_id": "claim-1", "ts_wall": _iso(1053), "ts_mono": 1053.0,
            "sensor": "agent_self", "sensor_privilege": "untrusted",
            "event_type": "agent.claim",
            "actor": {"pid": 4242, "pid_start_ts": None, "user": None,
                      "agent_run_id": "run-abc", "session_id": None,
                      "identity_source": "INFERRED", "identity_confidence": 0.90},
            "entities": [{"role": "dst", "kind": "object",
                          "id": "claim:no_upload", "classification": None}],
            "action": {"verb": "claim", "bytes": 0, "outcome": "success"},
            "peer": None, "note": "agent stated: no files were uploaded",
        },
        health_event(),
    ]


def test_graph_builds_nodes_and_edges():
    g = build_graph(scenario_full())
    stats = g.stats()
    assert stats["by_kind"]["run"] >= 1
    assert stats["by_kind"]["file"] == 1
    assert stats["by_kind"]["endpoint"] == 1
    file_node = g.node("file:/home/mengyan/Docs/image_123.jpg")
    assert file_node.classification == "confidential"
    edges = g.edges_from("pid:4242")
    verbs = {e.verb for e in edges}
    assert "read" in verbs and "connect" in verbs and "send" in verbs
    read_edge = next(e for e in edges if e.verb == "read")
    assert read_edge.sensor == "file" and read_edge.sensor_privilege == "kernel"
    assert read_edge.identity_source == "INFERRED"
    claim_edge = next(e for e in g.edges if e.sensor == "agent_self")
    assert claim_edge.sensor_privilege == "untrusted"


def test_rule_engine_full_scenario():
    cfg = RuleConfig(
        allowlist=["10.0.0.0/8", "151.101.0.0/16"],
        file_sizes={"/home/mengyan/Docs/image_123.jpg": 2300000},
    )
    out = RuleEngine(cfg).run(scenario_full())
    assert out["sensor_health"] == "HEALTHY"

    by_rule = {}
    for f in out["findings"]:
        by_rule.setdefault(f["rule"], []).append(f)

    r1 = by_rule["CONFIDENTIAL_FILE_TO_EXTERNAL_EGRESS"]
    assert len(r1) == 1 and r1[0]["violation"]
    assert r1[0]["conclusion"] == "ALERT_WITH_INFERRED_LINEAGE"
    assert r1[0]["lineage"] == "INFERRED"
    assert abs(r1[0]["confidence"] - 0.90) < 1e-9
    assert r1[0]["details"]["volume_reconciliation"]["verdict"] == "MATCH"
    assert r1[0]["details"]["bytes_sent"] == 2300000
    assert len(r1[0]["evidence"]) >= 3

    r2 = by_rule["AGENT_CLAIM_CONTRADICTED"]
    assert r2[0]["violation"]
    assert r2[0]["conclusion"] == "ALERT_WITH_INFERRED_LINEAGE"
    assert r2[0]["details"]["observed_egress_bytes"] == 2300000

    r3 = by_rule["EGRESS_TO_NON_ALLOWLIST"]
    assert len(r3) == 1 and r3[0]["violation"]
    assert r3[0]["details"]["endpoint"] == "203.0.113.7:443"
    assert r3[0]["details"]["bytes_sent"] == 2300000

    assert len(out["alerts"]) == 3


def test_allowlist_exempts():
    recs = scenario_full()
    for r in recs:
        if r.get("peer") and r["peer"]["id"] == "203.0.113.7:443":
            r["peer"]["id"] = "151.101.1.140:443"  # inside allowlist cidr
    cfg = RuleConfig(allowlist=["151.101.0.0/16"])
    out = RuleEngine(cfg).run(recs)
    by_rule = {}
    for f in out["findings"]:
        by_rule.setdefault(f["rule"], []).append(f)
    assert all(not f["violation"] for f in by_rule["CONFIDENTIAL_FILE_TO_EXTERNAL_EGRESS"])
    assert all(not f["violation"] for f in by_rule["EGRESS_TO_NON_ALLOWLIST"])
    # rule 2 still fires: claim contradicted even for allowlisted egress
    assert by_rule["AGENT_CLAIM_CONTRADICTED"][0]["violation"]


def test_degraded_sensor_makes_no_violation_inconclusive():
    recs = [
        kernel_event(4242, 1050, "file.open", "file", run_id="run-abc",
                     entities=[{"role": "src", "kind": "file",
                                "id": "/home/mengyan/Docs/image_123.jpg",
                                "classification": "confidential"}]),
        kernel_event(4242, 1051, "net.connect", "network", run_id="run-abc",
                     peer={"kind": "network_endpoint",
                           "id": "10.1.2.3:443", "sni": None}, verb="connect"),
        health_event(status="DEGRADED"),
    ]
    out = RuleEngine(RuleConfig(allowlist=["10.0.0.0/8"])).run(recs)
    assert out["sensor_health"] == "DEGRADED"
    for f in out["findings"]:
        if not f["violation"] and f["conclusion"] == "NO_VIOLATION":
            raise AssertionError("degraded sensor must not yield NO_VIOLATION")
    r1 = next(f for f in out["findings"]
              if f["rule"] == "CONFIDENTIAL_FILE_TO_EXTERNAL_EGRESS")
    assert r1["conclusion"] == "INCONCLUSIVE_DUE_TO_SENSOR_LOSS"


def test_no_claims_is_not_applicable():
    recs = [
        kernel_event(4242, 1050, "file.open", "file",
                     entities=[{"role": "src", "kind": "file",
                                "id": "/tmp/x", "classification": None}]),
        health_event(),
    ]
    out = RuleEngine(RuleConfig()).run(recs)
    r2 = next(f for f in out["findings"]
              if f["rule"] == "AGENT_CLAIM_CONTRADICTED")
    assert r2["conclusion"] == "NOT_APPLICABLE"
    assert not r2["violation"]


def test_volume_without_size_is_insufficient_not_fake():
    recs = scenario_full()
    cfg = RuleConfig(allowlist=[])  # no file_sizes provided
    out = RuleEngine(cfg).run(recs)
    r1 = next(f for f in out["findings"]
              if f["rule"] == "CONFIDENTIAL_FILE_TO_EXTERNAL_EGRESS")
    assert r1["violation"]  # still alerts on co-occurrence
    assert r1["details"]["volume_reconciliation"]["verdict"] == "INSUFFICIENT_EVIDENCE"


def test_unknown_lineage_alert_is_labeled():
    recs = scenario_full()
    for r in recs:
        if r["sensor"] in ("file", "network"):
            r["actor"]["agent_run_id"] = None
            r["actor"]["identity_source"] = "UNKNOWN"
            r["actor"]["identity_confidence"] = None
    cfg = RuleConfig(file_sizes={"/home/mengyan/Docs/image_123.jpg": 2300000})
    out = RuleEngine(cfg).run(recs)
    r1 = next(f for f in out["findings"]
              if f["rule"] == "CONFIDENTIAL_FILE_TO_EXTERNAL_EGRESS")
    assert r1["conclusion"] == "ALERT_WITH_UNKNOWN_LINEAGE"
    assert r1["lineage"] == "UNKNOWN" and r1["confidence"] is None


def test_pid_reuse_refuses_attribution_r21():
    """Same pid, DIFFERENT process instance (pid reused): the egress of
    the new process must NOT be attributed to the old process's file
    access. Prefer NO finding over a fabricated causal chain."""
    recs = [
        # old process instance: opens the confidential file at t=1050
        kernel_event(4242, 1050, "file.open", "file", pstart=900.0,
                     entities=[{"role": "src", "kind": "file",
                                "id": "/home/mengyan/Docs/image_123.jpg",
                                "classification": "confidential"}]),
        # new process instance (same pid, later start): connects + sends
        kernel_event(4242, 1060, "net.connect", "network", pstart=955.0,
                     verb="connect",
                     peer={"kind": "network_endpoint",
                           "id": "203.0.113.7:443", "sni": None}),
        kernel_event(4242, 1061, "net.egress", "network", pstart=955.0,
                     bytes_=2300000, verb="send"),
        health_event(),
    ]
    out = RuleEngine(RuleConfig()).run(recs)
    r1 = [f for f in out["findings"]
          if f["rule"] == "CONFIDENTIAL_FILE_TO_EXTERNAL_EGRESS"]
    assert all(not f["violation"] for f in r1), \
        "pid reuse must not produce an automatic causal attribution"
    # rule 3 still fires: the connect itself is to a non-allowlisted endpoint
    r3 = next(f for f in out["findings"]
              if f["rule"] == "EGRESS_TO_NON_ALLOWLIST")
    assert r3["violation"]


def test_missing_pid_start_ts_refuses_attribution_r21():
    """No exec records fused in -> pid_start_ts is None -> process
    instance unconfirmable -> pid-only match must NOT attribute."""
    recs = [
        kernel_event(4242, 1050, "file.open", "file", pstart=None,
                     entities=[{"role": "src", "kind": "file",
                                "id": "/home/mengyan/Docs/image_123.jpg",
                                "classification": "confidential"}]),
        kernel_event(4242, 1060, "net.connect", "network", pstart=None,
                     verb="connect",
                     peer={"kind": "network_endpoint",
                           "id": "203.0.113.7:443", "sni": None}),
        kernel_event(4242, 1061, "net.egress", "network", pstart=None,
                     bytes_=2300000, verb="send"),
        health_event(),
    ]
    out = RuleEngine(RuleConfig()).run(recs)
    r1 = [f for f in out["findings"]
          if f["rule"] == "CONFIDENTIAL_FILE_TO_EXTERNAL_EGRESS"]
    assert all(not f["violation"] for f in r1)
    # run-based attribution still works when run_id is present
    recs2 = scenario_full()
    for r in recs2:
        if r["sensor"] in ("file", "network"):
            r["actor"]["pid_start_ts"] = None  # no exec fused
    out2 = RuleEngine(RuleConfig()).run(recs2)
    r1b = next(f for f in out2["findings"]
               if f["rule"] == "CONFIDENTIAL_FILE_TO_EXTERNAL_EGRESS")
    assert r1b["violation"], "same run_id must still attribute"


def test_size_semantics_recorded_r23():
    import tempfile as _tf
    # config-provided size: exact semantics
    recs = scenario_full()
    cfg = RuleConfig(file_sizes={"/home/mengyan/Docs/image_123.jpg": 2300000})
    out = RuleEngine(cfg).run(recs)
    r1 = next(f for f in out["findings"]
              if f["rule"] == "CONFIDENTIAL_FILE_TO_EXTERNAL_EGRESS")
    fs = r1["details"]["file_size"]
    assert fs["size_source"] == "config_provided"
    assert fs["size_bytes"] == 2300000
    assert r1["details"]["volume_reconciliation"]["verdict"] == "MATCH"

    # unavailable size: never fabricated, reconciliation inconclusive
    cfg2 = RuleConfig()
    out2 = RuleEngine(cfg2).run(recs)
    r1b = next(f for f in out2["findings"]
               if f["rule"] == "CONFIDENTIAL_FILE_TO_EXTERNAL_EGRESS")
    fsb = r1b["details"]["file_size"]
    assert fsb["size_source"] == "unavailable"
    assert fsb["size_bytes"] is None
    assert r1b["details"]["volume_reconciliation"]["verdict"] == \
        "INSUFFICIENT_EVIDENCE"

    # post-event stat: real file, honest semantics labels
    with _tf.NamedTemporaryFile(suffix=".jpg", delete=False) as fh:
        fh.write(b"x" * 4096)
        path = fh.name
    try:
        recs3 = [
            kernel_event(4242, 1050, "file.open", "file", pstart=900.0,
                         entities=[{"role": "src", "kind": "file",
                                    "id": path, "classification": "confidential"}]),
            kernel_event(4242, 1060, "net.connect", "network", pstart=900.0,
                         verb="connect",
                         peer={"kind": "network_endpoint",
                               "id": "203.0.113.7:443", "sni": None}),
            kernel_event(4242, 1061, "net.egress", "network", pstart=900.0,
                         bytes_=4096, verb="send"),
            health_event(),
        ]
        cfg3 = RuleConfig(stat_missing_sizes=True)
        out3 = RuleEngine(cfg3).run(recs3)
        r1c = next(f for f in out3["findings"]
                   if f["rule"] == "CONFIDENTIAL_FILE_TO_EXTERNAL_EGRESS")
        fsc = r1c["details"]["file_size"]
        assert fsc["size_source"] == "post_event_stat"
        assert fsc["size_bytes"] == 4096
        assert fsc["size_observed_ts"] is not None
        assert "best_effort" in fsc["size_semantics"]
        assert r1c["details"]["volume_reconciliation"]["verdict"] == "MATCH"
    finally:
        import os as _os
        _os.unlink(path)


def test_window_recorded_in_finding_r24():
    recs = scenario_full()
    cfg = RuleConfig(file_sizes={"/home/mengyan/Docs/image_123.jpg": 2300000})
    out = RuleEngine(cfg).run(recs)
    r1 = next(f for f in out["findings"]
              if f["rule"] == "CONFIDENTIAL_FILE_TO_EXTERNAL_EGRESS")
    d = r1["details"]
    assert d["window_seconds"] == 600.0  # default
    assert d["window_start_epoch"] == 1050.0
    assert d["window_end_epoch"] == 1050.0 + 600.0

    # custom window is recorded so experiments stay reproducible
    cfg120 = RuleConfig(window_seconds=120.0,
                        file_sizes={"/home/mengyan/Docs/image_123.jpg": 2300000})
    out120 = RuleEngine(cfg120).run(recs)
    r1b = next(f for f in out120["findings"]
               if f["rule"] == "CONFIDENTIAL_FILE_TO_EXTERNAL_EGRESS")
    assert r1b["details"]["window_seconds"] == 120.0
    assert r1b["details"]["window_end_epoch"] == 1050.0 + 120.0


def test_endpoint_allowed_matching():
    al = ["10.0.0.0/8", "1.2.3.4", "5.6.7.8:443"]
    assert endpoint_allowed("10.1.2.3:443", al)
    assert endpoint_allowed("1.2.3.4:99", al)
    assert endpoint_allowed("5.6.7.8:443", al)
    assert not endpoint_allowed("5.6.7.8:80", al)
    assert not endpoint_allowed("203.0.113.7:443", al)


def test_sensor_health_absent_is_unknown():
    recs = [kernel_event(1, 1.0, "file.open", "file")]
    assert sensor_health(recs) == "UNKNOWN"


if __name__ == "__main__":
    test_graph_builds_nodes_and_edges()
    test_rule_engine_full_scenario()
    test_allowlist_exempts()
    test_degraded_sensor_makes_no_violation_inconclusive()
    test_no_claims_is_not_applicable()
    test_volume_without_size_is_insufficient_not_fake()
    test_unknown_lineage_alert_is_labeled()
    test_pid_reuse_refuses_attribution_r21()
    test_missing_pid_start_ts_refuses_attribution_r21()
    test_size_semantics_recorded_r23()
    test_window_recorded_in_finding_r24()
    test_endpoint_allowed_matching()
    test_sensor_health_absent_is_unknown()
    print("all step-5 part-A tests passed")
