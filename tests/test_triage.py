"""Step 6 tests: baseline, anomaly scoring, triage integration.

Scope semantics under test (threat-model section 12):
- behavior is "inconsistent_with_baseline", never "malicious"
- legal_status is NOT_DETERMINED on every item, always
- policy_status UNKNOWN when no known rule fires (never "compliant")
- constant-baseline deviations carry robust_z=None + note (no invented score)
- unattributed events are surfaced, never silently dropped
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.anomaly import (  # noqa: E402
    TriageConfig,
    render_triage_text,
    score_run,
    triage_runs,
    write_triage_reports,
)
from core.baseline import (  # noqa: E402
    Baseline,
    RunFeatures,
    extract_run_features,
    tool_bigrams,
)
from core.rules import RuleConfig  # noqa: E402

T0 = 1758850000.0
KNOWN_EP = "93.184.216.34:443"
EVIL_EP = "203.0.113.7:443"


def _iso(epoch: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def ev(event_type, sensor, ts, pid=500, run_id=None, idsrc="INFERRED",
       bytes_=0, entities=None, peer=None, verb="read", start_ts=100.0):
    return {
        "event_id": f"ev-{event_type}-{pid}-{int(ts)}",
        "ts_wall": _iso(ts),
        "ts_mono": float(ts),
        "sensor": sensor,
        "sensor_privilege": {"process": "kernel", "file": "kernel",
                             "network": "kernel", "tool_gateway": "gateway",
                             "agent_self": "untrusted"}[sensor],
        "event_type": event_type,
        "actor": {
            "pid": pid, "pid_start_ts": start_ts, "user": None,
            "agent_run_id": run_id, "session_id": None,
            "identity_source": idsrc, "identity_confidence": None,
        },
        "entities": entities or [],
        "action": {"verb": verb, "bytes": bytes_, "outcome": "success"},
        "peer": peer,
        "note": None,
    }


def normal_run_events(run_id, base_ts, pid=500):
    """A within-baseline run: known endpoint, small egress, normal tools."""
    return [
        ev("tool.call", "tool_gateway", base_ts, pid, run_id,
           idsrc="DIRECT", verb="web_search"),
        ev("tool.call", "tool_gateway", base_ts + 5, pid, run_id,
           idsrc="DIRECT", verb="read_file"),
        ev("net.connect", "network", base_ts + 10, pid, run_id,
           peer={"kind": "network_endpoint", "id": KNOWN_EP}),
        ev("net.egress", "network", base_ts + 11, pid, run_id, bytes_=400000),
    ]


def anomalous_run_events(run_id, base_ts, pid=700):
    """The motivating scenario: confidential read -> novel endpoint ->
    8.2MB egress -> agent claims no upload."""
    return [
        ev("tool.call", "tool_gateway", base_ts, pid, run_id,
           idsrc="DIRECT", verb="web_search"),
        ev("tool.call", "tool_gateway", base_ts + 5, pid, run_id,
           idsrc="DIRECT", verb="upload_file"),
        ev("file.open", "file", base_ts + 20, pid, run_id,
           entities=[{"role": "dst", "kind": "file",
                      "id": "/home/u/Docs/image_123.jpg",
                      "classification": "confidential"}]),
        ev("net.connect", "network", base_ts + 30, pid, run_id,
           peer={"kind": "network_endpoint", "id": EVIL_EP}),
        ev("net.egress", "network", base_ts + 31, pid, run_id,
           bytes_=8388608, start_ts=100.0),
        {
            "event_id": f"ev-claim-{run_id}", "ts_wall": _iso(base_ts + 40),
            "ts_mono": float(base_ts + 40), "sensor": "agent_self",
            "sensor_privilege": "untrusted", "event_type": "agent.claim",
            "actor": {"pid": pid, "pid_start_ts": 100.0, "user": None,
                      "agent_run_id": run_id, "session_id": None,
                      "identity_source": "INFERRED",
                      "identity_confidence": None},
            "entities": [{"role": "dst", "kind": "object",
                          "id": "claim:no_upload", "classification": None}],
            "action": {"verb": "claim", "bytes": 0, "outcome": "success"},
            "peer": None, "note": None,
        },
    ]


def test_feature_extraction_counts_and_order():
    recs = normal_run_events("run-a", T0)
    recs += [
        ev("process.exec", "process", T0 + 2, 501, "run-a",
           entities=[{"role": "dst", "kind": "process",
                      "id": "/usr/bin/python3", "classification": None}]),
        ev("net.egress", "network", T0 + 12, 500, "run-a", bytes_=2500),
    ]
    # tool.call emitted out of chronological order: sorting must fix order
    recs[0], recs[1] = recs[1], recs[0]
    # one unattributed event must be counted, not dropped
    recs.append(ev("file.open", "file", T0 + 50, 999, None,
                   entities=[{"role": "dst", "kind": "file", "id": "/x",
                              "classification": "public"}]))

    feats, unattributed = extract_run_features(recs)
    assert unattributed == 1
    f = feats["run-a"]
    assert f.tool_calls == 2
    assert f.process_spawns == 1
    assert f.outbound_bytes == 402500
    assert f.external_endpoints == {KNOWN_EP}
    assert f.confidential_opens == 0
    assert f.tool_sequence == ["web_search", "read_file"]  # ts order, not file order


def test_baseline_robust_stats():
    runs = []
    vals = [3, 3, 4, 4, 4, 5, 5, 100]  # median 4, one outlier
    for i, v in enumerate(vals):
        runs.append(RunFeatures(run_id=f"r{i}", tool_calls=v))
    base = Baseline.build(runs)
    assert base.median["tool_calls"] == 4.0
    # MAD over |x-4| = [1,1,0,0,0,1,1,96] -> median 1
    assert base.mad["tool_calls"] == 1.0
    # constant features detected: process_spawns all 0
    assert "process_spawns" in base.constant_features
    assert "tool_calls" not in base.constant_features


def test_score_run_flags_anomalous_run():
    # baseline with realistic variance in outbound_bytes (380k..420k)
    sizes = [380000, 390000, 400000, 410000, 420000] * 4
    baseline_runs = [RunFeatures(run_id=f"r{i}", tool_calls=2,
                                 outbound_bytes=sizes[i],
                                 external_endpoints={KNOWN_EP},
                                 tool_sequence=["web_search", "read_file"])
                     for i in range(20)]
    base = Baseline.build(baseline_runs)
    cfg = TriageConfig()

    target = RunFeatures(
        run_id="run-evil", tool_calls=2, outbound_bytes=8388608,
        confidential_opens=1, external_endpoints={EVIL_EP},
        tool_sequence=["web_search", "upload_file"],
    )
    flags = score_run(target, base, cfg)
    kinds = {f["kind"] for f in flags}
    assert kinds == {"numeric_deviation", "novel_endpoint",
                     "novel_tool_bigram"}
    vol = next(f for f in flags
               if f["kind"] == "numeric_deviation"
               and f["feature"] == "outbound_bytes")
    assert vol["robust_z"] is not None and vol["robust_z"] > cfg.z_threshold
    conf = next(f for f in flags
                if f["kind"] == "numeric_deviation"
                and f["feature"] == "confidential_opens")
    # confidential_opens is constant (0) in baseline -> robust_z is None,
    # deviation still flagged with an explicit note (no invented score)
    assert conf["robust_z"] is None and "zero variance" in conf["note"]

    normal = RunFeatures(run_id="run-ok", tool_calls=2,
                         outbound_bytes=400000,
                         external_endpoints={KNOWN_EP},
                         tool_sequence=["web_search", "read_file"])
    assert score_run(normal, base, cfg) == []


def test_triage_runs_end_to_end():
    baseline_records = []
    for i in range(20):
        baseline_records += normal_run_events(f"base-{i}", T0 + i * 100)
    baseline_runs = list(extract_run_features(baseline_records)[0].values())

    target_records = (
        normal_run_events("run-clean1", T0 + 10000)
        + normal_run_events("run-clean2", T0 + 11000)
        + anomalous_run_events("run-evil", T0 + 12000)
    )
    rule_cfg = RuleConfig(allowlist=[KNOWN_EP])  # EVIL_EP stays non-allowed
    result = triage_runs(target_records, baseline_runs,
                         TriageConfig(), rule_cfg)

    s = result["stats"]
    assert s["runs_scanned"] == 3
    assert s["runs_flagged"] == 1 and s["runs_high"] == 1
    assert s["unattributed_events"] == 0

    top = result["items"][0]
    assert top["run_id"] == "run-evil"
    assert top["anomaly_level"] == "HIGH"
    assert top["behavior"] == "inconsistent_with_baseline"
    # the locked semantics: never malicious, never a legality claim
    assert top["legal_status"] == "NOT_DETERMINED"
    # Step 5 rules fired on the same events -> concrete policy status
    assert top["policy_status"].startswith("VIOLATION_FOUND")

    clean = [it for it in result["items"] if it["run_id"] == "run-clean1"][0]
    assert clean["anomaly_level"] == "LOW"
    assert clean["behavior"] == "within_baseline"
    # no known rule fired -> UNKNOWN, never "compliant"
    assert clean["policy_status"] == "UNKNOWN"
    assert clean["legal_status"] == "NOT_DETERMINED"


def test_triage_text_report_semantics():
    baseline_runs = [RunFeatures(run_id=f"r{i}", tool_calls=2,
                                 outbound_bytes=400000,
                                 external_endpoints={KNOWN_EP},
                                 tool_sequence=["web_search", "read_file"])
                     for i in range(20)]
    target_records = anomalous_run_events("run-evil", T0 + 12000)
    result = triage_runs(target_records, baseline_runs,
                         TriageConfig(), RuleConfig())
    text = render_triage_text(result)
    assert "does not determine intent, legality, or culpability" in text
    assert "Scanned 1 runs -> 1 flagged" in text
    assert "Legal status: NOT_DETERMINED" in text
    assert "Provenance: INFERRED" in text
    assert "heuristic ranking aid" in text


def test_triage_reports_written():
    baseline_runs = [RunFeatures(run_id=f"r{i}", tool_calls=2)
                     for i in range(10)]
    target_records = normal_run_events("run-x", T0)
    result = triage_runs(target_records, baseline_runs,
                         TriageConfig(), RuleConfig())
    with tempfile.TemporaryDirectory() as tmp:
        paths = write_triage_reports(result, Path(tmp))
        txt = Path(paths["text"]).read_text(encoding="utf-8")
        jsn = Path(paths["json"]).read_text(encoding="utf-8")
        assert "AGENT BEHAVIORAL TRIAGE REPORT" in txt
        assert '"legal_status": "NOT_DETERMINED"' in jsn


def test_tool_bigrams():
    assert tool_bigrams(["a", "b", "c"]) == {("a", "b"), ("b", "c")}
    assert tool_bigrams(["a"]) == set()


if __name__ == "__main__":
    test_feature_extraction_counts_and_order()
    test_baseline_robust_stats()
    test_score_run_flags_anomalous_run()
    test_triage_runs_end_to_end()
    test_triage_text_report_semantics()
    test_triage_reports_written()
    test_tool_bigrams()
    print("all step-6 triage tests passed")
