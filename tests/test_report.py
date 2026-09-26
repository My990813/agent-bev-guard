"""Step 5 part-B tests: incident aggregation + report rendering + CLI.

Run: python tests/test_report.py
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_rules import scenario_full  # noqa: E402

from core.graph import build_graph  # noqa: E402
from core.report import (  # noqa: E402
    aggregate_incidents, build_report, render_graph_text, render_report_text,
)
from core.rules import RuleConfig, RuleEngine  # noqa: E402

PY = sys.executable or "python3"
CFG = RuleConfig(
    allowlist=["10.0.0.0/8", "151.101.0.0/16"],
    file_sizes={"/home/mengyan/Docs/image_123.jpg": 2300000},
)


def test_three_findings_group_into_one_incident():
    recs = scenario_full()
    out = RuleEngine(CFG).run(recs)
    assert len(out["alerts"]) == 3  # engine emits 3 raw findings (R22)
    grouped = aggregate_incidents(out["findings"])
    incs = grouped["incidents"]
    assert len(incs) == 1, "shared evidence must group all three findings"
    assert incs[0]["finding_count"] == 3
    assert set(incs[0]["rules_fired"]) == {
        "CONFIDENTIAL_FILE_TO_EXTERNAL_EGRESS",
        "AGENT_CLAIM_CONTRADICTED",
        "EGRESS_TO_NON_ALLOWLIST",
    }
    # non-violations preserved separately (coverage findings)
    assert grouped["non_violations"] == []


def test_unrelated_findings_stay_separate_incidents():
    from test_rules import kernel_event, health_event
    recs = [
        # incident A: file + egress on pid 4242
        kernel_event(4242, 1050, "file.open", "file", run_id="run-a",
                     idsrc="INFERRED", conf=0.90,
                     entities=[{"role": "src", "kind": "file",
                                "id": "/home/a/secret.txt",
                                "classification": "secret"}]),
        kernel_event(4242, 1051, "net.connect", "network", run_id="run-a",
                     idsrc="INFERRED", conf=0.90, verb="connect",
                     peer={"kind": "network_endpoint",
                           "id": "198.51.100.9:443", "sni": None}),
        kernel_event(4242, 1052, "net.egress", "network", run_id="run-a",
                     idsrc="INFERRED", conf=0.90, bytes_=1000, verb="send"),
        # incident B: unrelated connect from a different pid
        kernel_event(5151, 1060, "net.connect", "network", run_id="run-b",
                     idsrc="INFERRED", conf=0.90, verb="connect",
                     peer={"kind": "network_endpoint",
                           "id": "198.51.100.10:443", "sni": None}),
        kernel_event(5151, 1061, "net.egress", "network", run_id="run-b",
                     idsrc="INFERRED", conf=0.90, bytes_=2000, verb="send"),
        health_event(),
    ]
    out = RuleEngine(RuleConfig()).run(recs)
    grouped = aggregate_incidents(out["findings"])
    assert len(grouped["incidents"]) == 2
    counts = sorted(i["finding_count"] for i in grouped["incidents"])
    assert counts == [1, 2]


def test_render_report_text_structure():
    report = build_report(scenario_full(), CFG, log_path="demo.jsonl")
    text = render_report_text(report)
    # locked structured-conclusion format
    for key in ("Rule:", "Violation:", "Lineage:", "Confidence:",
                "Sensor:", "Evidence:", "Conclusion:"):
        assert key in text, f"missing {key} in report text"
    assert "ALERT_WITH_INFERRED_LINEAGE" in text
    assert "heuristic evidence score, NOT probability" in text
    assert "203.0.113.7:443" in text
    assert "2.2 MB" in text  # 2300000 bytes humanized
    assert "window: 600s" in text
    assert "config_provided" in text
    assert "INCIDENT INC-001" in text
    assert "RULE COVERAGE" in text


def test_render_graph_text():
    g = build_graph(scenario_full())
    text = render_graph_text(g)
    assert "--read-->" in text
    assert "--send-->" in text and "--connect-->" in text
    assert "203.0.113.7:443" in text
    assert "[confidential]" in text
    assert "kernel" in text and "untrusted" in text


def test_cli_end_to_end_and_tamper_detection():
    from examples.make_demo_log import write_demo_log
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        log_path = tmp / "events.jsonl"
        n = write_demo_log(log_path)
        assert n == 7

        outdir = tmp / "report_out"
        r = subprocess.run(
            [PY, str(ROOT / "report_cli.py"), "--log", str(log_path),
             "--config", str(ROOT / "examples" / "rules_config.json"),
             "--out", str(outdir)],
            capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        report = json.loads((outdir / "report.json").read_text())
        assert report["chain_ok"] is True
        assert report["event_count"] == 7
        assert report["violation_count"] == 3
        assert report["incident_count"] == 1
        assert report["incidents"][0]["finding_count"] == 3
        assert (outdir / "report.txt").exists()
        assert (outdir / "graph.txt").exists()
        # stdout summary
        assert "1 incident(s)" in r.stdout

        # tamper with one record -> chain broken -> CLI must refuse
        lines = log_path.read_text().splitlines()
        rec = json.loads(lines[2])
        rec["action"]["bytes"] = 999999999  # falsify the egress volume
        lines[2] = json.dumps(rec, sort_keys=True,
                              separators=(",", ":"), ensure_ascii=False)
        log_path.write_text("\n".join(lines) + "\n")
        r2 = subprocess.run(
            [PY, str(ROOT / "report_cli.py"), "--log", str(log_path),
             "--out", str(tmp / "report2")],
            capture_output=True, text=True)
        assert r2.returncode == 3, "tampered log must abort the report"
        assert "BROKEN" in r2.stderr


if __name__ == "__main__":
    test_three_findings_group_into_one_incident()
    test_unrelated_findings_stay_separate_incidents()
    test_render_report_text_structure()
    test_render_graph_text()
    test_cli_end_to_end_and_tamper_detection()
    print("all step-5 part-B tests passed")
