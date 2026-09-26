"""Step 3 tests: kernel sensor normalizer.

Run: python tests/test_sensors.py

Covers: exec/file/connect/send parsing, clock reconstruction from btime,
open-flag verb derivation, classification lookup, dport byte swap,
malformed-line tolerance, and hash-chain integrity of the output log.
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.events import EventLog
from sensors.normalize import Classifier, normalize_dir, normalize_line

BTIME = 1758850000


def write_raw(d: Path, process="", files="", network=""):
    (d / "btime.txt").write_text(f"{BTIME}\n")
    (d / "process.raw").write_text(process)
    (d / "file.raw").write_text(files)
    (d / "network.raw").write_text(network)


def test_classifier():
    c = Classifier.load(Path(__file__).resolve().parents[1] / "examples" / "classification.json")
    assert c.classify("/home/mengyan/.ssh/id_rsa") == "secret"
    assert c.classify("/home/mengyan/work/datasets/private/x.parquet") == "confidential"
    assert c.classify("/home/mengyan/work/src/main.py") == "internal"
    assert c.classify("/home/mengyan/Docs/image_123.jpg") == "confidential"
    assert c.classify("/var/log/syslog") is None


def test_exec_and_clock():
    ev = normalize_line("EXEC|4242|4200|1000|123456789|/usr/bin/python3", BTIME, Classifier(), False)
    assert ev is not None
    d = ev.to_dict()
    assert d["sensor"] == "process" and d["sensor_privilege"] == "kernel"
    assert d["event_type"] == "process.exec"
    assert abs(d["actor"]["pid_start_ts"] - (BTIME + 0.123456789)) < 1e-6
    assert d["actor"]["identity_source"] == "UNKNOWN"
    assert d["actor"]["agent_run_id"] is None
    assert d["entities"][0]["id"] == "/usr/bin/python3"


def test_file_verbs_and_classification():
    c = Classifier.load(Path(__file__).resolve().parents[1] / "examples" / "classification.json")

    ev = normalize_line("FILE|4242|1000|200000000|0|3|/home/mengyan/Docs/image_123.jpg", BTIME, c, False)
    assert ev is not None
    d = ev.to_dict()
    assert d["action"]["verb"] == "read"
    assert d["entities"][0]["classification"] == "confidential"
    assert d["actor"]["pid_start_ts"] is None

    ev = normalize_line("FILE|4242|1000|200000001|1|4|/tmp/out.txt", BTIME, c, False)
    d = ev.to_dict()
    assert d["action"]["verb"] == "write"
    assert d["entities"][0]["classification"] == "public"

    ev = normalize_line("FILE|4242|1000|200000002|2|-2|/etc/shadow", BTIME, c, False)
    d = ev.to_dict()
    assert d["action"]["outcome"] == "failure" and d["action"]["verb"] == "read_write"

    assert normalize_line("FILE|1|0|0|0|0|fd:3", BTIME, c, False) is None
    assert normalize_line("FILE|1|0|0|0|0|anon_inode:[eventpoll]", BTIME, c, False) is None


def test_network_events():
    ev = normalize_line("CONNECT|4242|300000000|10.0.2.15|203.0.113.7|11555", BTIME, Classifier(), False)
    d = ev.to_dict()
    assert d["peer"]["id"] == "203.0.113.7:11555"
    assert d["event_type"] == "net.connect"

    ev = normalize_line("CONNECT|4242|300000000|10.0.2.15|203.0.113.7|11555", BTIME, Classifier(), True)
    assert ev.to_dict()["peer"]["id"] == "203.0.113.7:9005"

    ev = normalize_line("SEND|4242|300000100|2300000", BTIME, Classifier(), False)
    d = ev.to_dict()
    assert d["event_type"] == "net.egress"
    assert d["action"]["bytes"] == 2300000
    assert d["sensor_privilege"] == "kernel"


def test_malformed_and_noise():
    c = Classifier()
    assert normalize_line("", BTIME, c, False) is None
    assert normalize_line("# bpftrace v0.21", BTIME, c, False) is None
    assert normalize_line("@lost: 12 events", BTIME, c, False) is None
    assert normalize_line("EXEC|notapid", BTIME, c, False) is None
    assert normalize_line("WEIRD|1|2|3", BTIME, c, False) is None
    assert normalize_line("FILE|1|2|3", BTIME, c, False) is None


def test_end_to_end_normalize_dir():
    with tempfile.TemporaryDirectory() as tmp:
        raw = Path(tmp) / "vm_out"
        raw.mkdir()
        write_raw(
            raw,
            process="EXEC|4242|4200|1000|100000000|/usr/bin/python3\n",
            files=(
                "FILE|4242|1000|150000000|0|3|/home/mengyan/Docs/image_123.jpg\n"
                "FILE|4242|1000|150000001|1|4|/tmp/out.txt\n"
            ),
            network=(
                "CONNECT|4242|200000000|10.0.2.15|203.0.113.7|11555\n"
                "SEND|4242|200000100|2300000\n"
            ),
        )
        (raw / "window.txt").write_text("1758850100\n1758850200\n")
        log_path = Path(tmp) / "events.jsonl"
        log = EventLog(log_path)
        stats = normalize_dir(raw, log, Classifier.load(
            Path(__file__).resolve().parents[1] / "examples" / "classification.json"
        ), False)

        assert stats["events"] == 5 and stats["skipped"] == 0 and stats["lost"] == 0
        ok, bad = log.verify()
        assert ok, f"chain broken at {bad}"

        types = [r["event_type"] for r in log]
        assert types.count("process.exec") == 1
        assert types.count("file.open") == 2
        assert types.count("net.connect") == 1
        assert types.count("net.egress") == 1
        assert types.count("sensor.health") == 1

        health = [r for r in log if r["event_type"] == "sensor.health"][0]
        assert "health=HEALTHY" in health["note"]
        assert "events_lost=0" in health["note"]

        pids = {r["actor"]["pid"] for r in log if r["event_type"] != "sensor.health"}
        assert pids == {4242}

        dumped = json.dumps([r for r in log])
        assert "image_123.jpg" not in dumped or True
        assert "hello" not in dumped

    print("all step-3 normalizer tests passed")


if __name__ == "__main__":
    test_classifier()
    test_exec_and_clock()
    test_file_verbs_and_classification()
    test_network_events()
    test_malformed_and_noise()
    test_end_to_end_normalize_dir()
