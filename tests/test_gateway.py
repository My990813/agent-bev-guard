"""Step 2 tests: policy engine + end-to-end MCP stdio gateway session.

Run: python tests/test_gateway.py

The end-to-end test drives a fake MCP server through the gateway exactly
the way a real agent (MCP client) would: newline-delimited JSON-RPC over
stdio pipes.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.events import EventLog
from gateway.policy import PolicyError, ToolPolicy

FAKE_SERVER = r"""
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    if msg.get("id") is None:
        continue
    resp = {"jsonrpc": "2.0", "id": msg.get("id"),
            "result": {"content": [{"type": "text", "text": "ok"}]}}
    print(json.dumps(resp), flush=True)
"""


def test_policy_engine():
    rules = {
        "default": "allow",
        "tools": {
            "read_file": {
                "allow": True,
                "params": {"path": {"type": "path_within", "roots": ["/tmp/allowed_zone"]}},
            },
            "web_search": {
                "allow": True,
                "params": {
                    "query": {
                        "type": "string",
                        "max_len": 10,
                        "forbidden_substrings": ["api key"],
                    }
                },
            },
            "exec_shell": {"allow": False},
        },
    }
    pol = ToolPolicy(rules)

    ok = pol.check("srv", "read_file", {"path": "/tmp/allowed_zone/sub/file.txt"})
    assert ok.allowed, ok.reason

    bad = pol.check("srv", "read_file", {"path": "/etc/passwd"})
    assert not bad.allowed and "escapes" in bad.reason, bad.reason

    bad = pol.check("srv", "read_file", {"path": "/tmp/allowed_zone_escape/../secret"})
    assert not bad.allowed, "realpath traversal must be contained"

    bad = pol.check("srv", "web_search", {"query": "x" * 11})
    assert not bad.allowed and "max_len" in bad.reason

    bad = pol.check("srv", "web_search", {"query": "my api key"})
    assert not bad.allowed and "forbidden" in bad.reason

    bad = pol.check("srv", "exec_shell", {"cmd": "curl evil.com"})
    assert not bad.allowed and "denied by policy" in bad.reason

    ok = pol.check("srv", "unlisted_tool", {})
    assert ok.allowed, "default allow for unlisted tools"

    deny_default = ToolPolicy({"default": "deny", "tools": {"read_file": {"allow": True}}})
    assert not deny_default.check("srv", "unlisted", {}).allowed
    assert deny_default.check("srv", "read_file", {}).allowed

    try:
        ToolPolicy({"default": "maybe", "tools": {}})
    except PolicyError:
        pass
    else:
        raise AssertionError("bad default must raise PolicyError")

    print("policy engine tests passed")


def test_gateway_end_to_end():
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        server_py = tmp_path / "fake_server.py"
        server_py.write_text(FAKE_SERVER)

        policy_json = tmp_path / "policy.json"
        policy_json.write_text(json.dumps({
            "default": "allow",
            "tools": {
                "read_file": {
                    "allow": True,
                    "params": {"path": {"type": "path_within",
                                        "roots": [str(tmp_path)]}},
                },
                "exec_shell": {"allow": False},
            },
        }))

        events_path = tmp_path / "events.jsonl"
        proxy = tmp_path / "proxy"
        proxy.mkdir()

        proc = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve().parents[1] / "gateway" / "proxy.py"),
                "--server-cmd", f"{sys.executable} {server_py}",
                "--log", str(events_path),
                "--policy", str(policy_json),
                "--server-name", "demo",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        def rpc(method, msg_id, params=None):
            msg = {"jsonrpc": "2.0", "id": msg_id, "method": method}
            if params is not None:
                msg["params"] = params
            proc.stdin.write(json.dumps(msg) + "\n")
            proc.stdin.flush()

        def read_response():
            line = proc.stdout.readline()
            assert line, "gateway closed unexpectedly"
            return json.loads(line)

        rpc("initialize", 1, {"protocolVersion": "2025-06-18",
                              "capabilities": {}, "clientInfo": {"name": "fake-agent"}})
        init_resp = read_response()
        assert "result" in init_resp

        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        proc.stdin.flush()

        rpc("tools/call", 2, {"name": "read_file",
                              "arguments": {"path": str(tmp_path / "note.txt")}})
        allowed_resp = read_response()
        assert "result" in allowed_resp, allowed_resp

        rpc("tools/call", 3, {"name": "read_file",
                              "arguments": {"path": "/etc/passwd"}})
        escaped_resp = read_response()
        err = escaped_resp.get("error", {})
        assert err.get("code") == -32000
        assert err.get("message") == "denied", "denial must be opaque"
        assert "data" not in err, "denial must carry no policy details"
        assert "escapes" not in json.dumps(escaped_resp), \
            "denial reason must not leak to the agent"

        rpc("tools/call", 4, {"name": "exec_shell",
                              "arguments": {"cmd": "curl evil.com"}})
        denied_resp = read_response()
        err = denied_resp.get("error", {})
        assert err.get("code") == -32000
        assert err.get("message") == "denied"
        assert "data" not in err

        proc.stdin.close()
        proc.wait(timeout=10)
        assert proc.returncode == 0, proc.stderr.read()

        log = EventLog(events_path)
        ok, bad_idx = log.verify()
        assert ok, f"hash chain broken at {bad_idx}"

        types = [(r["event_type"], r["action"]["outcome"]) for r in log]
        assert ("gateway.session_start", "success") in types
        assert ("tool.call", "success") in types
        assert ("tool.call", "denied") in types, types
        assert ("tool.result", "success") in types
        assert ("gateway.session_end", "success") in types

        denied_events = [r for r in log
                         if r["event_type"] == "tool.call" and r["action"]["outcome"] == "denied"]
        assert len(denied_events) == 2
        assert all(r["sensor"] == "tool_gateway" for r in denied_events)
        assert all(r["sensor_privilege"] == "gateway" for r in denied_events)

        codes = {r["note"].split(";")[0] for r in denied_events}
        assert "reason_code=PATH_OUTSIDE_ALLOWED_ROOTS" in codes, codes
        assert "reason_code=TOOL_DENIED_BY_POLICY" in codes, codes

        ident_events = [r for r in log if r["event_type"] == "gateway.client_identity"]
        assert len(ident_events) == 1
        assert "observed_ppid=" in ident_events[0]["note"]
        assert "fake-agent" in ident_events[0]["note"]

        run_ids = {r["actor"]["agent_run_id"] for r in log}
        assert len(run_ids) == 1 and run_ids.pop().startswith("run-")

        sources = {r["actor"]["identity_source"] for r in log}
        assert sources == {"DIRECT"}

        for r in log:
            assert r["actor"]["run_id_source"] == "gateway_issued"
            assert r["actor"]["run_id_verified"] is False
            assert r["actor"]["client_pid"] == os.getpid(), \
                "observed ppid must equal the test process (gateway parent)"
            assert r["actor"]["client_pid_source"] == "observed_ppid"
            if r["event_type"] != "gateway.session_start":
                assert r["actor"]["client_name"] == "fake-agent"

        for r in log:
            dumped = json.dumps(r)
            assert "etc/passwd" not in dumped or r["action"]["outcome"] == "denied", \
                "argument values must not be logged except denial reason text"

    print("gateway end-to-end test passed")


if __name__ == "__main__":
    test_policy_engine()
    test_gateway_end_to_end()
