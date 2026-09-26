"""MCP stdio tool-call gateway (Step 2).

Deployment:

    Agent (MCP client) <-> THIS GATEWAY <-> real MCP server (stdio)

The gateway is a transparent stdio proxy that:

1. Intercepts every JSON-RPC "tools/call" request from the agent.
2. Checks it against a ToolPolicy BEFORE forwarding.
   - Denied calls never reach the server; the agent receives an OPAQUE
     denial ({"code": -32000, "message": "denied"}) with no reason and
     no policy details, so a probed agent cannot map the policy surface.
     The full reason (reason_code + detail) goes to the audit log only.
3. Records every call (allowed AND denied) plus every result into the
   append-only hash-chained EventLog (sensor="tool_gateway",
   sensor_privilege="gateway").
4. Client identity correlation (R6): over stdio the gateway is spawned BY
   the agent, so os.getppid() is a system-observed client pid -- not a
   self-report. Additionally, the initialize request's clientInfo and an
   optional params._meta.client_pid are captured and cross-checked; a
   mismatch between declared and observed pid is itself recorded as a
   forensic signal.
5. run_id semantics (R7): the run_id is gateway-issued and UNVERIFIED.
   Every event carries run_id_source="gateway_issued" and
   run_id_verified=false. run_id is a correlation handle, never an
   authentication claim.

Privacy: only metadata is logged -- tool name, outcome, response size,
denial reason. Argument values and response payloads are never written.

Usage:
    python gateway/proxy.py \
        --server-cmd "python fake_mcp_server.py" \
        --log events.jsonl \
        --policy examples/gateway_policy.json \
        --server-name demo

JSON-RPC framing: MCP stdio transport = one JSON message per line.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import shlex
import subprocess
import sys
import threading
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.events import Action, Actor, Entity, Event, EventLog
from gateway.policy import ToolPolicy

JSONRPC_DENIED_CODE = -32000


class Gateway:
    def __init__(
        self,
        server_cmd: str,
        log_path: str | Path,
        policy: ToolPolicy,
        server_name: str = "mcp-server",
        run_id: str | None = None,
    ):
        self.server_cmd = server_cmd
        self.log_path = Path(log_path)
        self.policy = policy
        self.server_name = server_name
        self.run_id = run_id or f"run-{uuid.uuid4().hex[:12]}"
        self.log = EventLog(self.log_path)
        self.pending: dict = {}
        self.lock = threading.Lock()
        self.client_pid: int | None = os.getppid()
        self.client_pid_source = "observed_ppid"
        self.client_name: str | None = None
        self.client_declared_pid: int | None = None

    def _emit(
        self,
        event_type: str,
        verb: str,
        outcome: str = "success",
        bytes_: int = 0,
        entities: list[Entity] | None = None,
        note: str | None = None,
    ) -> None:
        ev = Event(
            sensor="tool_gateway",
            event_type=event_type,
            actor=Actor(
                pid=os.getpid(),
                user=getpass.getuser() or None,
                agent_run_id=self.run_id,
                identity_source="DIRECT",
                run_id_source="gateway_issued",
                run_id_verified=False,
                client_pid=self.client_pid,
                client_pid_source=self.client_pid_source,
                client_name=self.client_name,
            ),
            action=Action(verb=verb, bytes=bytes_, outcome=outcome),
            entities=entities or [],
            note=note,
        )
        self.log.append(ev)

    def _tool_entity(self, tool: str) -> Entity:
        return Entity(role="dst", kind="tool", id=f"{self.server_name}.{tool}")

    def start_server(self) -> subprocess.Popen:
        return subprocess.Popen(
            shlex.split(self.server_cmd),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            bufsize=1,
        )

    def pump_server_to_client(self, proc: subprocess.Popen) -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            try:
                msg = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            with self.lock:
                call = self.pending.pop(msg.get("id"), None)
            if call is not None:
                is_error = isinstance(msg.get("error"), dict)
                self._emit(
                    "tool.result",
                    verb=call,
                    outcome="failure" if is_error else "success",
                    bytes_=len(line.encode("utf-8")),
                    entities=[self._tool_entity(call)],
                    note="server error response" if is_error else None,
                )

    def run(self) -> int:
        proc = self.start_server()
        self._emit(
            "gateway.session_start",
            verb="session_start",
            note=(
                f"server={self.server_name} run_id={self.run_id} "
                f"client_pid={self.client_pid} (observed_ppid)"
            ),
        )
        pump = threading.Thread(
            target=self.pump_server_to_client, args=(proc,), daemon=True
        )
        pump.start()

        try:
            for line in sys.stdin:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    msg = json.loads(stripped)
                except (json.JSONDecodeError, ValueError):
                    self._forward(proc, stripped)
                    continue

                if isinstance(msg, dict) and msg.get("method") == "tools/call":
                    self._handle_call(proc, msg)
                elif isinstance(msg, dict) and msg.get("method") == "initialize":
                    self._handle_initialize(proc, msg)
                else:
                    self._forward(proc, stripped)
        finally:
            self._emit(
                "gateway.session_end",
                verb="session_end",
                note=f"run_id={self.run_id}",
            )
            try:
                if proc.stdin is not None:
                    proc.stdin.close()
                proc.wait(timeout=3)
            except Exception:
                proc.terminate()
        return 0

    def _forward(self, proc: subprocess.Popen, line: str) -> None:
        try:
            if proc.stdin is not None:
                proc.stdin.write(line + "\n")
                proc.stdin.flush()
        except (BrokenPipeError, ValueError):
            sys.exit(1)

    def _handle_initialize(self, proc: subprocess.Popen, msg: dict) -> None:
        params = msg.get("params") or {}
        info = params.get("clientInfo") or {}
        if isinstance(info.get("name"), str):
            self.client_name = info["name"]
        declared = (params.get("_meta") or {}).get("client_pid")
        if isinstance(declared, int) and declared > 0:
            self.client_declared_pid = declared

        parts = [
            f"client_name={self.client_name!r}",
            f"observed_ppid={self.client_pid}",
        ]
        if self.client_declared_pid is not None:
            parts.append(f"declared_pid={self.client_declared_pid}")
            if self.client_declared_pid != self.client_pid:
                parts.append(
                    "MISMATCH: declared pid does not match observed ppid"
                )
        self._emit(
            "gateway.client_identity",
            verb="client_identity",
            note="; ".join(parts),
        )
        self._forward(proc, json.dumps(msg, separators=(",", ":")))

    def _handle_call(self, proc: subprocess.Popen, msg: dict) -> None:
        params = msg.get("params") or {}
        tool = params.get("name") or "unknown"
        arguments = params.get("arguments") or {}
        req_id = msg.get("id")

        verdict = self.policy.check(self.server_name, tool, arguments)
        if not verdict.allowed:
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": JSONRPC_DENIED_CODE,
                    "message": "denied",
                },
            }
            sys.stdout.write(json.dumps(resp, separators=(",", ":")) + "\n")
            sys.stdout.flush()
            self._emit(
                "tool.call",
                verb=tool,
                outcome="denied",
                entities=[self._tool_entity(tool)],
                note=(
                    f"reason_code={verdict.reason_code}; "
                    f"detail={verdict.reason}"
                ),
            )
            return

        with self.lock:
            self.pending[req_id] = tool
        self._emit(
            "tool.call",
            verb=tool,
            entities=[self._tool_entity(tool)],
            note="forwarded to server",
        )
        self._forward(proc, json.dumps(msg, separators=(",", ":")))


def main() -> int:
    ap = argparse.ArgumentParser(description="MCP stdio tool-call gateway")
    ap.add_argument("--server-cmd", required=True,
                    help="command line of the real MCP server (stdio)")
    ap.add_argument("--log", required=True, help="path to events.jsonl")
    ap.add_argument("--policy", help="path to policy JSON (default: allow all)")
    ap.add_argument("--server-name", default="mcp-server")
    ap.add_argument("--run-id", default=None,
                    help="reuse an existing agent_run_id if known")
    args = ap.parse_args()

    policy = ToolPolicy.load(args.policy) if args.policy else ToolPolicy()
    gw = Gateway(
        server_cmd=args.server_cmd,
        log_path=args.log,
        policy=policy,
        server_name=args.server_name,
        run_id=args.run_id,
    )
    return gw.run()


if __name__ == "__main__":
    sys.exit(main())
