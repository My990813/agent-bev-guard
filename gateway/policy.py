"""Tool-call policy engine for the MCP gateway.

A policy decides ALLOW / DENY for each (server, tool, arguments) triple
BEFORE the call is forwarded to the real MCP server. Denied calls never
reach the server; they are answered with a JSON-RPC error and logged
with outcome="denied".

Policy file format (JSON):
{
  "default": "allow" | "deny",          # verdict for tools not listed
  "tools": {
    "read_file": {
      "allow": true,
      "params": {
        "path": {"type": "path_within", "roots": ["/Users/x/work"]}
      }
    },
    "web_search": {
      "allow": true,
      "params": {
        "query": {"type": "string", "max_len": 2000,
                  "forbidden_substrings": ["api key"]}
      }
    },
    "exec_shell": {"allow": false}
  }
}

Design notes:
- The policy sees argument VALUES at check time but never copies them
  into the audit log (core privacy principle: metadata only).
- path_within resolves symlinks via realpath before containment checks.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Verdict:
    allowed: bool
    reason: str
    reason_code: str = "OK"


REASON_CODES = {
    "OK": "allowed",
    "TOOL_NOT_IN_ALLOWLIST": "tool not listed and default is deny",
    "TOOL_DENIED_BY_POLICY": "tool explicitly denied by policy",
    "PATH_OUTSIDE_ALLOWED_ROOTS": "resolved path escapes all allowed roots",
    "PARAM_TOO_LONG": "string param exceeds max_len",
    "PARAM_FORBIDDEN_SUBSTRING": "string param contains forbidden substring",
    "PARAM_TYPE_MISMATCH": "param value has wrong type",
    "UNKNOWN_PARAM_RULE": "policy references an unknown param rule type",
}


class PolicyError(ValueError):
    pass


def _check_param_value(value, rule: dict) -> str | None:
    """Return None if the value passes, else a human-readable reason."""
    rtype = rule.get("type")
    if rtype == "path_within":
        if not isinstance(value, str):
            return "PARAM_TYPE_MISMATCH", "path param must be a string"
        real = os.path.realpath(value)
        for root in rule.get("roots", []):
            rroot = os.path.realpath(root)
            if real == rroot or real.startswith(rroot + os.sep):
                return None, None
        return "PATH_OUTSIDE_ALLOWED_ROOTS", f"path escapes allowed roots: {value}"
    if rtype == "string":
        if not isinstance(value, str):
            return "PARAM_TYPE_MISMATCH", "param must be a string"
        max_len = rule.get("max_len")
        if max_len is not None and len(value) > max_len:
            return "PARAM_TOO_LONG", f"param exceeds max_len={max_len}"
        for sub in rule.get("forbidden_substrings", []):
            if sub in value:
                return "PARAM_FORBIDDEN_SUBSTRING", "param contains forbidden substring"
        return None, None
    if rtype is None:
        return None, None
    return "UNKNOWN_PARAM_RULE", f"unknown param rule type: {rtype}"


class ToolPolicy:
    def __init__(self, rules: dict | None = None):
        if rules is None:
            rules = {"default": "allow", "tools": {}}
        if rules.get("default") not in ("allow", "deny"):
            raise PolicyError('default must be "allow" or "deny"')
        self.rules = rules

    @classmethod
    def load(cls, path: str | Path) -> "ToolPolicy":
        with Path(path).open("r", encoding="utf-8") as fh:
            return cls(json.load(fh))

    def check(self, server: str, tool: str, arguments: dict | None) -> Verdict:
        tool_rules = self.rules.get("tools", {}).get(tool)
        if tool_rules is None:
            if self.rules.get("default") == "deny":
                return Verdict(
                    False,
                    f"tool '{tool}' not in allowlist (default deny)",
                    "TOOL_NOT_IN_ALLOWLIST",
                )
            return Verdict(True, "default allow", "OK")

        if tool_rules.get("allow") is False:
            return Verdict(
                False, f"tool '{tool}' denied by policy", "TOOL_DENIED_BY_POLICY"
            )

        for param, rule in (tool_rules.get("params") or {}).items():
            if arguments is None or param not in arguments:
                continue
            code, reason = _check_param_value(arguments[param], rule)
            if code is not None:
                return Verdict(False, f"param '{param}': {reason}", code)

        return Verdict(True, "ok", "OK")
