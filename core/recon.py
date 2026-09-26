"""Volume reconciliation tolerance model (R14).

The SEND bytes observed by the network sensor include protocol overhead
(TLS records, HTTP/2 framing, ...). A 2.3 MB file sent over HTTPS
produces slightly MORE than 2.3 MB of tcp_sendmsg bytes. Reconciliation
therefore needs a tolerance -- and the tolerance must be an explicit,
configurable, explainable policy parameter, never a hidden constant.

Every reconciliation result records observed_bytes, expected_bytes,
tolerance, tolerance_reason and protocol so future protocol-specific
tuning changes policy, not the data model.

Conservative upper-bound mode (R15): we never claim to know exactly how
many bytes were read from a file (read() tracing is off by default).
Instead we compare outbound volume against the SIZE of files opened,
treating "outbound <= total opened size * (1 + tolerance)" as the
suspicion bound, and "outbound within tolerance of a single opened
file's size" as a strong single-file signal.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone


@dataclass
class Tolerance:
    ratio: float = 0.10
    reason: str = "default engineering margin for TLS/HTTP overhead (MVP)"
    protocol: str = "https"

    @classmethod
    def from_config(cls, cfg: dict) -> "Tolerance":
        return cls(
            ratio=float(cfg.get("ratio", 0.10)),
            reason=str(cfg.get("reason", "configured")),
            protocol=str(cfg.get("protocol", "https")),
        )

    def band(self, expected: int) -> tuple[int, int]:
        slack = max(1, int(expected * self.ratio))
        return max(0, expected - slack), expected + slack


@dataclass
class Reconciliation:
    observed_bytes: int
    expected_bytes: int
    tolerance_ratio: float
    tolerance_reason: str
    protocol: str
    verdict: str  # MATCH / OUT_OF_BAND / INSUFFICIENT_EVIDENCE

    def to_dict(self) -> dict:
        return asdict(self)


def reconcile(observed: int, expected: int | None, tol: Tolerance) -> Reconciliation:
    if expected is None or expected <= 0:
        return Reconciliation(
            observed_bytes=observed,
            expected_bytes=0,
            tolerance_ratio=tol.ratio,
            tolerance_reason=tol.reason,
            protocol=tol.protocol,
            verdict="INSUFFICIENT_EVIDENCE",
        )
    lo, hi = tol.band(expected)
    verdict = "MATCH" if lo <= observed <= hi else "OUT_OF_BAND"
    return Reconciliation(
        observed_bytes=observed,
        expected_bytes=expected,
        tolerance_ratio=tol.ratio,
        tolerance_reason=tol.reason,
        protocol=tol.protocol,
        verdict=verdict,
    )
