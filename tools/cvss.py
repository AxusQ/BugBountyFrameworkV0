"""CVSS v3.1 base score calculator.

The source material this framework draws on ships hardcoded severity-to-number
maps and no calculator at all, which is how severity claims drift away from the
metrics actually verified. This module implements the v3.1 base metric group
from the specification, so a score is always derived from stated metrics and is
reproducible by a triager.

Only the **base** group is supported, deliberately. Temporal and Environmental
metrics require knowledge of exploit maturity and the customer environment that
a bug bounty hunter generally does not have; setting them invents certainty.
The output records the vector string, so the reasoning is auditable rather than
being a bare number.

Reference: CVSS v3.1 Specification Document (FIRST.org), sections 7.1 and 7.4.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass, field
from typing import Any, Sequence

__all__ = ["CvssError", "CvssScore", "score", "score_to_severity"]

# Metric value tables from the v3.1 specification.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_LABELS = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"H": "High", "L": "Low", "N": "None"},
}


class CvssError(ValueError):
    """Raised for an unparseable or invalid metric vector."""


@dataclass
class CvssScore:
    """A computed base score with its inputs, so the number is auditable."""

    vector: str
    base_score: float
    severity: str
    impact: float
    exploitability: float
    metrics: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "vector": self.vector,
            "base_score": self.base_score,
            "severity": self.severity,
            "impact_subsystem": round(self.impact, 4),
            "exploitability_subsystem": round(self.exploitability, 4),
            "metrics": self.metrics,
            "metric_labels": {
                k: _LABELS.get(k, {}).get(v, v) for k, v in self.metrics.items()
            },
            "notes": self.notes,
        }

    def __str__(self) -> str:
        return f"{self.base_score:.1f} {self.severity}  {self.vector}"


def _roundup(value: float) -> float:
    """v3.1 Appendix A roundup: round up to one decimal place.

    Implemented with integer arithmetic on the scaled value because the naive
    ``ceil(x * 10) / 10`` is wrong for floats that are already exact multiples
    of 0.1 (e.g. 4.000000000000001 and 3.9999999999999996 both occur here).
    """
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def score_to_severity(base_score: float) -> str:
    """Qualitative rating bands from the specification (section 5)."""
    if base_score == 0.0:
        return "None"
    if base_score < 4.0:
        return "Low"
    if base_score < 7.0:
        return "Medium"
    if base_score < 9.0:
        return "High"
    return "Critical"


def _parse_vector(vector: str) -> dict[str, str]:
    """Parse ``CVSS:3.1/AV:N/AC:L/...`` into a metric mapping."""
    text = vector.strip()
    if text.upper().startswith("CVSS:3.1/"):
        text = text[len("CVSS:3.1/") :]
    elif text.upper().startswith("CVSS:3.0/"):
        raise CvssError("CVSS:3.0 vectors are accepted only after converting to 3.1 metric values")

    metrics: dict[str, str] = {}
    for part in text.split("/"):
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            raise CvssError(f"malformed metric {part!r}; expected KEY:VALUE")
        key, _, value = part.partition(":")
        key = key.strip().upper()
        value = value.strip().upper()
        if key in metrics:
            raise CvssError(f"duplicate metric {key}")
        metrics[key] = value
    return metrics


def score(
    vector: str | None = None,
    *,
    AV: str = "N",
    AC: str = "L",
    PR: str = "N",
    UI: str = "N",
    S: str = "U",
    C: str = "N",
    I: str = "N",
    A: str = "N",
) -> CvssScore:
    """Compute a CVSS v3.1 base score.

    Accepts either a full vector string or individual keyword metrics. When a
    vector is supplied, the keyword arguments are ignored.
    """
    if vector:
        metrics = _parse_vector(vector)
    else:
        metrics = {"AV": AV, "AC": AC, "PR": PR, "UI": UI, "S": S, "C": C, "I": I, "A": A}

    metrics = {k: str(v).upper() for k, v in metrics.items()}

    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    missing = sorted(required - set(metrics))
    if missing:
        raise CvssError(f"missing required base metric(s): {', '.join(missing)}")
    unknown = sorted(set(metrics) - required)
    if unknown:
        raise CvssError(
            f"unsupported metric(s): {', '.join(unknown)}; base scoring supports only {', '.join(sorted(required))}"
        )

    for key, table in (("AV", _AV), ("AC", _AC), ("UI", _UI), ("S", ("U", "C"))):
        if metrics[key] not in table:
            raise CvssError(f"invalid {key}:{metrics[key]} (expected one of {', '.join(table)})")
    for key in ("C", "I", "A"):
        if metrics[key] not in _CIA:
            raise CvssError(f"invalid {key}:{metrics[key]} (expected one of H, L, N)")
    if metrics["PR"] not in _PR_UNCHANGED:
        raise CvssError("invalid PR (expected one of N, L, H)")

    scope_changed = metrics["S"] == "C"
    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED

    iss = 1.0 - (
        (1.0 - _CIA[metrics["C"]]) * (1.0 - _CIA[metrics["I"]]) * (1.0 - _CIA[metrics["A"]])
    )
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = (
        8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr_table[metrics["PR"]] * _UI[metrics["UI"]]
    )

    notes: list[str] = []
    if impact <= 0:
        base = 0.0
        notes.append("no impact metrics (C/I/A all None): base score is 0.0 by definition")
    elif scope_changed:
        base = _roundup(min(1.08 * (impact + exploitability), 10.0))
    else:
        base = _roundup(min(impact + exploitability, 10.0))

    if scope_changed:
        notes.append("Scope:Changed multiplies impact+exploitability by 1.08 and uses the higher PR table")
    if metrics["PR"] != "N" and not scope_changed and _PR_UNCHANGED[metrics["PR"]] < _PR_UNCHANGED["N"]:
        notes.append("PR reduces exploitability: record the privilege level you actually demonstrated")
    if metrics["UI"] == "R":
        notes.append("UI:Required means a victim action is part of the chain; state the action explicitly")

    ordered = "".join(f"/{k}:{metrics[k]}" for k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"))
    return CvssScore(
        vector=f"CVSS:3.1{ordered}",
        base_score=base,
        severity=score_to_severity(base),
        impact=impact,
        exploitability=exploitability,
        metrics=metrics,
        notes=notes,
    )


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compute a CVSS v3.1 base score.")
    parser.add_argument("vector", nargs="?", help="e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    parser.add_argument("--av", default="N", choices=list(_AV))
    parser.add_argument("--ac", default="L", choices=list(_AC))
    parser.add_argument("--pr", default="N", choices=list(_PR_UNCHANGED))
    parser.add_argument("--ui", default="N", choices=list(_UI))
    parser.add_argument("--s", default="U", choices=["U", "C"])
    parser.add_argument("--c", default="N", choices=list(_CIA))
    parser.add_argument("--i", default="N", choices=list(_CIA))
    parser.add_argument("--a", default="N", choices=list(_CIA))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        if args.vector:
            result = score(args.vector)
        else:
            result = score(AV=args.av, AC=args.ac, PR=args.pr, UI=args.ui, S=args.s, C=args.c, I=args.i, A=args.a)
    except CvssError as exc:
        print(f"error: {exc}")
        return 2

    if args.json:
        print(json.dumps(result.as_dict(), indent=2))
    else:
        print(f"vector          {result.vector}")
        print(f"base score      {result.base_score:.1f}  ({result.severity})")
        print(f"impact          {result.impact:.4f}")
        print(f"exploitability  {result.exploitability:.4f}")
        for key in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
            print(f"  {key:<3} {result.metrics[key]}  {_LABELS[key][result.metrics[key]]}")
        for note in result.notes:
            print(f"note: {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
