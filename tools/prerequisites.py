"""Attacker-prerequisite ledger and counterevidence.

Two gates that decide whether a signal is actually a *finding*.

**The prerequisite ledger.** A demonstrated primitive is not a finding until
every value, role, state, or action an attacker would need is shown to be
obtainable through an in-scope path. "The endpoint returns another user's record
if you supply their UUID" is not a vulnerability report — it is a report that the
UUID was known. Attacker reachability has to be established separately, and this
module makes that a structured obligation rather than an afterthought.

**Counterevidence.** Before a finding is called proven, the strongest benign or
intended explanation must be written down, the control that ruled it out
recorded, and one fact named that would change the severity. A section that is
absent or filled with a placeholder blocks the claim; the point is to force the
author to argue against themselves once.

The load-bearing rule, and the reason this module exists rather than a checklist:

    Lack of time, or a single negative request, is not disproof.

A prerequisite may only be marked ``NOT_REACHABLE`` once the acquisition hunt has
been *documented*. An undocumented negative is recorded as ``UNVERIFIED`` — an
open question — because treating "I did not manage it" as "it cannot be done" is
how real vulnerabilities get closed as false positives. This mirrors the
``UNKNOWN``-beats-``REFUTED`` rule in :mod:`evidence`, one level up.

These mechanisms were reimplemented from the design of the MIT-licensed
`bug-bounty-hunting-prompts` pack, which tracks a reachability ledger and a
counterevidence section as gates before a finding may be called proven. The
implementation here is original and narrower: it is executable, not prose.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Iterable, Sequence

from evidence import GateResult

__all__ = [
    "CounterEvidence",
    "PrereqVerdict",
    "Prerequisite",
    "PrerequisiteLedger",
    "PrereqStatus",
]


class PrereqStatus(str, Enum):
    """Whether an attacker can satisfy one prerequisite."""

    UNVERIFIED = "UNVERIFIED"        # not yet established — an open question
    REACHABLE = "REACHABLE"          # obtained or created via an in-scope path
    NOT_REACHABLE = "NOT_REACHABLE"  # hunted for, and shown to be unobtainable
    BLOCKED = "BLOCKED"              # could not test: environment or access problem


class PrereqVerdict(str, Enum):
    """The ledger's overall judgement about a finding."""

    PROVEN = "PROVEN"            # every prerequisite reachable
    DISPROVED = "DISPROVED"      # some prerequisite genuinely unobtainable
    BLOCKED = "BLOCKED"          # something prevented testing
    INCOMPLETE = "INCOMPLETE"    # unanswered rows remain — not a negative


#: A counterevidence narrative shorter than this is treated as a placeholder.
MIN_COUNTEREVIDENCE_CHARS = 40

_PLACEHOLDER = re.compile(
    r"^\s*(?:n/?a|none|tbd|todo|unknown|-{1,3}|\.{1,3})\s*$", re.IGNORECASE
)


@dataclass
class Prerequisite:
    """One thing an attacker must have for the finding to be real.

    ``acquisition_step`` is where most findings die: it must name a concrete,
    in-scope way to obtain the prerequisite through the claimed attacker path.
    "Attacker guesses a UUID" is not an acquisition step.
    """

    requirement: str
    attacker_capability: str
    acquisition_step: str
    status: PrereqStatus = PrereqStatus.UNVERIFIED
    evidence_path: str | None = None
    #: Set once the acquisition hunt has been written up. Required before a
    #: negative can count as disproof rather than as an open question.
    hunt_documented: bool = False

    def effective_status(self) -> PrereqStatus:
        """The status this row is actually allowed to carry.

        An undocumented ``NOT_REACHABLE`` is downgraded to ``UNVERIFIED``.
        Failing to obtain something is not evidence that it cannot be obtained,
        and the whole point of the ledger is to stop that inference being made
        silently.
        """
        if self.status is PrereqStatus.NOT_REACHABLE and not self.hunt_documented:
            return PrereqStatus.UNVERIFIED
        return self.status

    def problems(self) -> list[str]:
        """Reasons this row is not usable as stated."""
        out: list[str] = []
        for name in ("requirement", "attacker_capability", "acquisition_step"):
            if not getattr(self, name, "").strip():
                out.append(f"missing {name}")
        if self.status is PrereqStatus.REACHABLE and not self.evidence_path:
            out.append("REACHABLE needs an evidence path")
        if self.status is PrereqStatus.NOT_REACHABLE and not self.hunt_documented:
            out.append("NOT_REACHABLE is recorded as UNVERIFIED until the acquisition hunt is documented")
        return out

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["effective_status"] = self.effective_status().value
        return d

    def __str__(self) -> str:
        return f"[{self.effective_status().value:<13}] {self.requirement}"


class PrerequisiteLedger:
    """Every prerequisite for one finding, and the verdict they support."""

    def __init__(self, rows: Iterable[Prerequisite] = ()) -> None:
        self.rows: list[Prerequisite] = list(rows)

    def __len__(self) -> int:
        return len(self.rows)

    def __iter__(self):
        return iter(self.rows)

    def add(self, row: Prerequisite) -> Prerequisite:
        self.rows.append(row)
        return row

    def counts(self) -> dict[str, int]:
        counts = {status.value: 0 for status in PrereqStatus}
        for row in self.rows:
            counts[row.effective_status().value] += 1
        return counts

    def verdict(self) -> tuple[PrereqVerdict, list[str]]:
        """Judge the ledger, returning ``(verdict, reasons)``.

        Precedence is deliberate: a documented disproof outranks a blockage,
        because "this cannot be done" is a stronger statement than "I could not
        finish testing it".
        """
        reasons: list[str] = []

        if not self.rows:
            return PrereqVerdict.INCOMPLETE, [
                "no prerequisites recorded; state what the attacker needs, or the finding cannot be assessed"
            ]

        malformed = [row for row in self.rows if row.problems()]
        unreachable = [r for r in self.rows if r.effective_status() is PrereqStatus.NOT_REACHABLE]

        if unreachable:
            for row in unreachable:
                reasons.append(f"prerequisite unreachable via the claimed path: {row.requirement}")
            return PrereqVerdict.DISPROVED, reasons

        blocked = [r for r in self.rows if r.effective_status() is PrereqStatus.BLOCKED]
        if blocked:
            for row in blocked:
                reasons.append(
                    f"testing blocked for: {row.requirement} — a blocked row prevents proof but is not disproof"
                )
            return PrereqVerdict.BLOCKED, reasons

        unverified = [r for r in self.rows if r.effective_status() is PrereqStatus.UNVERIFIED]
        if unverified:
            for row in unverified:
                reasons.append(f"unverified prerequisite: {row.requirement}")
            reasons.append(
                "an unanswered prerequisite leaves the finding open, not disproved"
            )
            return PrereqVerdict.INCOMPLETE, reasons

        if malformed:
            for row in malformed:
                for problem in row.problems():
                    reasons.append(f"{row.requirement or '<unnamed>'}: {problem}")
            return PrereqVerdict.INCOMPLETE, reasons

        reasons.append(f"all {len(self.rows)} prerequisite(s) reachable through the claimed attacker path")
        return PrereqVerdict.PROVEN, reasons

    def check(self) -> GateResult:
        """Gate result for the ledger alone."""
        verdict, reasons = self.verdict()
        return GateResult(name="prerequisites", passed=verdict is PrereqVerdict.PROVEN, reasons=reasons)

    def as_list(self) -> list[dict[str, Any]]:
        return [row.as_dict() for row in self.rows]


@dataclass
class CounterEvidence:
    """The strongest argument against your own finding, and how you ruled it out.

    ``would_change_severity`` is required because it exposes the fragility of the
    claim: if the author cannot name a single fact that would move the severity,
    they have usually not thought about the boundary conditions at all.
    """

    benign_explanation: str
    control_checked: str
    control_result: str
    would_change_severity: str

    def problems(self) -> list[str]:
        out: list[str] = []
        for name in ("benign_explanation", "control_checked", "control_result", "would_change_severity"):
            value = (getattr(self, name, "") or "").strip()
            if not value:
                out.append(f"missing {name}")
            elif _PLACEHOLDER.match(value):
                out.append(f"{name} is a placeholder ({value!r})")
            elif len(value) < MIN_COUNTEREVIDENCE_CHARS and name in ("benign_explanation", "control_checked"):
                out.append(
                    f"{name} is too short ({len(value)} chars) to be a real argument; "
                    f"aim for at least {MIN_COUNTEREVIDENCE_CHARS}"
                )
        return out

    def check(self) -> GateResult:
        problems = self.problems()
        result = GateResult(
            name="counterevidence",
            passed=not problems,
            reasons=problems,
        )
        if problems:
            result.reasons.append(
                "a proven finding must state the strongest benign explanation and the control that ruled it out"
            )
        return result

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
