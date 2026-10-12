"""Lead ledger: hypothesis lifecycle with a refusal-to-kill guard.

A *lead* is a hypothesis under investigation. Leads are cheap and numerous; a
*finding* is a lead that survived evidence. The failure mode this module exists
to prevent is **premature closure**: killing a promising lead on a single
negative probe, then later rediscovering the same bug the hard way.

The guard is deliberately obstructive. :func:`kill_lead` refuses to move a lead
to ``KILLED`` unless *both* halves of the experiment — the test arm and the
control arm — have been refuted, each with a non-empty evidence string. A
one-sided refutation parks the lead instead, and repeated one-sided attempts are
counted so an operator can see the lead is being circled rather than resolved.

Probes are expected to change exactly one variable at a time. When several
inputs change at once a negative result is uninterpretable, so mutations are
recorded individually and :meth:`Lead.multi_variable_mutations` surfaces the
violations.

SECURITY AND ETHICS: this module performs no I/O beyond JSON Lines persistence.
It does not probe anything.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Sequence

from evidence import InputRole, OracleKind, Verdict

__all__ = ["Arm", "KillOutcome", "Lead", "LeadLedger", "LeadState", "Mutation"]


class LeadState(str, Enum):
    """Where a hypothesis stands."""

    OPEN = "OPEN"            # formed, not yet probed
    MUTATING = "MUTATING"    # actively varying inputs
    FINDING = "FINDING"      # cleared the evidence bar
    PARKED = "PARKED"        # not resolved; revisit later
    KILLED = "KILLED"        # both arms refuted, with evidence


class Arm(str, Enum):
    """Which half of the experiment a refutation belongs to."""

    TEST = "test"
    CONTROL = "control"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Mutation:
    """One single-variable change and what it showed.

    ``variable`` names the one thing that changed (a payload clause, an
    encoding, a content-type, a parameter). ``companions`` records anything
    else that changed in the same request, which is usually a mistake.
    """

    variable: str
    from_value: str
    to_value: str
    observation_id: str | None = None
    verdict: Verdict = Verdict.UNKNOWN
    companions: list[str] = field(default_factory=list)
    at: str = field(default_factory=_now)

    @property
    def is_single_variable(self) -> bool:
        return not self.companions

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d


@dataclass
class Lead:
    """A hypothesis about one entry point, with its probe history."""

    id: str
    target: str
    entry_point: str
    parameter: str
    role: InputRole
    hypothesis: str
    oracle: OracleKind = OracleKind.DIFFERENTIAL
    state: LeadState = LeadState.OPEN
    mutations: list[Mutation] = field(default_factory=list)
    refutations: dict[str, list[str]] = field(default_factory=dict)  # arm -> evidence strings
    tripwires: list[str] = field(default_factory=list)
    dismissal_attempts: int = 0
    notes: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    @staticmethod
    def make_id(target: str, entry_point: str, parameter: str, hypothesis: str) -> str:
        material = f"{target}|{entry_point}|{parameter}|{hypothesis}".lower()
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]

    # -- mutation recording ------------------------------------------------- #

    def record_mutation(
        self,
        variable: str,
        from_value: str,
        to_value: str,
        *,
        observation_id: str | None = None,
        verdict: Verdict = Verdict.UNKNOWN,
        companions: Sequence[str] = (),
    ) -> Mutation:
        """Record one probe. Moves an OPEN lead to MUTATING."""
        mutation = Mutation(
            variable=variable,
            from_value=from_value,
            to_value=to_value,
            observation_id=observation_id,
            verdict=verdict,
            companions=list(companions),
        )
        self.mutations.append(mutation)
        if self.state is LeadState.OPEN:
            self.state = LeadState.MUTATING
        self.updated_at = _now()
        return mutation

    def multi_variable_mutations(self) -> list[Mutation]:
        """Probes that changed more than one variable, so results are confounded."""
        return [m for m in self.mutations if not m.is_single_variable]

    # -- refutation bookkeeping --------------------------------------------- #

    def refute(self, arm: Arm, evidence: str) -> None:
        """Record a refutation for one arm. Empty evidence is rejected."""
        if not evidence or not evidence.strip():
            raise ValueError("a refutation requires non-empty evidence")
        self.refutations.setdefault(arm.value, []).append(evidence.strip())
        self.updated_at = _now()

    def is_arm_refuted(self, arm: Arm) -> bool:
        return bool(self.refutations.get(arm.value))

    def both_arms_refuted(self) -> bool:
        return self.is_arm_refuted(Arm.TEST) and self.is_arm_refuted(Arm.CONTROL)

    def promote(self) -> None:
        """Advance a lead to FINDING (evidence gate is a separate check)."""
        self.state = LeadState.FINDING
        self.updated_at = _now()

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["role"] = self.role.value
        d["oracle"] = self.oracle.value
        d["state"] = self.state.value
        d["mutations"] = [m.as_dict() for m in self.mutations]
        return d


@dataclass
class KillOutcome:
    """Result of attempting to kill a lead."""

    lead_id: str
    killed: bool
    state: LeadState
    reason: str
    missing_arms: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        verb = "KILLED" if self.killed else "REFUSED"
        detail = f" (missing: {', '.join(self.missing_arms)})" if self.missing_arms else ""
        return f"[{verb}] {self.lead_id}: {self.reason}{detail}"


def kill_lead(lead: Lead) -> KillOutcome:
    """Kill a lead only if both arms are refuted; otherwise park it.

    Parking is not a soft kill: a parked lead keeps its state, its evidence, and
    its tripwires, and reappears in :meth:`LeadLedger.active` review rather than
    silently disappearing.
    """
    if lead.both_arms_refuted():
        lead.state = LeadState.KILLED
        lead.updated_at = _now()
        return KillOutcome(
            lead_id=lead.id,
            killed=True,
            state=lead.state,
            reason="both test and control arms refuted with evidence",
        )

    missing = [arm.value for arm in Arm if not lead.is_arm_refuted(arm)]
    lead.state = LeadState.PARKED
    lead.dismissal_attempts += 1
    lead.updated_at = _now()
    return KillOutcome(
        lead_id=lead.id,
        killed=False,
        state=lead.state,
        reason=(
            f"refused: only one side of the experiment is refuted (attempt #{lead.dismissal_attempts}); "
            "a one-sided negative does not establish absence of the vulnerability"
        ),
        missing_arms=missing,
    )


class LeadLedger:
    """Collection of leads with JSON Lines persistence."""

    def __init__(self, leads: Iterable[Lead] = ()) -> None:
        self._leads: dict[str, Lead] = {lead.id: lead for lead in leads}

    def __len__(self) -> int:
        return len(self._leads)

    def __iter__(self):
        return iter(self._leads.values())

    def add(self, lead: Lead) -> Lead:
        self._leads[lead.id] = lead
        return lead

    def get(self, lead_id: str) -> Lead | None:
        return self._leads.get(lead_id)

    def by_state(self, state: LeadState) -> list[Lead]:
        return sorted((l for l in self._leads.values() if l.state is state), key=lambda l: l.created_at)

    def active(self) -> list[Lead]:
        """Leads still needing attention: open, mutating, or parked."""
        return [
            l
            for l in sorted(self._leads.values(), key=lambda l: l.created_at)
            if l.state in (LeadState.OPEN, LeadState.MUTATING, LeadState.PARKED)
        ]

    def findings(self) -> list[Lead]:
        return self.by_state(LeadState.FINDING)

    def repeatedly_dismissed(self, threshold: int = 2) -> list[Lead]:
        """Parked leads someone keeps trying to kill — worth a human decision."""
        return [l for l in self.active() if l.dismissal_attempts >= threshold]

    def summary(self) -> dict[str, int]:
        counts = {state.value: 0 for state in LeadState}
        for lead in self._leads.values():
            counts[lead.state.value] += 1
        counts["total"] = len(self._leads)
        counts["confounded_mutations"] = sum(len(l.multi_variable_mutations()) for l in self._leads.values())
        return counts

    def to_jsonl(self) -> str:
        return "".join(json.dumps(l.as_dict(), ensure_ascii=False) + "\n" for l in self._leads.values())

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_jsonl(), encoding="utf-8")

    @classmethod
    def read(cls, path: Path) -> "LeadLedger":
        ledger = cls()
        if not path.is_file():
            return ledger
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            lead = Lead(
                id=raw["id"],
                target=raw["target"],
                entry_point=raw["entry_point"],
                parameter=raw["parameter"],
                role=InputRole(raw.get("role", "unknown")),
                hypothesis=raw.get("hypothesis", ""),
                oracle=OracleKind(raw.get("oracle", "differential")),
                state=LeadState(raw.get("state", "OPEN")),
                refutations=raw.get("refutations", {}),
                tripwires=raw.get("tripwires", []),
                dismissal_attempts=int(raw.get("dismissal_attempts", 0)),
                notes=raw.get("notes", []),
                created_at=raw.get("created_at", ""),
                updated_at=raw.get("updated_at", ""),
            )
            for m in raw.get("mutations", []):
                lead.mutations.append(
                    Mutation(
                        variable=m.get("variable", ""),
                        from_value=m.get("from_value", ""),
                        to_value=m.get("to_value", ""),
                        observation_id=m.get("observation_id"),
                        verdict=Verdict(m.get("verdict", "UNKNOWN")),
                        companions=m.get("companions", []),
                        at=m.get("at", ""),
                    )
                )
            ledger.add(lead)
        return ledger


def _main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Inspect a lead ledger JSONL file.")
    parser.add_argument("path", type=Path)
    args = parser.parse_args(argv)

    ledger = LeadLedger.read(args.path)
    summary = ledger.summary()
    print(f"{args.path}: {summary['total']} lead(s)")
    for key in ("OPEN", "MUTATING", "FINDING", "PARKED", "KILLED", "confounded_mutations"):
        print(f"  {key:<22} {summary.get(key, 0)}")
    for lead in ledger.active():
        print(f"\n  {lead.id}  [{lead.state.value}]  {lead.entry_point} :: {lead.parameter}")
        print(f"      {lead.hypothesis}")
        if lead.dismissal_attempts:
            print(f"      dismissal attempts: {lead.dismissal_attempts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
