"""Oracle-based evidence model: measurements, verdicts, and provenance.

This is the framework's epistemic core. Every claim a bug bounty finding makes
must trace back to a measurement that separated cleanly from a control. The
design goal is to make *overclaiming structurally difficult* rather than merely
discouraged in prose.

Three rules drive everything here:

1. **No signal without a control.** A differential or timing claim needs a
   paired control measurement taken under the same conditions. A payload that
   "worked" once, with nothing to compare against, is not evidence.
2. **Unknown beats refuted.** If measurements are missing, malformed, or do not
   separate cleanly, the verdict is ``UNKNOWN`` — never ``REFUTED``. Calling
   something refuted on weak evidence is how real vulnerabilities get closed as
   false positives. Refutation requires positive evidence of no effect,
   repeated.
3. **Every verdict is reproducible.** Each observation records its inputs and
   is hash-chained, so a reviewer can replay the reasoning chain and detect
   tampering after the fact.

SECURITY AND ETHICS: this module never performs network I/O. It records and
judges measurements that a human or an authorised driver collected. Use only
against systems you are authorised to test.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import statistics
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Sequence

__all__ = [
    "EvidenceGate",
    "GateResult",
    "InputRole",
    "Observation",
    "OracleKind",
    "ProvenanceChain",
    "Verdict",
    "classify",
    "redact",
]


# --------------------------------------------------------------------------- #
# Vocabulary
# --------------------------------------------------------------------------- #


class InputRole(str, Enum):
    """Where an input sits in query construction.

    This is the framework's central distinction, inherited from the SQLi
    methodology: placeholders parameterise *values*, never identifiers or
    keywords. Structure-role inputs are where SQL injection still lives in
    ORM-era applications.
    """

    VALUE = "value"
    STRUCTURE = "structure"
    BEHAVIOR = "behavior"
    UNKNOWN = "unknown"


class OracleKind(str, Enum):
    """The weakest sufficient oracle, in preference order."""

    REFLECTION = "reflection"      # error message or echoed fragment
    DIFFERENTIAL = "differential"  # boolean/state difference
    TIMING = "timing"              # latency delta
    OOB = "oob"                    # out-of-band callback
    OTHER = "other"


class Verdict(str, Enum):
    """Outcome of judging an observation.

    Deliberately not a boolean. ``UNKNOWN`` is a first-class, common result.
    """

    SIGNAL = "SIGNAL"      # separated cleanly from control
    REFUTED = "REFUTED"    # positive evidence of no effect, repeated
    UNKNOWN = "UNKNOWN"    # insufficient/ambiguous evidence
    ERROR = "ERROR"        # the measurement itself failed


#: Higher is more informative. ``UNKNOWN`` deliberately outranks ``REFUTED``:
#: an unresolved question is more valuable than a wrong negative.
_VERDICT_RANK = {
    Verdict.SIGNAL: 3,
    Verdict.UNKNOWN: 2,
    Verdict.ERROR: 1,
    Verdict.REFUTED: 0,
}


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #

_REDACT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"), "<email>"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"), "<jwt>"),
    # Keep the scheme word so the transcript still reads correctly.
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}"), r"\1 <secret>"),
    # Keep the key name and separator; mask only the value.
    (
        re.compile(r"(?i)\b(api[_-]?key|token|secret|password|passwd|pwd)\b(\s*[:=]\s*)[\"']?[^\s\"',;]{6,}"),
        r"\1\2<secret>",
    ),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "<ssn>"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "<card-like>"),
    (re.compile(r"\b[A-Fa-f0-9]{32,}\b"), "<hex-secret>"),
)


def redact(text: str, extra: Sequence[str] = ()) -> str:
    """Mask incidental third-party data in recorded evidence.

    A finding demonstrates *scope of access*; it does not republish the data
    reached along the way. Redaction happens at record time so unredacted
    values never reach an artifact on disk.
    """
    out = text
    for pattern, replacement in _REDACT_PATTERNS:
        out = pattern.sub(replacement, out)
    for literal in extra:
        if literal:
            out = out.replace(literal, "<redacted>")
    return out


# --------------------------------------------------------------------------- #
# Provenance
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ProvenanceRecord:
    """One link in an append-only hash chain."""

    seq: int
    at: str
    actor: str
    action: str
    digest: str
    prev_hash: str
    hash: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class ProvenanceChain:
    """Append-only, hash-chained record of what was done and observed.

    The chain makes silent edits detectable: changing any record invalidates
    every subsequent hash. It is tamper-*evident*, not tamper-proof — an
    attacker who rewrites the whole chain produces a consistent one — so the
    head hash should be recorded out of band (in the report) for real assurance.
    """

    GENESIS = "0" * 64

    def __init__(self, actor: str = "framework") -> None:
        self.actor = actor
        self._records: list[ProvenanceRecord] = []

    @staticmethod
    def _digest(payload: Any) -> str:
        encoded = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def append(self, action: str, payload: Any) -> ProvenanceRecord:
        seq = len(self._records) + 1
        at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        prev = self._records[-1].hash if self._records else self.GENESIS
        digest = self._digest(payload)
        material = f"{seq}|{at}|{self.actor}|{action}|{digest}|{prev}"
        record = ProvenanceRecord(
            seq=seq,
            at=at,
            actor=self.actor,
            action=action,
            digest=digest,
            prev_hash=prev,
            hash=hashlib.sha256(material.encode("utf-8")).hexdigest(),
        )
        self._records.append(record)
        return record

    @property
    def head(self) -> str:
        return self._records[-1].hash if self._records else self.GENESIS

    @property
    def records(self) -> list[ProvenanceRecord]:
        return list(self._records)

    def verify(self) -> tuple[bool, str]:
        """Recompute the chain. Returns ``(ok, detail)``."""
        prev = self.GENESIS
        for index, rec in enumerate(self._records, start=1):
            if rec.seq != index:
                return False, f"record {index}: sequence discontinuity (seq={rec.seq})"
            if rec.prev_hash != prev:
                return False, f"record {index}: prev_hash mismatch"
            material = f"{rec.seq}|{rec.at}|{rec.actor}|{rec.action}|{rec.digest}|{rec.prev_hash}"
            expected = hashlib.sha256(material.encode("utf-8")).hexdigest()
            if rec.hash != expected:
                return False, f"record {index}: hash mismatch (content altered)"
            prev = rec.hash
        return True, f"{len(self._records)} record(s) verified"

    def to_jsonl(self) -> str:
        return "".join(json.dumps(r.as_dict(), ensure_ascii=False) + "\n" for r in self._records)


# --------------------------------------------------------------------------- #
# Observation and judging
# --------------------------------------------------------------------------- #


@dataclass
class Observation:
    """A single judged probe: one payload, its control, and the measurements.

    ``control_measurements`` are taken with a null/benign variant of the same
    request, under the same conditions, and are mandatory for any verdict other
    than ``UNKNOWN`` or ``ERROR``.
    """

    id: str
    target: str
    entry_point: str
    parameter: str
    role: InputRole
    oracle: OracleKind
    payload: str
    control: str | None = None
    measurements: list[float] = field(default_factory=list)
    control_measurements: list[float] = field(default_factory=list)
    verdict: Verdict = Verdict.UNKNOWN
    rationale: str = ""
    notes: str = ""
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def __post_init__(self) -> None:
        self.payload = redact(self.payload)
        if self.control is not None:
            self.control = redact(self.control)
        self.notes = redact(self.notes)

    @property
    def repeats(self) -> int:
        return len(self.measurements)

    @property
    def has_control(self) -> bool:
        return bool(self.control_measurements)

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["role"] = self.role.value
        d["oracle"] = self.oracle.value
        d["verdict"] = self.verdict.value
        return d


def _spread(values: Sequence[float]) -> float:
    """Dispersion of a sample; 0.0 for a single point (unknown, not zero noise)."""
    if len(values) < 2:
        return 0.0
    return statistics.pstdev(values)


def classify(
    oracle: OracleKind,
    measurements: Sequence[float],
    control_measurements: Sequence[float] = (),
    *,
    min_repeats: int = 3,
    timing_margin: float = 2.5,
    timing_floor_s: float = 0.5,
) -> tuple[Verdict, str]:
    """Judge one oracle reading, returning ``(verdict, rationale)``.

    ``REFLECTION``, ``DIFFERENTIAL`` and ``OOB`` are treated as categorical
    oracles: a non-zero measurement means the effect was seen. ``TIMING``
    requires the delta to exceed both an absolute floor and a multiple of the
    baseline dispersion, because shared infrastructure, cold starts, and rate
    limiters all fake latency signals.

    Insufficient repeats yield ``UNKNOWN`` — never ``REFUTED``.
    """
    if not measurements:
        return Verdict.UNKNOWN, "no measurements recorded"

    if len(measurements) < 2 or (control_measurements and len(control_measurements) < 2):
        return (
            Verdict.UNKNOWN,
            f"single-sample reading ({len(measurements)} test, {len(control_measurements)} control); "
            "one anomalous response is noise until repeated",
        )

    if oracle in (OracleKind.REFLECTION, OracleKind.DIFFERENTIAL, OracleKind.OOB):
        hits = sum(1 for m in measurements if m)
        misses = len(measurements) - hits
        if not control_measurements:
            if hits == len(measurements) and hits >= 2:
                return (
                    Verdict.UNKNOWN,
                    f"effect observed in {hits}/{len(measurements)} readings but no control was recorded; "
                    "record a paired null variant before claiming a signal",
                )
            return Verdict.UNKNOWN, "no control recorded"
        control_hits = sum(1 for m in control_measurements if m)
        if hits >= 2 and control_hits == 0 and misses == 0:
            return (
                Verdict.SIGNAL,
                f"effect in {hits}/{len(measurements)} test readings, {control_hits}/{len(control_measurements)} control",
            )
        if hits == 0 and control_hits == 0:
            if len(measurements) < min_repeats:
                return (
                    Verdict.UNKNOWN,
                    f"no effect in {len(measurements)} readings but fewer than {min_repeats} repeats; "
                    "not enough evidence to refute",
                )
            return Verdict.REFUTED, f"no effect in {len(measurements)} test and {len(control_measurements)} control readings"
        if control_hits > 0:
            return (
                Verdict.UNKNOWN,
                f"effect also present in control ({control_hits}/{len(control_measurements)}); "
                "the oracle does not separate — likely caching, load balancing, or a shared baseline",
            )
        return Verdict.UNKNOWN, f"inconsistent: effect in only {hits}/{len(measurements)} test readings"

    if oracle is OracleKind.TIMING:
        if not control_measurements:
            return Verdict.UNKNOWN, "timing claim with no control baseline; latency cannot be judged in isolation"
        if len(measurements) < min_repeats or len(control_measurements) < min_repeats:
            return (
                Verdict.UNKNOWN,
                f"timing needs >={min_repeats} repeats per arm; have {len(measurements)} test, "
                f"{len(control_measurements)} control",
            )
        test_med = statistics.median(measurements)
        ctrl_med = statistics.median(control_measurements)
        delta = test_med - ctrl_med
        noise = max(_spread(measurements), _spread(control_measurements), 1e-6)
        if delta >= timing_floor_s and delta >= timing_margin * noise:
            return (
                Verdict.SIGNAL,
                f"median delta {delta:.3f}s exceeds floor {timing_floor_s}s and "
                f"{timing_margin}x observed spread ({noise:.3f}s)",
            )
        if abs(delta) < noise and len(measurements) >= min_repeats and len(control_measurements) >= min_repeats:
            return Verdict.REFUTED, f"median delta {delta:.3f}s is within observed spread ({noise:.3f}s)"
        return Verdict.UNKNOWN, f"delta {delta:.3f}s does not clear the floor+margin bar ({timing_floor_s}s, {timing_margin}x)"

    return Verdict.UNKNOWN, f"no judging rule for oracle {oracle.value}"


def judge(observation: Observation, **kwargs: Any) -> Observation:
    """Classify an observation in place and return it."""
    verdict, rationale = classify(
        observation.oracle, observation.measurements, observation.control_measurements, **kwargs
    )
    observation.verdict = verdict
    observation.rationale = rationale
    return observation


def strongest(observations: Iterable[Observation]) -> Verdict:
    """Best verdict across a set, using the informative-first ranking."""
    best = Verdict.REFUTED
    for obs in observations:
        if _VERDICT_RANK[obs.verdict] > _VERDICT_RANK[best]:
            best = obs.verdict
    return best


# --------------------------------------------------------------------------- #
# Evidence gate
# --------------------------------------------------------------------------- #


@dataclass
class GateResult:
    """Outcome of a gate check."""

    name: str
    passed: bool
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __str__(self) -> str:
        state = "PASS" if self.passed else "BLOCK"
        lines = [f"[{state}] {self.name}"]
        lines += [f"    - {r}" for r in self.reasons]
        lines += [f"    ! {w}" for w in self.warnings]
        return "\n".join(lines)


class EvidenceGate:
    """Require a finding to clear a minimum evidentiary bar before reporting.

    This is the framework's answer to impact inflation: a finding cannot reach
    the report stage on a single unrepeated reading, and it cannot claim
    structure-level SQL injection without naming the query-construction
    boundary that was crossed.
    """

    def __init__(
        self,
        *,
        min_repeats: int = 3,
        require_control: bool = True,
        require_structure_boundary: bool = True,
    ) -> None:
        self.min_repeats = min_repeats
        self.require_control = require_control
        self.require_structure_boundary = require_structure_boundary

    def check(
        self,
        observation: Observation,
        *,
        boundary: str | None = None,
        reproducible_from: str | None = None,
    ) -> GateResult:
        """Evaluate one observation against the bar.

        ``boundary`` names the specific query-construction seam that was
        crossed (e.g. "ORDER BY identifier position in the report-sort
        parameter"). Naming it is what separates a modern SQLi report from a
        scanner dump.
        """
        result = GateResult(name="evidence", passed=True)

        if observation.verdict is not Verdict.SIGNAL:
            result.passed = False
            result.reasons.append(
                f"verdict is {observation.verdict.value}, not SIGNAL — {observation.rationale}"
            )

        if observation.repeats < self.min_repeats:
            result.passed = False
            result.reasons.append(
                f"{observation.repeats} repeat(s); at least {self.min_repeats} required to separate signal from noise"
            )

        if self.require_control and not observation.has_control:
            result.passed = False
            result.reasons.append("no control measurements; a paired null variant is mandatory")

        if self.require_structure_boundary:
            if not boundary or not boundary.strip():
                result.passed = False
                result.reasons.append(
                    "no query-construction boundary named; state which seam the input crossed "
                    "(identifier position, raw escape hatch, second-order store, filter DSL)"
                )

        if observation.role is InputRole.VALUE:
            result.warnings.append(
                "input is classified as a VALUE (parameterisable); injection here usually means a "
                "missing placeholder rather than an identifier-position flaw — confirm the sink before reporting"
            )
        if observation.role is InputRole.UNKNOWN:
            result.warnings.append("input role is unclassified; classify value vs structure before reporting")

        if not reproducible_from:
            result.warnings.append("no reproduction prerequisite recorded (account level, feature flags, prior state)")

        return result


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #


def write_observations(path: Path, observations: Sequence[Observation]) -> None:
    """Write observations as JSON Lines, one judged probe per line."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for obs in observations:
            handle.write(json.dumps(obs.as_dict(), ensure_ascii=False) + "\n")


def read_observations(path: Path) -> list[Observation]:
    """Read observations back from JSON Lines."""
    out: list[Observation] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        raw = json.loads(line)
        out.append(
            Observation(
                id=raw["id"],
                target=raw["target"],
                entry_point=raw["entry_point"],
                parameter=raw["parameter"],
                role=InputRole(raw.get("role", "unknown")),
                oracle=OracleKind(raw.get("oracle", "other")),
                payload=raw.get("payload", ""),
                control=raw.get("control"),
                measurements=[float(m) for m in raw.get("measurements", [])],
                control_measurements=[float(m) for m in raw.get("control_measurements", [])],
                verdict=Verdict(raw.get("verdict", "UNKNOWN")),
                rationale=raw.get("rationale", ""),
                notes=raw.get("notes", ""),
                observed_at=raw.get("observed_at", ""),
            )
        )
    return out
