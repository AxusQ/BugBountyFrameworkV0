"""The hunting pipeline: phases, artifacts, and gates in one runnable driver.

The phase model follows the assembled design — authorise, gather, hypothesise,
probe, gate, deduplicate, report — but with two properties the source material
lacks:

* **Gates are executable.** Each phase that can be blocked by policy is blocked
  by code, not by a sentence in a prompt.
* **State is on disk.** A run is a directory; every phase writes an artifact and
  every later phase reads the artifacts of earlier ones. A run can be resumed,
  reviewed, or handed to a human at any point, and the reasoning chain survives
  the end of the session.

The gather phase is deliberately model-free. Deterministic collectors produce a
bounded, ranked evidence bundle; the model is only asked to adjudicate that
bundle. Because the inputs to gathering are supplied as artefacts rather than
fetched over the network, the whole pipeline is replayable in tests.

This driver never sends network requests and never exploits anything. Probing is
performed by the operator or an authorised driver, which records measurements
through :func:`record`; the pipeline's job is to decide whether what was recorded
is reportable.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

import collectors as C  # noqa: E402
import evidence as E  # noqa: E402
import gates as G  # noqa: E402
import leads as L  # noqa: E402
import report as R  # noqa: E402

FRAMEWORK_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RUNS = FRAMEWORK_ROOT / "runs"

#: Ordered phases. Each name matches a method on :class:`Run`.
PHASES = ("authorise", "gather", "hypothesise", "probe", "gate", "deduplicate", "report")

ARTIFACTS = {
    "authorise": "scope.json",
    "gather": "evidence.json",
    "boundary": "boundary.json",
    "hypothesise": "leads.jsonl",
    "probe": "observations.jsonl",
    "gate": "gate.json",
    "deduplicate": "dedup.json",
    "report": "reports",
    "provenance": "provenance.jsonl",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


#: A run target must be a bare hostname-ish token. Anything else is refused.
#:
#: This is a security boundary, not tidiness. ``Path("/runs") / "/etc/pwned"``
#: discards the left operand entirely in pathlib, and ``../`` walks upward, so a
#: target string taken from an operator, a config file, or an agent's own output
#: could direct every artifact write — scope record, evidence, observations,
#: reports — outside the runs directory. In an agent-driven pipeline that is a
#: write-anywhere primitive, so it is validated *and* the result is re-checked
#: for containment before use.
_TARGET_RE = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,251}[a-z0-9])?\Z")


def safe_target_slug(target: str) -> str:
    """Normalise ``target`` into a directory name safe to join onto the runs root."""
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target must be a non-empty string")

    slug = target.strip().lower()
    if not _TARGET_RE.match(slug):
        raise ValueError(
            f"unsafe target {target!r}: expected a hostname-like token of letters, digits, "
            "dots, hyphens and underscores (no path separators, no '..', no drive letters)"
        )
    if ".." in slug:
        raise ValueError(f"unsafe target {target!r}: path traversal sequence is not permitted")
    return slug


@dataclass
class PhaseResult:
    """Outcome of one phase, so a caller can decide whether to continue."""

    phase: str
    ok: bool
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    blocked_by: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        state = "ok" if self.ok else "BLOCKED"
        lines = [f"[{state}] {self.phase}: {self.summary}"]
        lines += [f"    blocked by: {reason}" for reason in self.blocked_by]
        return "\n".join(lines)


class Run:
    """One hunting run against one target, persisted as a directory.

    ``runs/<target>/`` holds the authorization record, the gathered evidence,
    the lead ledger, the judged observations, and the gate results. Every write
    is also appended to a hash-chained provenance log so the sequence of actions
    is tamper-evident after the fact.
    """

    def __init__(self, root: Path, target: str) -> None:
        # Validated, not merely joined: see safe_target_slug and _TARGET_RE.
        self.target = safe_target_slug(target)
        self.root = Path(root).resolve()
        candidate = (self.root / self.target).resolve()

        # Defence in depth. Even with a validated slug, refuse anything that
        # resolves outside the runs root, so a symlinked runs directory or an
        # unexpected filesystem cannot redirect artifact writes.
        if candidate != self.root and self.root not in candidate.parents:
            raise ValueError(
                f"refusing a run directory outside the runs root: {candidate} is not under {self.root}"
            )

        self.dir = candidate
        self.dir.mkdir(parents=True, exist_ok=True)
        self.chain = E.ProvenanceChain(actor="pipeline")

    # -- artifact helpers --------------------------------------------------- #

    def path(self, key: str) -> Path:
        return self.dir / ARTIFACTS[key]

    def _write_json(self, key: str, payload: Any) -> Path:
        path = self.path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        self.chain.append(f"write:{key}", payload if not isinstance(payload, list) else {"count": len(payload)})
        return path

    def _read_json(self, key: str) -> Any:
        path = self.path(key)
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def save_provenance(self) -> Path:
        path = self.path("provenance")
        path.write_text(self.chain.to_jsonl(), encoding="utf-8")
        return path

    # -- phases ------------------------------------------------------------- #

    def authorise(self, authorization: G.Authorization) -> PhaseResult:
        """Record the authorization basis and refuse to continue without one."""
        self._write_json("authorise", asdict(authorization))
        check = G.ScopeGate(authorization).check()
        return PhaseResult(
            phase="authorise",
            ok=check.passed,
            summary=f"scope recorded for program {authorization.program!r}",
            details={"in_scope": authorization.in_scope, "out_of_scope": authorization.out_of_scope},
            blocked_by=check.reasons,
        )

    def authorization(self) -> G.Authorization | None:
        raw = self._read_json("authorise")
        return G.Authorization(**raw) if raw else None

    def gather(
        self,
        *,
        js_texts: Iterable[tuple[str, str]] = (),
        previous_snapshot: dict[str, Any] | None = None,
        alive: Sequence[str] = (),
        dead: Sequence[str] = (),
        first_seen: dict[str, str] | None = None,
        max_items: int = 40,
    ) -> PhaseResult:
        """Run the deterministic collectors and apply the asset boundary.

        Blocked when no authorization has been recorded, because gathering from
        a target you have not established a basis for is the failure this gate
        exists to prevent.
        """
        auth = self.authorization()
        scope = G.ScopeGate(auth).check()
        if not scope.passed:
            return PhaseResult(
                phase="gather", ok=False,
                summary="gathering refused: no valid authorization on record",
                blocked_by=scope.reasons,
            )

        texts = list(js_texts)
        signals: list[C.ChangeSignal] = []
        if previous_snapshot:
            differ = C.SnapshotDiffer()
            differ.observe(
                self.target,
                alive=previous_snapshot.get("alive", []),
                dead=previous_snapshot.get("dead", []),
            )
            signals = differ.diff(self.target, alive=alive, dead=dead)

        bundle = C.collect(
            self.target, js_texts=texts, signals=signals, first_seen=first_seen, max_items=max_items
        )
        self._write_json("gather", json.loads(bundle.to_json()))

        boundary = G.AssetBoundary(auth)
        allowed, blocked = boundary.partition(texts)
        self._write_json(
            "boundary",
            {
                "allowed": [asdict(v) for v in allowed],
                "blocked": [asdict(v) for v in blocked],
                "policy": (
                    "hosts discovered inside target artefacts are untrusted; any host not independently "
                    "covered by the authorization record must not be contacted"
                ),
            },
        )

        summary = bundle.summary()
        return PhaseResult(
            phase="gather",
            ok=True,
            summary=(
                f"{summary['total']} evidence item(s) gathered, {summary['structure_role']} structure-role; "
                f"{len(blocked)} host(s) outside scope blocked"
            ),
            details=summary,
        )

    def hypothesise(self, *, max_leads: int = 25) -> PhaseResult:
        """Turn ranked evidence into leads, one per testable surface."""
        raw = self._read_json("gather")
        if not raw:
            return PhaseResult("hypothesise", False, "no evidence bundle; run gather first",
                               blocked_by=["missing artifact: evidence.json"])

        ledger = L.LeadLedger()
        for item in raw.get("items", [])[:max_leads]:
            if item["kind"] not in ("param", "sql-sink-hint", "template-sql", "api-path", "change-new", "change-revived"):
                continue
            hypothesis = _hypothesis_for(item)
            lead = L.Lead(
                id=L.Lead.make_id(self.target, item.get("raw_ref") or "artifact", item["value"], hypothesis),
                target=self.target,
                entry_point=item.get("raw_ref") or "artifact",
                parameter=item["value"],
                role=E.InputRole(item.get("role", "unknown")),
                hypothesis=hypothesis,
                oracle=E.OracleKind.DIFFERENTIAL,
                tripwires=[f"re-run the collector if {item['value']} changes upstream"],
            )
            ledger.add(lead)

        ledger.write(self.path("hypothesise"))
        self.chain.append("hypothesise", {"leads": len(ledger)})
        return PhaseResult(
            "hypothesise", True, f"{len(ledger)} lead(s) formed from the evidence bundle",
            details=ledger.summary(),
        )

    def record(self, observation: E.Observation, **gate_kwargs: Any) -> PhaseResult:
        """Judge and persist one probe observation."""
        E.judge(observation)
        path = self.path("probe")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(observation.as_dict(), ensure_ascii=False) + "\n")
        self.chain.append("probe", {"id": observation.id, "verdict": observation.verdict.value})
        return PhaseResult(
            "probe", True,
            f"{observation.id}: {observation.verdict.value} ({observation.rationale or 'no rationale'})",
            details=observation.as_dict(),
        )

    def gate(
        self,
        *,
        boundary: str | None = None,
        reproducible_from: str | None = None,
        prerequisites: Any = None,
        counterevidence: Any = None,
    ) -> PhaseResult:
        """Apply the evidence bar to every recorded observation.

        Supplying ``prerequisites`` and ``counterevidence`` raises the bar from
        "is this a signal?" to "may I report this?": a demonstrated primitive is
        not a finding until attacker reachability is established and the
        strongest benign explanation has been ruled out.
        """
        path = self.path("probe")
        if not path.is_file():
            return PhaseResult("gate", False, "no observations recorded",
                               blocked_by=["missing artifact: observations.jsonl"])

        observations = E.read_observations(path)
        gate = E.EvidenceGate()
        results = [
            gate.check(
                obs,
                boundary=boundary,
                reproducible_from=reproducible_from,
                prerequisites=prerequisites,
                counterevidence=counterevidence,
            )
            for obs in observations
        ]

        overall = E.strongest(observations)
        payload = {
            "checked_at": _now(),
            "overall_verdict": overall.value,
            "observations": len(observations),
            "passed": sum(1 for r in results if r.passed),
            "blocked": sum(1 for r in results if not r.passed),
            "results": [r.as_dict() for r in results],
        }
        if prerequisites is not None:
            verdict, reasons = prerequisites.verdict()
            payload["prerequisite_verdict"] = verdict.value
            payload["prerequisites"] = prerequisites.as_list()
            payload["prerequisite_reasons"] = reasons
        if counterevidence is not None:
            payload["counterevidence"] = counterevidence.as_dict()
            payload["counterevidence_problems"] = counterevidence.problems()

        self._write_json("gate", payload)
        return PhaseResult(
            "gate",
            ok=payload["passed"] > 0,
            summary=f"{payload['passed']}/{payload['observations']} observation(s) cleared the evidence bar; overall {overall.value}",
            details=payload,
            blocked_by=[r for result in results if not result.passed for r in result.reasons][:8],
        )

    def deduplicate(
        self,
        keys: Iterable[G.FindingKey] = (),
        *,
        known: Iterable[G.FindingKey] = (),
        prior_report_check: str | None = None,
        known_issue_list_checked: bool = False,
    ) -> PhaseResult:
        """Check candidate findings against the session and prior disclosures.

        ``known`` seeds the gate with findings recorded *elsewhere*. The
        candidates under test are deliberately not seeded: doing so would make
        every candidate a duplicate of itself, and the check would pass or fail
        for the wrong reason.
        """
        raw = self._read_json("gate")
        if not raw:
            return PhaseResult("deduplicate", False, "no gate results", blocked_by=["run gate first"])

        gate = G.DuplicateGate(known)
        findings: list[dict[str, Any]] = []
        blocked: list[str] = []
        for key in keys:
            result = gate.check(
                key,
                prior_report_check=prior_report_check,
                known_issue_list_checked=known_issue_list_checked,
            )
            findings.append(
                {
                    "key": str(key),
                    "passed": result.passed,
                    "reasons": result.reasons,
                    "warnings": result.warnings,
                }
            )
            blocked.extend(result.reasons)
            if result.passed:
                gate.record(key)  # a repeat of this key later is a real duplicate

        self._write_json("deduplicate", {"checked": len(findings), "findings": findings})
        ok = bool(findings) and all(f["passed"] for f in findings)
        return PhaseResult(
            "deduplicate",
            ok=ok,
            summary=(
                f"{sum(1 for f in findings if f['passed'])}/{len(findings)} finding key(s) cleared the "
                "duplication check"
            ),
            details={"findings": findings},
            blocked_by=blocked[:6],
        )

    def emit(self, finding: R.Finding, platform: str = "hackerone") -> PhaseResult:
        """Render a report, after running the self-triage gate over the draft."""
        problems = R.validate(finding, platform)
        text = R.render(finding, platform, strict=False)

        triage = G.TriageGate().check(
            text,
            cvss_vector=finding.cvss_vector,
            claimed_severity=finding.severity,
            boundary_named=bool(finding.boundary.strip()),
            poc_present=bool(finding.payload.strip() and finding.steps),
        )

        out_dir = self.path("report")
        out_dir.mkdir(parents=True, exist_ok=True)
        slug = "".join(ch if ch.isalnum() else "-" for ch in finding.title.lower())[:60].strip("-")
        out = out_dir / f"{platform}-{slug}.md"
        out.write_text(text, encoding="utf-8")
        self.chain.append("report", {"platform": platform, "verdict": triage.verdict, "path": str(out)})

        ok = triage.verdict != "DO NOT SUBMIT"
        return PhaseResult(
            "report", ok,
            f"{platform} report written to {out.name}; triage verdict {triage.verdict}",
            details={"path": str(out), "verdict": triage.verdict, "validation": problems,
                     "reasons": triage.result.reasons, "warnings": triage.result.warnings},
            blocked_by=triage.result.reasons,
        )

    # -- reporting ---------------------------------------------------------- #

    def status(self) -> dict[str, Any]:
        """Summarise which phases have produced artifacts."""
        out: dict[str, Any] = {"target": self.target, "dir": str(self.dir), "phases": {}}
        for phase in PHASES:
            path = self.path(phase)
            present = path.exists() and (path.is_dir() or path.stat().st_size > 0)
            out["phases"][phase] = {"artifact": path.name, "present": present}
        for extra in ("boundary", "provenance"):
            path = self.path(extra)
            out["phases"][extra] = {"artifact": path.name, "present": path.exists()}
        return out


def _hypothesis_for(item: dict[str, Any]) -> str:
    """State a testable claim for one evidence item."""
    kind = item["kind"]
    value = item["value"]
    if kind == "param" and item.get("role") == "structure":
        return (
            f"'{value}' selects query structure; test whether it is mapped to an allowlist or "
            "concatenated into the generated SQL"
        )
    if kind == "param":
        return f"'{value}' is a value parameter; test whether it reaches the query unparameterised"
    if kind == "sql-sink-hint":
        return f"raw-query API '{value}' is reachable from an attacker-controlled input"
    if kind == "template-sql":
        return "a template literal interpolates a variable beside a SQL keyword; trace the value's origin"
    if kind in ("change-new", "change-revived"):
        return f"{value} changed state since the last snapshot; inspect it before others re-scan it"
    return f"the surface {value} warrants a closer look"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _resolve_run(target: str, runs_root: Path) -> Run:
    return Run(runs_root, target)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["status", "list", "authorise", "scope", "gather", "hypothesise", "gate", "verify"])
    parser.add_argument("target", nargs="?")
    parser.add_argument("--runs", type=Path, default=DEFAULT_RUNS)
    parser.add_argument("--js", type=Path, action="append", default=[], help="JavaScript/JSON artefact (repeatable)")
    parser.add_argument("--scope-file", type=Path, help="authorization JSON for the 'authorise' command")
    parser.add_argument("--boundary", help="name the query-construction boundary crossed")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.command == "list":
        if not args.runs.is_dir():
            print(f"no runs yet ({args.runs})")
            return 0
        for entry in sorted(p for p in args.runs.iterdir() if p.is_dir()):
            print(f"  {entry.name}")
        return 0

    if not args.target:
        parser.error("this command needs a target")

    run = _resolve_run(args.target, args.runs)

    if args.command == "status":
        status = run.status()
        if args.json:
            print(json.dumps(status, indent=2))
        else:
            print(f"run: {status['target']}\ndir: {status['dir']}\n")
            for phase, info in status["phases"].items():
                mark = "yes" if info["present"] else " - "
                print(f"  [{mark}] {phase:<14} {info['artifact']}")
        return 0

    if args.command == "authorise":
        if not args.scope_file or not args.scope_file.is_file():
            print("error: --scope-file is required and must be an existing JSON file", file=sys.stderr)
            return 2
        try:
            raw = json.loads(args.scope_file.read_text(encoding="utf-8"))
            auth = G.Authorization(**raw)
        except (json.JSONDecodeError, TypeError) as exc:
            print(f"error: could not read the authorization record: {exc}", file=sys.stderr)
            return 2
        result = run.authorise(auth)
        run.save_provenance()
        print(result)
        if not result.ok:
            print("\nThe record is stored but incomplete. Gathering stays blocked until it is fixed.")
        return 0 if result.ok else 1

    if args.command == "scope":
        auth = run.authorization()
        if not auth:
            print("no authorization recorded for this run")
            return 1
        result = G.ScopeGate(auth).check()
        print(f"program {auth.program!r}  policy {auth.policy_url} (read {auth.policy_seen})")
        print(f"in scope:     {', '.join(auth.in_scope) or '(none)'}")
        print(f"out of scope: {', '.join(auth.out_of_scope) or '(none)'}")
        print(result)
        return 0 if result.passed else 1

    if args.command == "gather":
        texts: list[tuple[str, str]] = []
        for path in args.js:
            if not path.is_file():
                print(f"warning: {path} not found", file=sys.stderr)
                continue
            texts.append((str(path), path.read_text(encoding="utf-8", errors="replace")))
        result = run.gather(js_texts=texts)
        run.save_provenance()
        print(result)
        return 0 if result.ok else 1

    if args.command == "hypothesise":
        result = run.hypothesise()
        run.save_provenance()
        print(result)
        return 0 if result.ok else 1

    if args.command == "gate":
        result = run.gate(boundary=args.boundary)
        run.save_provenance()
        print(result)
        return 0 if result.ok else 1

    if args.command == "verify":
        ok, detail = run.chain.verify()
        print(f"provenance: {'ok' if ok else 'FAILED'} - {detail}")
        return 0 if ok else 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
