"""Platform report emitters.

Renders one finding into the section structure each bounty platform expects:
HackerOne, Bugcrowd, Intigriti, Immunefi, and a platform-neutral generic form.

Two rules are enforced rather than merely documented:

* **Severity must follow the metrics.** When a CVSS vector is supplied the
  severity label is derived from it, and a mismatch is a validation error. This
  is the mechanised form of "never claim a vector you have not validated".
* **A report states only what was demonstrated.** The renderer has no field for
  speculative impact. :class:`~gates.TriageGate` additionally rejects
  theoretical phrasing in the prose.

Nothing here submits anything. These functions produce text for a human to
review and post.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cvss import CvssError, score as cvss_score  # noqa: E402
from evidence import InputRole  # noqa: E402

__all__ = ["Finding", "PLATFORMS", "render", "validate"]

PLATFORMS = ("hackerone", "bugcrowd", "intigriti", "immunefi", "generic")

#: Bugcrowd priority bands.
_PRIORITY = {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4", "None": "P5"}

#: Convenience defaults for the classes this framework targets.
_VRT_DEFAULTS = {
    "sql injection": "Server-Side Injection > SQL Injection",
    "sqli": "Server-Side Injection > SQL Injection",
    "nosql injection": "Server-Side Injection > NoSQL Injection",
    "second-order sql injection": "Server-Side Injection > SQL Injection",
}


@dataclass
class Finding:
    """One reportable finding.

    ``boundary`` is mandatory: it names the specific query-construction seam the
    input crossed. Without it a report is indistinguishable from a scanner dump.
    """

    title: str
    target: str
    endpoint: str
    parameter: str
    role: InputRole
    bug_class: str
    boundary: str
    prerequisites: str
    steps: list[str]
    payload: str
    control: str
    expected: str
    observed: str
    impact: str
    remediation: str
    cvss_vector: str | None = None
    severity: str | None = None
    vrt_category: str | None = None
    references: list[str] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)
    tech_stack: str | None = None
    immunefi_type: str | None = None
    immunefi_classification: str | None = None
    contract_address: str | None = None
    protocol_name: str | None = None
    supporting_material: list[str] = field(default_factory=list)

    def resolved_severity(self) -> str:
        """Severity from the vector when present, else the stated label."""
        if self.cvss_vector:
            try:
                return cvss_score(self.cvss_vector).severity
            except CvssError:
                pass
        return self.severity or "Unrated"

    def score(self) -> float | None:
        if not self.cvss_vector:
            return None
        try:
            return cvss_score(self.cvss_vector).base_score
        except CvssError:
            return None

    def resolved_vrt(self) -> str:
        if self.vrt_category:
            return self.vrt_category
        return _VRT_DEFAULTS.get(self.bug_class.strip().lower(), "Server-Side Injection > SQL Injection")


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


def validate(finding: Finding, platform: str) -> list[str]:
    """Return a list of blocking problems for this platform."""
    problems: list[str] = []

    if platform not in PLATFORMS:
        return [f"unknown platform {platform!r}; expected one of {', '.join(PLATFORMS)}"]

    for name in ("title", "target", "endpoint", "parameter", "bug_class", "boundary",
                 "prerequisites", "payload", "control", "expected", "observed",
                 "impact", "remediation"):
        value = getattr(finding, name)
        if not value or not str(value).strip():
            problems.append(f"missing required field: {name}")

    if not finding.steps:
        problems.append("missing required field: steps")
    elif len(finding.steps) < 2:
        problems.append("steps must have at least two entries (setup and the triggering request)")

    if finding.cvss_vector:
        try:
            computed = cvss_score(finding.cvss_vector)
        except CvssError as exc:
            problems.append(f"invalid CVSS vector: {exc}")
        else:
            if finding.severity and finding.severity.strip().lower() != computed.severity.lower():
                problems.append(
                    f"stated severity {finding.severity!r} disagrees with the vector, "
                    f"which scores {computed.base_score:.1f} ({computed.severity})"
                )
    elif finding.severity:
        problems.append(
            "severity stated without a CVSS vector; supply metrics so a triager can reproduce the score"
        )

    if platform == "immunefi":
        for name in ("immunefi_type", "tech_stack"):
            if not getattr(finding, name):
                problems.append(f"immunefi requires: {name}")
    if platform == "intigriti" and not finding.cvss_vector:
        problems.append("intigriti expects a CVSS 3.1 vector")
    if platform == "bugcrowd" and not finding.resolved_vrt():
        problems.append("bugcrowd requires a VRT category")

    if not finding.references:
        problems.append("no references; cite the fingerprinted version, the CVE/advisory, or the program scope page")

    return problems


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def _kv(label: str, value: Any) -> str:
    return f"**{label}:** {value}"


def render(finding: Finding, platform: str = "generic", *, strict: bool = True) -> str:
    """Render ``finding`` for ``platform``.

    With ``strict`` (the default) a validation failure raises, so an incomplete
    report cannot be emitted by accident.
    """
    if platform not in PLATFORMS:
        raise ValueError(f"unknown platform {platform!r}; expected one of {', '.join(PLATFORMS)}")

    problems = validate(finding, platform)
    if problems and strict:
        raise ValueError(
            f"finding does not satisfy the {platform} requirements:\n  - " + "\n  - ".join(problems)
        )

    severity = finding.resolved_severity()
    score = finding.score()
    score_text = f"{score:.1f}" if score is not None else "not scored"

    header = [
        f"# {finding.title}",
        "",
        _kv("Severity", f"{severity} ({score_text})"),
    ]
    if finding.cvss_vector:
        header.append(_kv("CVSS", f"`{finding.cvss_vector}`"))
    header.append(_kv("Affected asset", finding.target))
    header.append(_kv("Endpoint", f"`{finding.endpoint}`"))
    header.append(_kv("Parameter", f"`{finding.parameter}` ({finding.role.value} role)"))
    header.append(_kv("Class", finding.bug_class))

    repro = [
        "## Steps to reproduce",
        "",
        _kv("Prerequisites", finding.prerequisites),
        "",
        *[f"{i}. {step}" for i, step in enumerate(finding.steps, start=1)],
        "",
        "### Payload (test arm)",
        "",
        "```",
        finding.payload,
        "```",
        "",
        "### Control (null variant)",
        "",
        "```",
        finding.control,
        "```",
    ]

    body = [
        "## Query-construction boundary crossed",
        "",
        finding.boundary,
        "",
        "## Expected vs observed",
        "",
        _kv("Expected", finding.expected),
        "",
        _kv("Observed", finding.observed),
        "",
        "## Impact",
        "",
        finding.impact,
        "",
        "## Remediation",
        "",
        finding.remediation,
    ]

    tail: list[str] = []
    if finding.references:
        tail += ["", "## References", "", *[f"- {r}" for r in finding.references]]
    if finding.supporting_material:
        tail += ["", "## Supporting material", "", *[f"- {s}" for s in finding.supporting_material]]
    if finding.attachments:
        tail += ["", "## Attachments", "", *[f"- {a}" for a in finding.attachments]]

    if platform == "hackerone":
        return "\n".join(
            ["## Summary", "", finding.title, "", "## Vulnerability details", "", *header[2:],
             "", *repro, "", *body, *tail, ""]
        )

    if platform == "bugcrowd":
        return "\n".join(
            [
                f"# {finding.title}", "",
                _kv("VRT category", finding.resolved_vrt()),
                _kv("Priority", _PRIORITY.get(severity, "P5")),
                _kv("Asset", finding.target), "",
                "## Description", "", finding.title, "",
                *repro, "", *body,
                _kv("CVSS vector", f"`{finding.cvss_vector or 'not supplied'}`"),
                *tail, "",
            ]
        )

    if platform == "intigriti":
        return "\n".join(
            [
                f"# {finding.title}", "",
                _kv("Severity", severity),
                _kv("Affected URL", f"{finding.target}{finding.endpoint}"), "",
                "## Description", "", finding.title, "",
                "## Reproduction steps", "", *repro[3:], "",
                *body,
                _kv("CVSS 3.1", f"`{finding.cvss_vector or 'not supplied'}`"),
                "",
                "## Suggested fix", "", finding.remediation,
                *tail, "",
            ]
        )

    if platform == "immunefi":
        return "\n".join(
            [
                f"# {finding.title}", "",
                _kv("Severity", severity),
                _kv("Type", finding.immunefi_type or ""),
                _kv("Classification", finding.immunefi_classification or ""),
                _kv("Tech stack", finding.tech_stack or ""),
                _kv("Contract address", finding.contract_address or "n/a"),
                _kv("Protocol", finding.protocol_name or "n/a"), "",
                "## Description", "", finding.title, "",
                "## Attack scenario", "", *repro, "",
                *body,
                "## Recommended fix", "", finding.remediation,
                *tail, "",
            ]
        )

    # generic
    return "\n".join(
        [
            "# Finding report", "",
            _kv("Target", finding.target),
            _kv("Class", finding.bug_class),
            "",
            "## Summary", "",
            f"| Field | Value |", f"| --- | --- |",
            f"| Severity | {severity} |",
            f"| CVSS base | {score_text} |",
            f"| Endpoint | `{finding.endpoint}` |",
            f"| Parameter | `{finding.parameter}` |",
            "",
            *header[2:], "",
            *repro, "", *body, *tail, "",
        ]
    )


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render a finding JSON file for a bounty platform.")
    parser.add_argument("finding", type=Path, help="finding JSON file")
    parser.add_argument("--platform", default="generic", choices=PLATFORMS)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--check", action="store_true", help="validate only; print problems and exit non-zero")
    args = parser.parse_args(argv)

    raw = json.loads(args.finding.read_text(encoding="utf-8"))
    raw["role"] = InputRole(raw.get("role", "unknown"))
    finding = Finding(**raw)

    problems = validate(finding, args.platform)
    if args.check:
        if problems:
            print(f"{len(problems)} problem(s):")
            for p in problems:
                print(f"  - {p}")
            return 1
        print(f"finding satisfies the {args.platform} requirements")
        return 0

    try:
        text = render(finding, args.platform, strict=False)
    except ValueError as exc:
        print(f"error: {exc}")
        return 2

    if problems:
        print(f"warning: {len(problems)} unmet requirement(s):", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
