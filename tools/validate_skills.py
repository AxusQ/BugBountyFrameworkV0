"""Lint skills against the agentskills/DSH contract plus framework conventions.

Two layers:

1. **Contract** — delegated to :mod:`skillreg` (kebab-case name, required
   description, strict invocation booleans, one-level discovery). A violation
   here means DSH would drop the skill silently, so it is a hard error.
2. **Quality** — description and body linting that the contract does not cover.
   These are the failure modes observed in the source corpus: descriptions
   truncated to one line, missing activation cues, duplicate descriptions,
   placeholders shipped to production, and thin bodies that describe a topic
   instead of a procedure.

Exit code is non-zero when any error is found, so this doubles as a CI gate.

Usage:
    python tools/validate_skills.py [roots...] [--min-severity warning] [--json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))
import skillreg as sr  # noqa: E402

FRAMEWORK_ROOT = Path(__file__).resolve().parent.parent

#: Descriptions are rendered into a capped catalog; keep them bounded.
DESC_MIN = 60
DESC_MAX = 1024

#: A body shorter than this is usually a topic summary, not a procedure.
BODY_MIN = 400

#: Cues that a description states *when* to activate, not just *what* it does.
ACTIVATION_CUES = (
    "use when",
    "use during",
    "use for",
    "use whenever",
    "use this",
    "activate",
    "invoke when",
    "trigger",
)

#: Always a defect, wherever they appear.
PLACEHOLDER_ALWAYS = (
    re.compile(r"\bTODO\b"),
    re.compile(r"\bTBD\b"),
    re.compile(r"\bFIXME\b"),
    re.compile(r"\bXXX\b"),
    re.compile(r"\bYOUR_[A-Z_]+\b"),
    re.compile(r"\bLorem ipsum\b", re.IGNORECASE),
)

#: Angle-bracket meta-variables. These are legitimate inside code, where they
#: document a CLI argument (``pipeline.py status <target>``), and suspicious in
#: prose, where they usually mark a gap. Anywhere they clearly ask to be filled
#: (``<your-api-key>``) they are a defect regardless of context.
PLACEHOLDER_META = re.compile(r"<([a-z][a-z0-9 _-]{1,40})>")
UNFILLED_MARKERS = (
    "your", "insert", "placeholder", "replace", "change", "here",
    "example", "sample", "redacted", "foo", "bar", "baz",
)

#: Regions where an angle-bracket token is documentation rather than a gap.
_CODE_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`[^`\n]+`")


def _code_spans(text: str) -> list[tuple[int, int]]:
    """Character ranges occupied by fenced or inline code."""
    spans = [(m.start(), m.end()) for m in _CODE_FENCE_RE.finditer(text)]
    spans += [(m.start(), m.end()) for m in _INLINE_CODE_RE.finditer(text)]
    return spans


def _in_spans(position: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= position < end for start, end in spans)

#: First-person boilerplate that wastes catalog space.
SELF_REFERENTIAL = (
    re.compile(r"\bI can help\b", re.IGNORECASE),
    re.compile(r"\bthis skill will help you\b", re.IGNORECASE),
    re.compile(r"\bwe will now\b", re.IGNORECASE),
)

HEADING_RE = re.compile(r"^#{1,3} \S", re.MULTILINE)


def lint_skill(skill: sr.Skill) -> list[sr.Diagnostic]:
    """Quality findings for one already-valid skill."""
    out: list[sr.Diagnostic] = []
    path = str(skill.path)

    def add(severity: str, code: str, message: str) -> None:
        out.append(sr.Diagnostic(severity, code, message, path=path, skill=skill.name))

    desc = skill.description

    if len(desc) < DESC_MIN:
        add(
            "warning",
            "desc-too-short",
            f"description is {len(desc)} chars (<{DESC_MIN}); a catalog entry needs enough "
            "text for semantic matching",
        )
    if len(desc) > DESC_MAX:
        add(
            "warning",
            "desc-too-long",
            f"description is {len(desc)} chars (>{DESC_MAX}); the catalog caps long "
            "descriptions, so the tail may never be read",
        )

    lowered = desc.lower()
    if not any(cue in lowered for cue in ACTIVATION_CUES):
        add(
            "warning",
            "desc-no-activation-cue",
            "description never states when to activate (expected phrasing such as "
            "'Use when ...'); semantic auto-invocation depends on it",
        )

    for pattern in SELF_REFERENTIAL:
        if pattern.search(desc):
            add("warning", "desc-self-referential", f"description matches {pattern.pattern!r}; state the capability, not the offer")
            break

    # A description that merely restates the name adds no matching signal.
    name_words = {w for w in re.split(r"[-_ ]+", skill.name.lower()) if len(w) > 2}
    desc_words = {w for w in re.findall(r"[a-z0-9]+", lowered)}
    if name_words and name_words <= desc_words and len(desc_words - name_words) < 8:
        add(
            "info",
            "desc-restates-name",
            "description adds little beyond the skill name; include concrete technologies, "
            "entry points, or artefacts for better matching",
        )

    body = skill.body
    if not HEADING_RE.search(body):
        add("warning", "body-no-headings", "body has no markdown headings; a procedure should be navigable")
    if len(body.strip()) < BODY_MIN:
        add(
            "warning",
            "body-too-thin",
            f"body is {len(body.strip())} chars (<{BODY_MIN}); it may describe a topic "
            "rather than a procedure an agent can execute end to end",
        )
    for pattern in PLACEHOLDER_ALWAYS:
        match = pattern.search(body)
        if match:
            add("error", "body-placeholder", f"unfilled placeholder {match.group(0)!r} in body")
            break
    else:
        spans = _code_spans(body)
        for match in PLACEHOLDER_META.finditer(body):
            inner = match.group(1)
            if any(marker in inner for marker in UNFILLED_MARKERS) or not _in_spans(match.start(), spans):
                add(
                    "error",
                    "body-placeholder",
                    f"unfilled placeholder {match.group(0)!r} in body",
                )
                break

    if not skill.license and skill.root_label.startswith(("framework", "arg", "custom")):
        add(
            "info",
            "no-license-field",
            "no 'license' frontmatter field; recommended so downstream reuse is unambiguous",
        )

    return out


def lint_duplicates(skills: Sequence[sr.Skill]) -> list[sr.Diagnostic]:
    """Exact duplicate descriptions across distinct skills."""
    out: list[sr.Diagnostic] = []
    seen: dict[str, list[sr.Skill]] = defaultdict(list)
    for skill in skills:
        seen[" ".join(skill.description.lower().split())].append(skill)
    for _, group in seen.items():
        if len(group) > 1:
            names = sorted(s.name for s in group)
            out.append(
                sr.Diagnostic(
                    "error",
                    "duplicate-description",
                    f"{len(group)} skills share an identical description: {', '.join(names)}; "
                    "the catalog cannot distinguish them",
                    path=str(group[0].path),
                    skill=names[0],
                )
            )
    return out


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "roots",
        nargs="*",
        type=Path,
        default=[FRAMEWORK_ROOT / "skills"],
        help="skill roots to lint (default: the framework's own skills)",
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--min-severity", default="info", choices=["error", "warning", "info"])
    parser.add_argument("--quiet-info", action="store_true", help="hide info-level findings")
    args = parser.parse_args(argv)

    roots = [sr.SkillRoot(f"arg{i}", Path(p).resolve(), sr.DSH_RANK_ORDER.get("project-dsh", 100) + i) for i, p in enumerate(args.roots)]
    scan = sr.scan_roots(roots)
    catalog, _ = sr.merge_catalog(scan.skills)

    findings = list(scan.diagnostics) + lint_duplicates(scan.skills)
    for skill in scan.skills:
        findings.extend(lint_skill(skill))

    if args.quiet_info:
        findings = [f for f in findings if f.severity != "info"]
    if args.min_severity != "info":
        allowed = {"error"} if args.min_severity == "error" else {"error", "warning"}
        findings = [f for f in findings if f.severity in allowed]

    findings.sort(key=lambda d: ({"error": 0, "warning": 1, "info": 2}[d.severity], d.code, d.path or ""))

    counts = {"error": 0, "warning": 0, "info": 0}
    for f in findings:
        counts[f.severity] += 1

    if args.json:
        print(
            json.dumps(
                {
                    "roots": [str(r.path) for r in roots],
                    "skills_checked": len(catalog),
                    "counts": counts,
                    "findings": [f.as_dict() for f in findings],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 1 if counts["error"] else 0

    print(f"checked {len(catalog)} skill(s) across {len(roots)} root(s)")
    print(f"errors {counts['error']}   warnings {counts['warning']}   info {counts['info']}\n")
    for f in findings:
        print(f"  {f}")
    if not findings:
        print("  clean")
    return 1 if counts["error"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
