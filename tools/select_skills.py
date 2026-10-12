"""Select the skills relevant to a task from the merged catalog.

The corpus is 800+ skills; loading the wrong ones wastes context and loading all
of them is impossible. This tool scores every catalog entry against a task
description and returns a ranked shortlist with the reason each skill was
chosen, so the selection is reviewable rather than opaque.

Scoring combines three signals:

* **Lexical overlap** between the task and the skill's name, description, and
  ``whenToUse``, weighted so that discriminating domain vocabulary counts for
  more than common words.
* **Negative triggers.** A skill that explicitly disclaims the task ("do not use
  for X") is demoted or excluded. The corpus documents these as the mechanism
  that stops two skills competing for one request, so ignoring them would
  reintroduce exactly the collision they were added to fix.
* **Role hints.** Values-role versus structure-role vocabulary is weighted
  differently, because "sort parameter" and "username parameter" should not
  retrieve the same skill.

Usage:
    python tools/select_skills.py "authorised SQLi test of a Django sort parameter"
    python tools/select_skills.py --class sqli --top 15
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))
import skillreg as sr  # noqa: E402
from build_index import FRAMEWORK_ROOT, load_sources  # noqa: E402
from detect_collisions import STOPWORDS, WEIGHTED_TERMS, tokenize  # noqa: E402

#: Preset task profiles so common jobs do not need a hand-written sentence.
PROFILES = {
    "sqli": (
        "sql injection sqli injection identifier structure parameter sort order column filter "
        "orm raw query escape hatch second-order blind boolean timing out-of-band waf bypass "
        "postgres mysql mssql oracle django rails typeorm sequelize graphql report triage"
    ),
    "recon": "recon reconnaissance subdomain enumeration fingerprinting technology stack asset discovery osint",
    "report": "report writing triage severity cvss impact remediation evidence submission",
    "recon-sqli": (
        "sql injection recon fingerprinting orm stack sort filter parameter surface inventory "
        "identifier raw query waf detection timing boolean"
    ),
}

NEGATIVE_RE = re.compile(r"(?i)\b(?:do not use|don't use|not for use)\b[^.\n]{0,120}")


@dataclass
class Scored:
    skill: sr.Skill
    score: float
    matched: list[str]
    disclaimed: str | None = None

    def as_dict(self, rank: int) -> dict:
        return {
            "rank": rank,
            "name": self.skill.name,
            "score": round(self.score, 4),
            "root": self.skill.root_label,
            "matched_terms": self.matched,
            "description": self.skill.description,
            "negative_trigger": self.disclaimed,
        }


def _cosine(task: dict[str, float], skill: dict[str, float]) -> float:
    if not task or not skill:
        return 0.0
    shared = set(task) & set(skill)
    if not shared:
        return 0.0
    num = sum(task[t] * skill[t] for t in shared)
    den = math.sqrt(sum(v * v for v in task.values())) * math.sqrt(sum(v * v for v in skill.values()))
    return num / den if den else 0.0


def score_task(
    task: str,
    skills: Iterable[sr.Skill],
    *,
    limit: int = 15,
    respect_negative_triggers: bool = True,
) -> list[Scored]:
    """Rank catalog skills against a task description."""
    task_tokens = tokenize(task)
    if not task_tokens:
        return []

    results: list[Scored] = []
    for skill in skills:
        haystack = " ".join(filter(None, [skill.name.replace("-", " "), skill.description, skill.when_to_use or ""]))
        skill_tokens = tokenize(haystack)

        base = _cosine(task_tokens, skill_tokens)

        # Exact name-token hits are a strong signal.
        name_tokens = set(re.findall(r"[a-z0-9]+", skill.name.lower()))
        hits = sorted(name_tokens & set(task_tokens))
        name_bonus = 0.05 * len(hits)
        weighted_bonus = 0.01 * sum(WEIGHTED_TERMS.get(t, 0.0) for t in (set(skill_tokens) & set(task_tokens)))

        total = base + name_bonus + weighted_bonus
        if total <= 0:
            continue

        disclaimed = None
        if respect_negative_triggers:
            match = NEGATIVE_RE.search(skill.body)
            if match:
                disclaimed = " ".join(match.group(0).split())
                # Only penalise when the disclaimer overlaps the task.
                words = {w for w in re.findall(r"[a-z0-9]+", disclaimed.lower()) if w not in STOPWORDS}
                if words & set(task_tokens):
                    total *= 0.35

        results.append(Scored(skill=skill, score=total, matched=sorted(set(skill_tokens) & set(task_tokens))[:12], disclaimed=disclaimed))

    results.sort(key=lambda s: (-s.score, s.skill.name))
    return results[:limit]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("task", nargs="?", help="free-text task description")
    parser.add_argument("--class", dest="preset", choices=sorted(PROFILES), help="use a preset task profile")
    parser.add_argument("--top", type=int, default=15)
    parser.add_argument("--source", action="append", default=None, help="restrict to a source label (repeatable)")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--config", type=Path, default=FRAMEWORK_ROOT / "corpus" / "sources.yaml")
    args = parser.parse_args(argv)

    if not args.task and not args.preset:
        parser.error("provide a task description or --class")
    task = args.task or PROFILES[args.preset]
    if args.preset and args.task:
        task = f"{args.task} {PROFILES[args.preset]}"

    sources = load_sources(args.config)
    if args.source:
        wanted = {s.lower() for s in args.source}
        sources = [s for s in sources if s["label"].lower() in wanted]
        if not sources:
            parser.error(f"no source matched {sorted(wanted)}")

    roots = [sr.SkillRoot(s["label"], s["path"], s["rank"]) for s in sources]
    scan = sr.scan_roots(roots)
    catalog, _ = sr.merge_catalog(scan.skills)
    skills = [catalog[n] for n in sorted(catalog)]

    ranked = score_task(task, skills, limit=args.top)

    if args.json:
        print(json.dumps({"task": task, "pool": len(skills), "selected": [s.as_dict(i + 1) for i, s in enumerate(ranked)]}, indent=2, ensure_ascii=False))
        return 0

    print(f"pool: {len(skills)} skill(s) from {len(sources)} source(s)")
    print(f"task: {task[:100]}{'...' if len(task) > 100 else ''}\n")
    for i, scored in enumerate(ranked, start=1):
        print(f"{i:2}. {scored.score:.3f}  {scored.skill.name}   [{scored.skill.root_label}]")
        print(f"      {scored.skill.description[:150]}{'...' if len(scored.skill.description) > 150 else ''}")
        if scored.matched:
            print(f"      matched: {', '.join(scored.matched)}")
        if scored.disclaimed:
            print(f"      NOTE disclaims: {scored.disclaimed[:110]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
