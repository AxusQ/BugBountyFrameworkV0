"""Detect competing skills that would fight over the same request.

Two distinct problems, both real:

* **Name collisions** — two roots offer the same skill name. The DSH registry
  resolves these by root rank and the loser vanishes. :mod:`skillreg` already
  computes this; this tool reports it in catalogue terms.
* **Trigger collisions** — two *differently named* skills whose descriptions
  claim the same request. Name uniqueness does not prevent this, and it is the
  failure mode the source corpus documents: it added explicit negative triggers
  ("Do not use for X - use `other-skill`") precisely because two skills
  otherwise compete for one request.

Trigger collisions are found by scoring description overlap. The score is a
weighted Jaccard over normalised content tokens, with domain-specific weight
given to the technology and entry-point vocabulary that actually drives skill
selection (a shared "sqlmap" matters far more than a shared "the").

Usage:
    python tools/detect_collisions.py [--threshold 0.42] [--top 25] [--json]
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from itertools import combinations
from pathlib import Path
from typing import Iterable, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))
import skillreg as sr  # noqa: E402
from build_index import FRAMEWORK_ROOT, load_sources  # noqa: E402

#: Tokens too common to signal anything about which skill a request wants.
STOPWORDS = frozenset(
    """
    a an the and or of to in for on with by from as is are be been being it its this that these those
    you your use used uses using when during while into at into over under about across after before
    skill skills tool tools task tasks perform performs performing conduct conducting carry out
    test testing assess assessing assessment evaluate evaluating check checking verify verifying
    identify identifying detect detecting detection find finding discover discovering
    guide guides guide to how instructions procedure procedures step steps method methods approach
    workflow workflows process processes technique techniques provide provides including include
    such also can may should must will would enable enables allow allows help helps support supports
    against within without between each other others both all any some more most less least
    """.split()
)

#: Vocabulary that genuinely drives selection in this domain.
WEIGHTED_TERMS = {
    # technologies / products
    "sqlmap": 4.0, "sqlite": 3.0, "postgres": 4.0, "postgresql": 4.0, "mysql": 4.0,
    "mssql": 4.0, "oracle": 3.0, "nosql": 3.0, "mongodb": 3.0, "graphql": 3.5,
    "django": 3.5, "rails": 3.5, "laravel": 3.0, "hibernate": 3.0, "typeorm": 3.5,
    "sequelize": 3.5, "prisma": 3.0, "supabase": 3.0, "postgrest": 3.5, "n8n": 3.0,
    "burpsuite": 2.5, "burp": 2.5, "zap": 2.5, "waf": 3.5, "orm": 3.5,
    # artefacts / entry points
    "injection": 3.0, "sqli": 4.0, "sql": 3.5, "query": 2.5, "identifier": 3.0,
    "parameter": 2.0, "header": 2.0, "cookie": 2.0, "endpoint": 2.0, "api": 2.0,
    "second-order": 4.0, "blind": 3.0, "boolean": 2.5, "timing": 2.5, "out-of-band": 3.0,
    "payload": 2.5, "oracle": 2.5, "exploit": 2.0, "exploitation": 2.0,
    # bug-bounty specific
    "bounty": 2.5, "report": 2.0, "triage": 2.5, "scope": 2.5, "duplicate": 2.5,
    "severity": 2.0, "cvss": 2.5, "impact": 2.5,
}

TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9+.#_-]*")


def tokenize(text: str) -> Counter[str]:
    """Normalised weighted token counts for a description."""
    lowered = text.lower()
    tokens = TOKEN_RE.findall(lowered)
    counts: Counter[str] = Counter()
    for token in tokens:
        if len(token) < 3 or token in STOPWORDS:
            continue
        counts[token] += 1.0
    # Fold simple plural forms so "reports"/"report" do not look distinct.
    for token in list(counts):
        if token.endswith("s") and len(token) > 4 and token[:-1] in counts:
            counts[token[:-1]] += counts.pop(token)
    return counts


def weighted_jaccard(a: Counter[str], b: Counter[str]) -> float:
    """Weighted Jaccard similarity over two token bags."""
    if not a or not b:
        return 0.0

    def weight(token: str, count: float) -> float:
        return count * WEIGHTED_TERMS.get(token, 1.0)

    keys = set(a) | set(b)
    inter = sum(min(weight(t, a.get(t, 0.0)), weight(t, b.get(t, 0.0))) for t in keys)
    union = sum(max(weight(t, a.get(t, 0.0)), weight(t, b.get(t, 0.0))) for t in keys)
    return inter / union if union else 0.0


def shared_salient(a: Counter[str], b: Counter[str], limit: int = 8) -> list[str]:
    """The highest-signal tokens two descriptions share, for human review."""
    shared = set(a) & set(b)
    ranked = sorted(shared, key=lambda t: (-WEIGHTED_TERMS.get(t, 1.0), t))
    return ranked[:limit]


def negative_triggers(body: str, description: str) -> list[str]:
    """Extract explicit 'do not use' disclaimers already present."""
    text = f"{description}\n{body}"
    out: list[str] = []
    for match in re.finditer(r"(?i)\b(?:do not use|don't use|not for use)\b([^.\n]{0,160})", text):
        out.append(" ".join(match.group(0).split()))
    return out


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, default=FRAMEWORK_ROOT / "corpus" / "sources.yaml")
    parser.add_argument("--threshold", type=float, default=0.42, help="similarity at which two skills are reported as competing")
    parser.add_argument("--top", type=int, default=25, help="max competing pairs to print")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    sources = load_sources(args.config)
    roots = [sr.SkillRoot(s["label"], s["path"], s["rank"]) for s in sources]
    scan = sr.scan_roots(roots)
    catalog, name_collisions = sr.merge_catalog(scan.skills)

    skills = [catalog[n] for n in sorted(catalog)]
    tokens = {s.name: tokenize(f"{s.description} {s.when_to_use or ''}") for s in skills}

    pairs: list[dict[str, Any]] = []
    for a, b in combinations(skills, 2):
        score = weighted_jaccard(tokens[a.name], tokens[b.name])
        if score >= args.threshold:
            pairs.append(
                {
                    "a": a.name,
                    "b": b.name,
                    "score": round(score, 4),
                    "shared": shared_salient(tokens[a.name], tokens[b.name]),
                    "a_disclaims": negative_triggers(a.body, a.description),
                    "b_disclaims": negative_triggers(b.body, b.description),
                }
            )
    pairs.sort(key=lambda p: -p["score"])

    unreconciled = [p for p in pairs if not (p["a_disclaims"] or p["b_disclaims"])]

    payload = {
        "skills_scanned": len(skills),
        "threshold": args.threshold,
        "name_collisions": [c.as_dict() for c in name_collisions],
        "competing_pairs": len(pairs),
        "unreconciled_pairs": len(unreconciled),
        "pairs": pairs[: args.top],
    }

    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    print(f"scanned {len(skills)} skills from {len(sources)} source(s)")
    print(f"name collisions: {len(name_collisions)}")
    for c in name_collisions:
        print(f"  {c.name}: kept={c.winner.root_label} shadowed={[s.root_label for s in c.losers]}")

    print(
        f"\ntrigger collisions at >= {args.threshold:.2f}: {len(pairs)} "
        f"({len(unreconciled)} with no 'do not use' disclaimer on either side)"
    )
    for p in pairs[: args.top]:
        flag = "" if (p["a_disclaims"] or p["b_disclaims"]) else "  <-- unreconciled"
        print(f"\n  {p['score']:.3f}  {p['a']}  vs  {p['b']}{flag}")
        print(f"          shared signals: {', '.join(p['shared'])}")
        for side, disclaimers in (("a", p["a_disclaims"]), ("b", p["b_disclaims"])):
            for d in disclaimers[:2]:
                print(f"          {side} disclaims: {d}")
    if len(pairs) > args.top:
        print(f"\n  ... and {len(pairs) - args.top} more pair(s); raise --top to see them")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
