"""Build a merged skill index across every configured source.

Reads ``corpus/sources.yaml``, scans each source root with :mod:`skillreg`,
resolves collisions by rank, and writes ``index.json`` plus a human-readable
report of what was found and what was rejected.

Usage:
    python tools/build_index.py [--config corpus/sources.yaml] [--out index.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import skillreg as sr  # noqa: E402

FRAMEWORK_ROOT = Path(__file__).resolve().parent.parent


def load_sources(config_path: Path) -> list[dict[str, Any]]:
    """Load and normalise the source list, resolving relative paths."""
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    sources = raw.get("sources") or []
    if not isinstance(sources, list):
        raise SystemExit(f"{config_path}: 'sources' must be a list")

    base = config_path.parent
    out: list[dict[str, Any]] = []
    for i, entry in enumerate(sources):
        if not isinstance(entry, dict) or "path" not in entry:
            raise SystemExit(f"{config_path}: source #{i} needs a 'path'")
        raw_path = str(entry["path"]).replace("\\", "/")
        if raw_path.startswith("~"):
            path = Path(raw_path).expanduser()
        else:
            path = (base / raw_path).resolve()
        out.append(
            {
                "label": entry.get("label") or f"source{i}",
                "rank": int(entry.get("rank", 100 + i)),
                "path": path,
                "license": entry.get("license", "unknown"),
                "origin": entry.get("origin", ""),
                "role": entry.get("role", ""),
                "reusable": entry.get("reusable", "unknown"),
            }
        )
    return out


def _relativise_diagnostic(entry: dict[str, Any]) -> dict[str, Any]:
    """Strip absolute paths from a diagnostic before it is persisted."""
    out = dict(entry)
    if out.get("path"):
        out["path"] = _relative(str(out["path"]))
    return out


def _relative(path_str: str) -> str:
    """Express a path relative to the framework root when it lies inside it.

    index.json is committed, so absolute paths would embed this machine's
    directory layout, go stale the moment the repository is cloned elsewhere,
    and leak the local username. Relative POSIX-style paths are stable across
    hosts; a path outside the framework root (such as a user skill root) is left
    absolute because there is no meaningful relative form.
    """
    try:
        candidate = Path(path_str)
        resolved = candidate.resolve()
    except (OSError, ValueError):
        return path_str

    for base in (FRAMEWORK_ROOT, FRAMEWORK_ROOT.parent):
        try:
            return resolved.relative_to(base.resolve()).as_posix()
        except ValueError:
            continue

    # A home-relative path is still portable if it names no local username.
    try:
        return "~/" + resolved.relative_to(Path.home()).as_posix()
    except ValueError:
        return path_str


def build(config_path: Path) -> tuple[sr.ScanResult, dict[str, sr.Skill], list[sr.Collision], list[dict[str, Any]]]:
    sources = load_sources(config_path)
    roots = [sr.SkillRoot(s["label"], s["path"], s["rank"]) for s in sources]
    result = sr.scan_roots(roots)
    catalog, collisions = sr.merge_catalog(result.skills)

    per_source: list[dict[str, Any]] = []
    for s in sources:
        members = [sk for sk in result.skills if sk.root_label == s["label"]]
        shadowed = sorted(
            c.name for c in collisions for loser in c.losers if loser.root_label == s["label"]
        )
        per_source.append(
            {
                "label": s["label"],
                "rank": s["rank"],
                "path": _relative(str(s["path"])),
                "exists": s["path"].exists(),
                "license": s["license"],
                "origin": s["origin"],
                "role": s["role"],
                "skills_admitted": len(members),
                "winning": sum(1 for sk in members if catalog.get(sk.name) is sk),
                "shadowed": shadowed,
            }
        )
    return result, catalog, collisions, per_source


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, default=FRAMEWORK_ROOT / "corpus" / "sources.yaml")
    parser.add_argument("--out", type=Path, default=FRAMEWORK_ROOT / "index.json")
    parser.add_argument("--json", action="store_true", help="print the summary as JSON")
    args = parser.parse_args(argv)

    if not args.config.is_file():
        raise SystemExit(f"config not found: {args.config}")

    result, catalog, collisions, per_source = build(args.config)

    # Relativise every emitted skill path too, so the committed index carries no
    # absolute local paths.
    summaries: list[dict[str, Any]] = []
    for name in sorted(catalog):
        entry = catalog[name].summary()
        entry["path"] = _relative(str(entry["path"]))
        summaries.append(entry)

    payload = {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "framework": "bug-bounty-agent-framework",
        "total_skills": len(catalog),
        "total_candidates": len(result.skills),
        "sources": per_source,
        "collisions": [c.as_dict() for c in collisions],
        "rejected": [_relativise_diagnostic(d.as_dict()) for d in result.errors],
        "diagnostics": [_relativise_diagnostic(d.as_dict()) for d in result.diagnostics],
        "skills": summaries,
    }

    args.out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    summary = {
        "out": str(args.out),
        "total_skills": len(catalog),
        "candidates": len(result.skills),
        "collisions": len(collisions),
        "rejected": len(result.errors),
        "warnings": len(result.warnings),
        "sources": per_source,
    }

    if args.json:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return 0

    print(f"index written: {args.out}")
    print(f"candidates {len(result.skills)} -> catalog {len(catalog)}\n")
    print(f"{'source':<10}{'rank':>5}  {'admitted':>9}{'winning':>9}{'shadowed':>9}  license")
    for s in per_source:
        state = "" if s["exists"] else "  (MISSING)"
        print(
            f"{s['label']:<10}{s['rank']:>5}  {s['skills_admitted']:>9}{s['winning']:>9}"
            f"{len(s['shadowed']):>9}  {s['license']}{state}"
        )
    if collisions:
        print(f"\ncollisions ({len(collisions)}) — lowest rank wins:")
        for c in collisions:
            print(f"  {c.name}: kept={c.winner.root_label} shadowed={[s.root_label for s in c.losers]}")
    if result.errors:
        print(f"\nrejected ({len(result.errors)}):")
        for d in result.errors:
            print(f"  {d}")
    if result.warnings:
        print(f"\nwarnings ({len(result.warnings)}):")
        for d in result.warnings[:20]:
            print(f"  {d}")
        if len(result.warnings) > 20:
            print(f"  ... and {len(result.warnings) - 20} more")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
