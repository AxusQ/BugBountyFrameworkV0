"""Deterministic collectors: code gathers, the agent judges.

This module implements the framework's central cost and correctness principle.
Gathering is repetitive and mechanical, so it is done by deterministic code that
never calls a model. The model is handed a *bounded, ranked, filtered* bundle of
evidence and asked only to adjudicate it.

The economics are the reason. If every discovered host goes through a model,
model usage scales with the size of the scan; if deterministic code filters
first, usage scales with the much smaller number of promising leads. The
correctness benefit matters just as much: a regex that extracts parameter names
from a JavaScript bundle is reproducible, cheap, and reviewable, whereas a model
asked to "find the interesting endpoints" is none of those things and cannot be
regression-tested.

Everything here is offline and pure: text in, structured evidence out. No
network I/O, so every collector is unit-testable and safe to run against a
corpus of saved artefacts.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from evidence import InputRole

__all__ = [
    "ChangeSignal",
    "EvidenceItem",
    "EvidenceBundle",
    "FreshnessRanker",
    "JsSurfaceCollector",
    "SnapshotDiffer",
    "STRUCTURE_PARAMS",
    "SQL_SINK_HINTS",
    "collect",
]

#: Parameter names whose value selects query *structure* rather than a value.
#: These cannot be parameterised by a placeholder, so they are where SQL
#: injection still lives in ORM-era applications. Sourced from the SQLi
#: methodology's inventory vocabulary.
STRUCTURE_PARAMS = frozenset(
    {
        "sort", "order", "orderby", "order_by", "sortby", "sort_by", "sortfield",
        "column", "columns", "field", "fields", "group", "groupby", "group_by",
        "filter", "filters", "operator", "op", "direction", "dir", "asc", "desc",
        "include", "includes", "expand", "select", "where", "having", "distinct",
        "distincton", "aggregate", "agg", "q", "search", "query", "limit",
        "offset", "page", "per_page", "perpage", "size", "top", "skip", "take",
    }
)

#: Substrings in JavaScript that indicate a raw-SQL escape hatch: a place where
#: the framework's parameterisation guarantees stop applying.
SQL_SINK_HINTS = (
    "whereraw", "selectraw", "orderbyraw", "havingraw", "db::raw", "db.raw",
    "queryraw", "executeraw", "rawquery", "createquerybuilder", "extra(",
    "sequelize.literal", "literal(", "knex.raw", "sql`", "sqltemplate",
    "querybuilder", "addselect", "fromraw", "joinraw", "statement(",
    "executesql", "nativequery", "createsqlquery", "session.createsqlquery",
)

#: Template-literal interpolation adjacent to a SQL keyword — the classic
#: modern injection shape.
_TEMPLATE_SQL = re.compile(
    r"(?i)(?:select|where|order\s+by|group\s+by|insert\s+into|update|delete\s+from)"
    r"[^`'\"]{0,80}\$\{[^}]+\}"
)

_PATH_RE = re.compile(r"""(?P<q>['"`])(?P<path>/(?:api|v\d|graphql|rest|admin|internal|_next|services?)[A-Za-z0-9._~/{}\-]*(?:\?[^'"`\s]*)?)(?P=q)""")
_QUERY_PARAM_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_.\-\[\]]{0,40})=")
_PARAMS_OBJ_RE = re.compile(r"(?i)\bparams\s*[:=]\s*\{(?P<body>[^{}]{0,400})\}")
_SET_PARAM_RE = re.compile(r"""(?i)(?:searchParams|params|query)\s*\.\s*(?:set|append|get)\s*\(\s*['"]([A-Za-z_][A-Za-z0-9_.\-]{0,40})['"]""")
_SOURCEMAP_RE = re.compile(r"(?i)(?:sourceMappingURL\s*=\s*|//#\s*sourceMappingURL=)(?P<url>[^\s'\"*]+)")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# Evidence model
# --------------------------------------------------------------------------- #


@dataclass
class EvidenceItem:
    """One deterministic observation about a target's surface.

    ``priority`` is set by the collector, not by a model: it encodes how likely
    the item is to matter for the class being hunted. ``signals`` explains the
    score so a human can audit the ranking.
    """

    kind: str
    target: str
    value: str
    priority: float = 0.0
    signals: list[str] = field(default_factory=list)
    role: InputRole = InputRole.UNKNOWN
    source: str = ""
    raw_ref: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    collected_at: str = field(default_factory=_now)

    def as_dict(self) -> dict[str, Any]:
        d = {
            "kind": self.kind,
            "target": self.target,
            "value": self.value,
            "priority": round(self.priority, 4),
            "signals": self.signals,
            "role": self.role.value,
            "source": self.source,
            "raw_ref": self.raw_ref,
            "collected_at": self.collected_at,
        }
        if self.extra:
            d["extra"] = self.extra
        return d


@dataclass
class EvidenceBundle:
    """A bounded, ranked handoff from collectors to the agent.

    ``max_items`` is enforced because the whole point is to keep model usage
    proportional to promise rather than to scan size. ``truncated`` records what
    was dropped so the filter is visible rather than silent.
    """

    target: str
    items: list[EvidenceItem] = field(default_factory=list)
    max_items: int = 40
    dropped: int = 0
    collector_stats: dict[str, int] = field(default_factory=dict)

    def ranked(self) -> list[EvidenceItem]:
        return sorted(self.items, key=lambda i: (-i.priority, i.kind, i.value))

    def bounded(self) -> list[EvidenceItem]:
        ordered = self.ranked()
        self.dropped = max(0, len(ordered) - self.max_items)
        return ordered[: self.max_items]

    def by_role(self, role: InputRole) -> list[EvidenceItem]:
        return [i for i in self.items if i.role is role]

    def summary(self) -> dict[str, Any]:
        kinds: dict[str, int] = {}
        for item in self.items:
            kinds[item.kind] = kinds.get(item.kind, 0) + 1
        return {
            "target": self.target,
            "total": len(self.items),
            "by_kind": kinds,
            "structure_role": len(self.by_role(InputRole.STRUCTURE)),
            "dropped_by_bound": self.dropped,
            "collectors": self.collector_stats,
        }

    def to_json(self) -> str:
        return json.dumps(
            {
                "target": self.target,
                "summary": self.summary(),
                "items": [i.as_dict() for i in self.bounded()],
            },
            indent=2,
            ensure_ascii=False,
        ) + "\n"


# --------------------------------------------------------------------------- #
# JavaScript surface collector
# --------------------------------------------------------------------------- #


class JsSurfaceCollector:
    """Extract API surface and query-parameter names from JavaScript.

    This is the highest-yield deterministic step for modern SQL injection work.
    Client bundles enumerate the API: paths, parameter names, and often the
    structure-selection parameters (``sort``, ``filter``, ``fields``) that are
    the actual injection surface. A bundle also frequently reveals raw-SQL
    escape hatches by name.

    The collector never guesses: every item records the matched text in
    ``signals`` so a reviewer can confirm the hit in the source.
    """

    name = "js-surface"

    def __init__(self, *, structure_weight: float = 3.0) -> None:
        self.structure_weight = structure_weight

    def collect_text(self, text: str, target: str, *, source: str = "") -> list[EvidenceItem]:
        items: list[EvidenceItem] = []
        lowered = text.lower()

        # 1. API paths.
        seen_paths: set[str] = set()
        for match in _PATH_RE.finditer(text):
            path = match.group("path")
            base = path.split("?", 1)[0]
            if base in seen_paths or len(base) < 4:
                continue
            seen_paths.add(base)
            priority = 1.0
            signals = [f"path literal: {base}"]
            if "admin" in base.lower() or "internal" in base.lower():
                priority += 2.0
                signals.append("privileged-looking segment")
            if "?" in path:
                priority += 0.5
                signals.append("carries a query string in the literal")
            items.append(
                EvidenceItem(
                    kind="api-path", target=target, value=base, priority=priority,
                    signals=signals, source=source or "javascript",
                )
            )

        # 2. Query parameter names, classified by role.
        params: dict[str, set[str]] = {}
        for regex, label in ((_QUERY_PARAM_RE, "query string"), (_SET_PARAM_RE, "searchParams API")):
            for match in regex.finditer(text):
                params.setdefault(match.group(1), set()).add(label)
        for match in _PARAMS_OBJ_RE.finditer(text):
            for key in re.findall(r"['\"]?([A-Za-z_][A-Za-z0-9_]{0,40})['\"]?\s*:", match.group("body")):
                params.setdefault(key, set()).add("params object")

        for name, origins in params.items():
            normalised = name.lower().rstrip("[]")
            is_structure = normalised in STRUCTURE_PARAMS
            role = InputRole.STRUCTURE if is_structure else InputRole.VALUE
            priority = self.structure_weight if is_structure else 0.8
            signals = [f"parameter name from {', '.join(sorted(origins))}"]
            if is_structure:
                signals.append(
                    f"'{name}' looks like a structure selector; identifiers cannot be parameterised, "
                    "so test whether it is mapped to an allowlist"
                )
            items.append(
                EvidenceItem(
                    kind="param", target=target, value=name, priority=priority,
                    signals=signals, role=role, source=source or "javascript",
                )
            )

        # 3. Raw-SQL escape hatches.
        for hint in SQL_SINK_HINTS:
            index = lowered.find(hint.lower())
            if index >= 0:
                excerpt = " ".join(text[max(0, index - 40) : index + len(hint) + 40].split())
                items.append(
                    EvidenceItem(
                        kind="sql-sink-hint", target=target, value=hint, priority=4.0,
                        signals=[f"raw-query API referenced: ...{excerpt}..."],
                        role=InputRole.STRUCTURE, source=source or "javascript",
                    )
                )

        # 4. Template-literal interpolation next to a SQL keyword.
        for match in _TEMPLATE_SQL.finditer(text):
            excerpt = " ".join(match.group(0).split())
            items.append(
                EvidenceItem(
                    kind="template-sql", target=target, value=excerpt[:160], priority=5.0,
                    signals=["SQL keyword adjacent to a template-literal interpolation"],
                    role=InputRole.STRUCTURE, source=source or "javascript",
                )
            )

        # 5. Source maps.
        for match in _SOURCEMAP_RE.finditer(text):
            items.append(
                EvidenceItem(
                    kind="sourcemap", target=target, value=match.group("url"), priority=2.5,
                    signals=["source map referenced; original sources may be recoverable"],
                    source=source or "javascript",
                )
            )

        return items

    def collect_file(self, path: Path, target: str) -> list[EvidenceItem]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        return self.collect_text(text, target, source=str(path))


# --------------------------------------------------------------------------- #
# Snapshot differ: change signals become leads
# --------------------------------------------------------------------------- #


@dataclass
class ChangeSignal:
    """A difference between two observations of the same target over time.

    ``NEW`` and ``REVIVED`` are the valuable ones: a newly appearing asset has
    usually been tested by nobody, and a host that went from unreachable to
    reachable has just changed state, which is exactly when misconfiguration
    appears. ``DISAPPEARED`` matters for cleanup, not for hunting.
    """

    kind: str  # NEW | REVIVED | DISAPPEARED
    target: str
    value: str
    priority: float
    signals: list[str] = field(default_factory=list)

    def as_evidence(self, role: InputRole = InputRole.UNKNOWN) -> EvidenceItem:
        return EvidenceItem(
            kind=f"change-{self.kind.lower()}",
            target=self.target,
            value=self.value,
            priority=self.priority,
            signals=self.signals,
            role=role,
            source="snapshot-diff",
        )


class SnapshotDiffer:
    """Diff two snapshots and emit change signals.

    ``previous`` maps a target to the set of assets seen last time. A host
    present now but absent before is ``NEW``; one previously marked dead and now
    alive is ``REVIVED`` and outranks ``NEW`` because a change in reachability
    is a stronger hint than mere existence.
    """

    def __init__(self) -> None:
        self.previous: dict[str, set[str]] = {}
        self.previously_dead: dict[str, set[str]] = {}

    def observe(self, target: str, *, alive: Iterable[str], dead: Iterable[str] = ()) -> None:
        self.previous[target] = set(alive) | set(dead)
        self.previously_dead[target] = set(dead)

    def diff(self, target: str, *, alive: Iterable[str], dead: Iterable[str] = ()) -> list[ChangeSignal]:
        alive_now = set(alive)
        dead_now = set(dead)
        known = self.previous.get(target, set())
        was_dead = self.previously_dead.get(target, set())

        signals: list[ChangeSignal] = []

        for asset in sorted(alive_now):
            if asset not in known:
                signals.append(
                    ChangeSignal(
                        "NEW", target, asset, 4.0,
                        ["asset not present in the previous snapshot; likely untested by others"],
                    )
                )
            elif asset in was_dead:
                signals.append(
                    ChangeSignal(
                        "REVIVED", target, asset, 5.0,
                        ["asset was unreachable in the previous snapshot and is now alive; "
                         "a reachability change often accompanies a misconfiguration"],
                    )
                )

        for asset in sorted(known - alive_now - dead_now):
            signals.append(
                ChangeSignal("DISAPPEARED", target, asset, 0.2, ["no longer observed; keep for asset tracking"])
            )

        signals.sort(key=lambda s: (-s.priority, s.kind, s.value))
        return signals


# --------------------------------------------------------------------------- #
# Freshness ranking
# --------------------------------------------------------------------------- #


class FreshnessRanker:
    """Rank assets so the newest is worked first.

    The premise: a newly published asset is the one nobody else has tested yet,
    so the marginal value of being first exceeds the marginal value of revisiting
    a well-trodden host. The ranker therefore *multiplies* a base priority by a
    decay factor rather than replacing it, so a stale but very promising target
    still outranks a fresh but boring one.
    """

    def __init__(self, *, half_life_days: float = 14.0, floor: float = 0.35) -> None:
        if half_life_days <= 0:
            raise ValueError("half_life_days must be positive")
        self.half_life_days = half_life_days
        self.floor = floor

    def factor(self, first_seen: str, *, now: datetime | None = None) -> float:
        """Multiplier in ``[floor, 1.0]`` based on age."""
        now = now or datetime.now(timezone.utc)
        try:
            seen = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return 1.0
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        age_days = max(0.0, (now - seen).total_seconds() / 86400.0)
        raw = 0.5 ** (age_days / self.half_life_days)
        return max(self.floor, raw)

    def rank(self, items: Sequence[EvidenceItem], first_seen: dict[str, str]) -> list[EvidenceItem]:
        """Return a copy ranked with freshness applied, annotating the signals."""
        ranked: list[EvidenceItem] = []
        for item in items:
            seen = first_seen.get(item.target)
            factor = self.factor(seen) if seen else 1.0
            clone = EvidenceItem(
                kind=item.kind,
                target=item.target,
                value=item.value,
                priority=item.priority * factor,
                signals=list(item.signals)
                + ([f"freshness x{factor:.2f} (first seen {seen})"] if seen else ["no first-seen date; freshness not applied"]),
                role=item.role,
                source=item.source,
                raw_ref=item.raw_ref,
                extra=dict(item.extra),
            )
            ranked.append(clone)
        ranked.sort(key=lambda i: (-i.priority, i.kind, i.value))
        return ranked


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def collect(
    target: str,
    *,
    js_texts: Iterable[tuple[str, str]] = (),
    signals: Iterable[ChangeSignal] = (),
    first_seen: dict[str, str] | None = None,
    max_items: int = 40,
) -> EvidenceBundle:
    """Run the deterministic collectors and return a bounded bundle.

    ``js_texts`` is an iterable of ``(source_label, text)`` pairs. Nothing here
    touches the network: the caller supplies artefacts, which keeps the
    gathering stage reproducible and lets the same inputs be replayed in tests.
    """
    bundle = EvidenceBundle(target=target, max_items=max_items)
    collector = JsSurfaceCollector()

    count = 0
    for label, text in js_texts:
        found = collector.collect_text(text, target, source=label)
        bundle.items.extend(found)
        count += len(found)
    bundle.collector_stats["js-surface"] = count

    signal_items = [s.as_evidence() for s in signals]
    bundle.items.extend(signal_items)
    bundle.collector_stats["snapshot-diff"] = len(signal_items)

    if first_seen:
        bundle.items = FreshnessRanker().rank(bundle.items, first_seen)

    return bundle


def _main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Gather deterministic evidence from saved JavaScript artefacts.")
    parser.add_argument("target", help="target label")
    parser.add_argument("files", nargs="+", type=Path, help="JavaScript/JSON artefacts to scan")
    parser.add_argument("--max-items", type=int, default=40)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)

    collector = JsSurfaceCollector()
    bundle = EvidenceBundle(target=args.target, max_items=args.max_items)
    for path in args.files:
        bundle.items.extend(collector.collect_file(path, args.target))

    text = bundle.to_json()
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
