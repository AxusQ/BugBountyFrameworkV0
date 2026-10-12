"""Portable skill registry for the bug bounty agent framework.

This module is the framework's foundation: it discovers skills from any set of
roots, parses their YAML frontmatter, validates them against the agentskills /
DSH contract, and merges multiple sources into one catalog with deterministic
collision resolution.

Design constraints inherited from the DSH filesystem provider
(`@deepseek-ai/dsh-skill-filesystem`), which is the authoritative contract:

* A skill is ``<root>/<name>/SKILL.md`` or ``<root>/<name>.md``.
* Discovery is exactly **one level deep**. Nested ``**/SKILL.md`` is ignored.
* Frontmatter requires ``name`` (kebab-case) and ``description``.
* Optional keys: ``whenToUse``, ``metadata``, ``disable-model-invocation``,
  ``user-invocable``.
* Invocation booleans accept YAML booleans plus the case-insensitive
  ``true/false``, ``yes/no``, ``on/off``, ``1/0`` spellings. A rejected spelling
  or non-boolean value drops the whole skill rather than silently permitting a
  surface.

Parsing uses PyYAML deliberately. The corpus this framework consumes documents
that three hand-rolled regex frontmatter parsers truncated 604 of 817
descriptions to their first line, because skill descriptions legally span
multiple lines (folded scalars, wrapped quoted scalars, and blank lines inside
quoted strings). Never replace ``yaml.safe_load`` here with a regex.

SECURITY: skill bodies and bundled ``scripts/`` are third-party content. This
module reads them as data. It never imports, evaluates, or executes anything it
discovers.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

import yaml

__all__ = [
    "KEBAB_RE",
    "Diagnostic",
    "ScanResult",
    "Skill",
    "SkillRoot",
    "default_roots",
    "merge_catalog",
    "parse_frontmatter",
    "parse_strict_bool",
    "scan_roots",
    "split_frontmatter",
]

KEBAB_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

#: Frontmatter keys this registry understands. Unknown keys are preserved in
#: ``Skill.extra`` and reported as informational diagnostics, never dropped.
#:
#: ``license``, ``version``, ``author`` and ``allowed-tools`` are part of the
#: agentskills standard and appear throughout the source corpus, so they are
#: recognised rather than reported as non-standard. Only ``name`` and
#: ``description`` are required by the DSH contract.
KNOWN_KEYS = {
    "name",
    "description",
    "whenToUse",
    "metadata",
    "disable-model-invocation",
    "user-invocable",
    "license",
    "version",
    "author",
    "allowed-tools",
}

_BOOL_TRUE = {"true", "yes", "on", "1"}
_BOOL_FALSE = {"false", "no", "off", "0"}

_SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}

#: A skill file larger than this is refused rather than read into memory. Skill
#: bodies are prose procedures; anything approaching this size is either a
#: mistake or a memory-exhaustion attempt. 2 MiB is roughly 200x the corpus mean.
MAX_SKILL_BYTES = 2 * 1024 * 1024

#: Budgets for the post-parse expansion check. See :func:`check_expansion`.
MAX_STRUCTURE_NODES = 10_000
MAX_STRUCTURE_DEPTH = 32


# --------------------------------------------------------------------------- #
# Diagnostics
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Diagnostic:
    """One finding about one candidate skill.

    ``error`` means the skill is dropped from the catalog. ``warning`` and
    ``info`` mean it is admitted (or that a root was unusable) and the message
    is advisory.

    This matters because the DSH provider drops malformed entries silently:
    the model catalog receives no per-skill diagnostic, so an invalid skill is
    indistinguishable from an absent one. This registry keeps the diagnostics
    so the framework's own tooling can surface them.
    """

    severity: str
    code: str
    message: str
    path: str | None = None
    skill: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
            "path": self.path,
            "skill": self.skill,
        }

    def __str__(self) -> str:
        where = self.path or self.skill or "-"
        return f"[{self.severity.upper():7}] {self.code}: {self.message} ({where})"


def _sort_diagnostics(diags: Iterable[Diagnostic]) -> list[Diagnostic]:
    return sorted(
        diags,
        key=lambda d: (
            _SEVERITY_ORDER.get(d.severity, 9),
            d.code,
            d.path or "",
        ),
    )


# --------------------------------------------------------------------------- #
# Frontmatter parsing
# --------------------------------------------------------------------------- #


def split_frontmatter(text: str) -> tuple[str | None, str, str | None]:
    """Split ``text`` into ``(raw_yaml, body, error)``.

    ``raw_yaml`` is ``None`` when the document has no frontmatter block, which
    is a validation error at the skill level but not a parse failure. ``error``
    is set only when the block is present but unterminated.
    """
    stripped = text.lstrip("\ufeff")
    lines = stripped.splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        return None, text, None

    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            raw = "".join(lines[1:index])
            body = "".join(lines[index + 1 :])
            return raw, body, None

    return None, text, "frontmatter block opened with '---' but never closed"


def parse_frontmatter(raw_yaml: str) -> tuple[dict[str, Any] | None, str | None]:
    """Parse frontmatter with PyYAML, returning ``(mapping, error)``."""
    try:
        loaded = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as exc:  # malformed YAML is a hard error
        detail = str(exc).replace("\n", " ")
        return None, f"invalid YAML frontmatter: {detail}"

    if loaded is None:
        return None, "frontmatter block is empty"
    if not isinstance(loaded, dict):
        return None, f"frontmatter must be a mapping, got {type(loaded).__name__}"
    return loaded, None


def parse_strict_bool(value: Any) -> tuple[bool | None, str | None]:
    """Resolve a DSH invocation flag, returning ``(boolean, error)``.

    Accepts YAML booleans and the documented case-insensitive spellings. Note
    that PyYAML (YAML 1.1) already resolves bare ``yes``/``no``/``on``/``off``
    to ``bool`` and bare ``1``/``0`` to ``int``, so both routes are handled; a
    *quoted* ``"yes"`` arrives as ``str`` and is handled by the string branch.
    """
    if isinstance(value, bool):
        return value, None

    if isinstance(value, int):  # bool is an int subclass, already handled above
        if value in (1, 0):
            return bool(value), None
        return None, f"expected a boolean, got the integer {value}"

    if isinstance(value, float):
        if value in (1.0, 0.0):
            return bool(value), None
        return None, f"expected a boolean, got the number {value}"

    if isinstance(value, str):
        token = value.strip().lower()
        if token in _BOOL_TRUE:
            return True, None
        if token in _BOOL_FALSE:
            return False, None
        return None, f"expected a boolean, got the string {value!r}"

    return None, f"expected a boolean, got {type(value).__name__}"


# --------------------------------------------------------------------------- #
# Skill model
# --------------------------------------------------------------------------- #


@dataclass
class Skill:
    """One validated skill."""

    name: str
    description: str
    path: Path
    root_label: str
    root_rank: int
    source: str  # "bundle" | "flat"
    when_to_use: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    model_invocable: bool = True
    user_invocable: bool = True
    license: str | None = None
    version: str | None = None
    author: str | None = None
    body: str = ""
    body_bytes: int = 0
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def bundle_dir(self) -> Path:
        """Directory holding this skill's resources (references/, scripts/)."""
        return self.path if self.source == "flat" else self.path.parent

    def resources(self) -> list[Path]:
        """Files shipped alongside the skill, excluding SKILL.md itself.

        Reported for inventory only. The framework never executes these.
        """
        base = self.bundle_dir
        if not base.is_dir():
            return []
        return sorted(
            p for p in base.rglob("*") if p.is_file() and p.name != "SKILL.md"
        )

    def summary(self) -> dict[str, Any]:
        d = {
            "name": self.name,
            "description": self.description,
            "path": str(self.path),
            "root": self.root_label,
            "rank": self.root_rank,
            "source": self.source,
            "model_invocable": self.model_invocable,
            "user_invocable": self.user_invocable,
        }
        if self.when_to_use:
            d["whenToUse"] = self.when_to_use
        if self.metadata:
            d["metadata"] = self.metadata
        if self.license:
            d["license"] = self.license
        if self.version:
            d["version"] = self.version
        if self.author:
            d["author"] = self.author
        return d

    def __str__(self) -> str:
        return f"{self.name} ({self.root_label})"


@dataclass(frozen=True)
class SkillRoot:
    """A directory scanned for skills. Lower ``rank`` wins a name collision."""

    label: str
    path: Path
    rank: int

    def as_dict(self) -> dict[str, Any]:
        return {"label": self.label, "path": str(self.path), "rank": self.rank}


@dataclass
class ScanResult:
    """Everything one scan learned."""

    skills: list[Skill] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    roots: list[SkillRoot] = field(default_factory=list)

    @property
    def errors(self) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.severity == "error"]

    @property
    def warnings(self) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.severity == "warning"]

    def by_name(self) -> dict[str, Skill]:
        return {s.name: s for s in self.skills}


# --------------------------------------------------------------------------- #
# Root defaults
# --------------------------------------------------------------------------- #

#: Mirrors the DSH provider's rank order so the framework resolves collisions
#: exactly as the harness would.
DSH_RANK_ORDER = {
    "project-dsh": 100,
    "project-agents": 200,
    "custom": 300,
    "user-dsh": 400,
    "user-agents": 500,
    "bundled": 600,
}


def default_roots(
    project_root: Path,
    dsh_home: Path | None = None,
    agents_home: Path | None = None,
    custom_dirs: Sequence[Path] = (),
) -> list[SkillRoot]:
    """Build the DSH-equivalent root list.

    Only existing roots are returned by :func:`scan_roots`; this function
    states intent, and missing roots are valid empty state.
    """
    home = Path.home()
    dsh_home = dsh_home or Path.home() / ".dsh"
    agents_home = agents_home or Path.home() / ".agents"

    roots = [
        SkillRoot("project-dsh", project_root / ".dsh" / "skills", 100),
        SkillRoot("project-agents", project_root / ".agents" / "skills", 200),
    ]
    for i, d in enumerate(custom_dirs):
        roots.append(SkillRoot("custom", Path(d), 300 + i))
    roots += [
        SkillRoot("user-dsh", dsh_home / "skills", 400),
        SkillRoot("user-agents", agents_home / "skills", 500),
    ]
    return roots


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #


def check_expansion(
    obj: Any,
    *,
    max_nodes: int = MAX_STRUCTURE_NODES,
    max_depth: int = MAX_STRUCTURE_DEPTH,
) -> str | None:
    """Bound the *serialised* size of a parsed structure, returning an error or None.

    This guards a subtle and genuinely dangerous asymmetry. PyYAML resolves YAML
    aliases to **shared object references**, so parsing a small document is cheap
    no matter how large a tree it describes::

        a: &a ["x","x","x","x","x","x","x","x","x"]
        b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
        c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]

    A 316-byte document of that shape expands to 26.9 MB of JSON in ~6.6 seconds
    the moment anything serialises it, because ``json.dumps`` has no notion of
    reference sharing and emits every occurrence. Add levels and it stops being
    slow and starts being fatal.

    The framework serialises skill metadata into its index, so a malicious or
    merely careless ``SKILL.md`` in any ingested source can hang or exhaust the
    process. This walk counts dereferences exactly as serialisation would, so the
    bomb is rejected at discovery time.
    """
    nodes = 0
    stack: list[tuple[Any, int]] = [(obj, 0)]
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            return f"structure expands beyond {max_nodes} nodes when serialised (alias bomb?)"
        if depth > max_depth:
            return f"structure nests deeper than {max_depth} levels"
        if isinstance(node, dict):
            for key, value in node.items():
                stack.append((key, depth + 1))
                stack.append((value, depth + 1))
        elif isinstance(node, (list, tuple, set, frozenset)):
            for value in node:
                stack.append((value, depth + 1))
    return None


def _read_text(path: Path, *, max_bytes: int = MAX_SKILL_BYTES) -> tuple[str | None, str | None]:
    """Read UTF-8 (BOM tolerated), falling back to cp1252 for stray encodings.

    Refuses oversized files up front so an untrusted skill cannot exhaust memory
    simply by existing.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        return None, f"cannot stat file: {exc}"

    if size > max_bytes:
        return None, f"file is {size} bytes, over the {max_bytes}-byte limit"

    try:
        data = path.read_bytes()
    except OSError as exc:
        return None, f"cannot read file: {exc}"

    try:
        return data.decode("utf-8-sig"), None
    except UnicodeDecodeError:
        try:
            return data.decode("cp1252"), None
        except UnicodeDecodeError as exc:
            return None, f"not decodable as utf-8 or cp1252: {exc}"


def _candidates(root: Path, label: str) -> Iterator[tuple[Path, str, str]]:
    """Yield ``(skill_file, source_kind, dir_name)`` for one root, one level deep.

    A root that does not exist yields nothing: confirmed missing is valid empty
    state, not an error.
    """
    try:
        entries = sorted(root.iterdir(), key=lambda p: p.name.lower())
    except (FileNotFoundError, NotADirectoryError):
        return
    except OSError:
        return

    for entry in entries:
        # The user DSH root skips its `.system` child by contract.
        if entry.name.startswith(".") or entry.name == "node_modules":
            continue
        if entry.is_dir():
            skill_file = entry / "SKILL.md"
            if skill_file.is_file():
                yield skill_file, "bundle", entry.name
        elif entry.is_file() and entry.suffix.lower() == ".md":
            yield entry, "flat", entry.stem


def scan_roots(
    roots: Sequence[SkillRoot],
    *,
    min_severity: str = "info",
) -> ScanResult:
    """Discover and validate every skill under ``roots``.

    Returns all *admissible* skills; invalid candidates are dropped and
    reported as ``error`` diagnostics rather than silently disappearing.
    """
    result = ScanResult(roots=list(roots))
    diags: list[Diagnostic] = []

    for root in roots:
        if not root.path.exists():
            diags.append(
                Diagnostic(
                    "info",
                    "root-missing",
                    f"root '{root.label}' does not exist yet; treated as empty",
                    path=str(root.path),
                )
            )
            continue

        for skill_file, kind, dir_name in _candidates(root.path, root.label):
            text, read_err = _read_text(skill_file)
            if text is None:
                diags.append(
                    Diagnostic("error", "unreadable", read_err or "unreadable", path=str(skill_file))
                )
                continue

            raw_yaml, body, split_err = split_frontmatter(text)
            if split_err:
                diags.append(
                    Diagnostic("error", "frontmatter-unterminated", split_err, path=str(skill_file))
                )
                continue
            if raw_yaml is None:
                diags.append(
                    Diagnostic(
                        "error",
                        "frontmatter-missing",
                        "no YAML frontmatter block; a skill requires 'name' and 'description'",
                        path=str(skill_file),
                    )
                )
                continue

            meta, parse_err = parse_frontmatter(raw_yaml)
            if parse_err or meta is None:
                diags.append(
                    Diagnostic("error", "frontmatter-invalid", parse_err or "unparseable", path=str(skill_file))
                )
                continue

            expansion_err = check_expansion(meta)
            if expansion_err:
                diags.append(
                    Diagnostic("error", "frontmatter-expansion", expansion_err, path=str(skill_file))
                )
                continue

            name = meta.get("name")
            if not isinstance(name, str) or not name.strip():
                diags.append(
                    Diagnostic("error", "name-missing", "frontmatter 'name' is required and must be a string", path=str(skill_file))
                )
                continue
            name = name.strip()
            if not KEBAB_RE.match(name):
                diags.append(
                    Diagnostic(
                        "error",
                        "name-not-kebab",
                        f"name {name!r} is not kebab-case (expected e.g. 'my-skill')",
                        path=str(skill_file),
                    )
                )
                continue

            description = meta.get("description")
            if not isinstance(description, str) or not description.strip():
                diags.append(
                    Diagnostic(
                        "error",
                        "description-missing",
                        "'description' is required and must be a non-empty string",
                        path=str(skill_file),
                        skill=name,
                    )
                )
                continue
            description = " ".join(description.split())

            if kind == "bundle" and name != dir_name:
                diags.append(
                    Diagnostic(
                        "warning",
                        "name-dir-mismatch",
                        f"frontmatter name {name!r} differs from directory {dir_name!r}; "
                        "the catalog uses the frontmatter name",
                        path=str(skill_file),
                        skill=name,
                    )
                )

            # Invocation flags: a bad value drops the whole skill by contract.
            model_ok, user_ok = True, True
            bad_flag: str | None = None
            for key, target in (("disable-model-invocation", "model"), ("user-invocable", "user")):
                if key not in meta:
                    continue
                value, flag_err = parse_strict_bool(meta[key])
                if flag_err:
                    bad_flag = f"'{key}' {flag_err}; skill dropped"
                    break
                if key == "disable-model-invocation":
                    model_ok = not value  # inverted: disabling removes the surface
                else:
                    user_ok = bool(value)
            if bad_flag:
                diags.append(
                    Diagnostic("error", "invocation-invalid", bad_flag, path=str(skill_file), skill=name)
                )
                continue

            when_to_use = meta.get("whenToUse")
            if when_to_use is not None and not isinstance(when_to_use, str):
                diags.append(
                    Diagnostic(
                        "warning",
                        "whenToUse-not-string",
                        f"'whenToUse' should be a string, got {type(when_to_use).__name__}",
                        path=str(skill_file),
                        skill=name,
                    )
                )
                when_to_use = None

            metadata = meta.get("metadata")
            if metadata is not None and not isinstance(metadata, dict):
                diags.append(
                    Diagnostic(
                        "warning",
                        "metadata-not-mapping",
                        f"'metadata' should be a mapping, got {type(metadata).__name__}",
                        path=str(skill_file),
                        skill=name,
                    )
                )
                metadata = {}

            extra = {k: v for k, v in meta.items() if k not in KNOWN_KEYS}
            if extra:
                diags.append(
                    Diagnostic(
                        "info",
                        "extra-frontmatter",
                        "non-standard frontmatter key(s) preserved but not interpreted: "
                        + ", ".join(sorted(extra)),
                        path=str(skill_file),
                        skill=name,
                    )
                )

            if not description:
                diags.append(
                    Diagnostic("warning", "description-empty", "description is empty after normalising whitespace", path=str(skill_file), skill=name)
                )

            license_value = meta.get("license")
            license_value = license_value.strip() if isinstance(license_value, str) else None
            version_value = meta.get("version")
            version_value = str(version_value).strip() if version_value is not None else None
            author_value = meta.get("author")
            author_value = author_value.strip() if isinstance(author_value, str) else None

            skill = Skill(
                name=name,
                description=description,
                path=skill_file,
                root_label=root.label,
                root_rank=root.rank,
                source=kind,
                when_to_use=when_to_use,
                metadata=metadata or {},
                model_invocable=model_ok,
                user_invocable=user_ok,
                license=license_value,
                version=version_value,
                author=author_value,
                body=body,
                body_bytes=len(body.encode("utf-8")),
                extra=extra,
            )
            result.skills.append(skill)

    result.diagnostics = _sort_diagnostics(
        d for d in diags if _SEVERITY_ORDER.get(d.severity, 9) <= _SEVERITY_ORDER.get(min_severity, 2)
    )
    return result


# --------------------------------------------------------------------------- #
# Merging
# --------------------------------------------------------------------------- #


@dataclass
class Collision:
    """Two or more roots offering the same skill name."""

    name: str
    winner: Skill
    losers: list[Skill]

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "winner": self.winner.summary(),
            "losers": [s.summary() for s in self.losers],
            "shadowed_roots": [s.root_label for s in self.losers],
        }


def merge_catalog(
    skills: Sequence[Skill],
) -> tuple[dict[str, Skill], list[Collision]]:
    """Resolve a flat skill list into one catalog, lowest rank winning.

    Within a single rank the first candidate in scan order wins, matching the
    registry's "first-wins with a warning" behaviour for same-layer
    registrations.
    """
    grouped: dict[str, list[Skill]] = {}
    for skill in skills:
        grouped.setdefault(skill.name, []).append(skill)

    catalog: dict[str, Skill] = {}
    collisions: list[Collision] = []
    for name, group in grouped.items():
        ordered = sorted(group, key=lambda s: (s.root_rank, str(s.path)))
        catalog[name] = ordered[0]
        if len(ordered) > 1:
            collisions.append(Collision(name=name, winner=ordered[0], losers=ordered[1:]))
    return catalog, collisions


def catalog_to_json(
    catalog: dict[str, Skill],
    *,
    version: int = 1,
    repository: str = "bug-bounty-agent-framework",
) -> str:
    """Serialise a catalog, compatible in spirit with the corpus index.json."""
    payload = {
        "version": version,
        "repository": repository,
        "total_skills": len(catalog),
        "skills": [catalog[name].summary() for name in sorted(catalog)],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Scan skill roots and report the merged catalog.")
    parser.add_argument("roots", nargs="+", type=Path, help="directories to scan (label:path or path)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--min-severity", default="info", choices=["error", "warning", "info"])
    args = parser.parse_args(argv)

    roots: list[SkillRoot] = []
    for i, spec in enumerate(args.roots):
        if ":" in str(spec) and not re.match(r"^[A-Za-z]:", str(spec)):
            label, _, raw = str(spec).partition(":")
            roots.append(SkillRoot(label, Path(raw), DSH_RANK_ORDER.get(label, 100 + i)))
        else:
            roots.append(SkillRoot(f"arg{i}", Path(spec), 100 + i))

    result = scan_roots(roots, min_severity=args.min_severity)
    catalog, collisions = merge_catalog(result.skills)

    if args.json:
        print(
            json.dumps(
                {
                    "roots": [r.as_dict() for r in result.roots],
                    "total_candidates": len(result.skills),
                    "total_skills": len(catalog),
                    "skills": [catalog[n].summary() for n in sorted(catalog)],
                    "collisions": [c.as_dict() for c in collisions],
                    "diagnostics": [d.as_dict() for d in result.diagnostics],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    print(f"roots scanned: {len(roots)}")
    for r in roots:
        state = "ok" if r.path.exists() else "missing (empty)"
        print(f"  [{r.rank:>3}] {r.label:<16} {r.path}  -> {state}")
    print(f"\ncandidates: {len(result.skills)}   catalog: {len(catalog)}   collisions: {len(collisions)}")
    if collisions:
        print("\ncollisions (lowest rank wins):")
        for c in collisions:
            print(f"  {c.name}: winner={c.winner.root_label} shadowed={[s.root_label for s in c.losers]}")
    if result.diagnostics:
        print(f"\ndiagnostics ({len(result.diagnostics)}):")
        for d in result.diagnostics:
            print(f"  {d}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
