"""Install the framework's skills into a DSH-scanned skill root.

WHY THIS EXISTS
---------------
DSH discovers skills from a fixed set of roots, one level deep, and the highest
priority root is ``<projectRoot>/.dsh/skills`` where *projectRoot is the nearest
ancestor containing ``.git``*. In this workspace that resolution is hostile: the
nearest ``.git`` ancestor is ``C:\\``, so the project root is the drive root and
the project root would be ``C:\\.dsh\\skills``. Writing there would scatter state
across the filesystem root, so this installer targets the **user** root instead:

    <dshHome>/skills/<name>/SKILL.md        (rank 400)

That root is confirmed working — the existing ``sqli-bug-bounty`` skill lives
there and appears in the session catalog — and DSH watches it, so an installed
skill becomes available without restarting the harness.

An alternative is ``customSkillDirs`` in the profile patch file, which would let
DSH watch the workspace directory directly with no copying. ``--print-config``
emits that snippet; it is not applied automatically because editing harness
configuration is the user's decision, not the installer's.

MODES
-----
copy (default)   copy each bundle into the target root; re-runnable (idempotent)
link             create a directory junction per bundle (Windows, no admin
                 needed) so the workspace stays the single source of truth
check            report what is installed and whether it matches the source
uninstall        remove framework-owned skills from the target root

Nothing outside the target root is ever touched, and uninstall only removes
directories that carry the framework's own marker.
"""

from __future__ import annotations

import argparse
import filecmp
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))
import skillreg as sr  # noqa: E402

FRAMEWORK_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE = FRAMEWORK_ROOT / "skills"

#: Marks a directory as framework-managed so uninstall never removes anything else.
MARKER = ".bb-framework-install.json"


def resolve_target(explicit: Path | None) -> Path:
    """Resolve the install target, defaulting to the DSH user skill root."""
    if explicit:
        return explicit.expanduser().resolve()
    home = os.environ.get("DSH_HOME")
    base = Path(home) if home else Path.home() / ".dsh"
    return (base / "skills").resolve()


def source_bundles(source: Path) -> list[Path]:
    """Bundle directories under ``source``, one level deep."""
    if not source.is_dir():
        return []
    out: list[Path] = []
    for entry in sorted(source.iterdir(), key=lambda p: p.name.lower()):
        if entry.is_dir() and (entry / "SKILL.md").is_file():
            out.append(entry)
    return out


def _dirs_equal(a: Path, b: Path) -> bool:
    """Compare two bundle directories, ignoring framework-install metadata.

    The marker file is written *into* the destination after a copy, so a strict
    comparison would report every freshly installed skill as stale. It is
    bookkeeping, not content, and is therefore excluded at every level.
    """
    if not (b / "SKILL.md").is_file():
        return False
    cmp = filecmp.dircmp(str(a), str(b), ignore=[MARKER], hide=[MARKER])
    if cmp.left_only or cmp.right_only or cmp.diff_files or cmp.funny_files:
        return False
    for sub in cmp.common_dirs:
        if not _dirs_equal(a / sub, b / sub):
            return False
    return True


def _write_marker(bundle: Path, origin: Path, mode: str) -> None:
    (bundle / MARKER).write_text(
        json.dumps({"managed_by": "bug-bounty-agent-framework", "origin": str(origin), "mode": mode}, indent=2) + "\n",
        encoding="utf-8",
    )


def _is_managed(bundle: Path) -> bool:
    return (bundle / MARKER).is_file()


#: Characters cmd.exe acts on even inside an unquoted argument. A path containing
#: any of these cannot be handed to mklink safely.
_CMD_UNSAFE_CHARS = frozenset('&|^<>%!"\r\n')


def _cmd_quote(path: Path) -> str:
    """Render a path as a single, safely quoted cmd.exe argument.

    ``subprocess.list2cmdline`` quotes an argument only when it contains
    whitespace. A source directory named ``evil&calc`` therefore reaches cmd.exe
    as live metacharacters and the remainder becomes a second command — a real
    argument-injection primitive, and a plausible one here because the whole
    point of ``--source`` is to install skills from third-party repositories.

    Quoting neutralises the metacharacters; refusing the ones quoting cannot
    neutralise (a literal quote, a newline) closes the rest.
    """
    text = str(path)
    unsafe = _CMD_UNSAFE_CHARS & set(text)
    if unsafe:
        raise RuntimeError(
            f"refusing to pass a path containing {sorted(unsafe)} to the command interpreter: {text!r}"
        )
    return f'"{text}"'


def _make_junction(link: Path, target: Path) -> None:
    """Create a Windows directory junction (no elevation required)."""
    if os.name != "nt":
        link.symlink_to(target, target_is_directory=True)
        return
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", _cmd_quote(link), _cmd_quote(target)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"mklink failed: {result.stdout}{result.stderr}")


def install(source: Path, target: Path, *, mode: str, dry_run: bool, force: bool) -> tuple[list[str], list[str]]:
    actions: list[str] = []
    errors: list[str] = []
    target.mkdir(parents=True, exist_ok=True)

    for bundle in source_bundles(source):
        name = bundle.name

        # A skill name is kebab-case by contract anyway, so this rejects nothing
        # legitimate. It is the outermost layer of defence against a hostile
        # directory name reaching the command interpreter or the filesystem.
        if not sr.KEBAB_RE.match(name):
            errors.append(
                f"refused    {name}: directory name is not a safe kebab-case skill name"
            )
            continue

        dest = target / name

        if dest.exists() or dest.is_symlink():
            if _is_managed(dest) or dest.is_symlink():
                if mode == "copy" and not force and _dirs_equal(bundle, dest):
                    actions.append(f"unchanged  {name}")
                    continue
                actions.append(f"replace    {name}")
                if not dry_run:
                    if dest.is_symlink():
                        dest.unlink()
                    else:
                        shutil.rmtree(dest)
            else:
                errors.append(f"refused    {name}: {dest} exists and is not framework-managed")
                continue
        else:
            actions.append(f"install    {name}")

        if dry_run:
            continue

        try:
            if mode == "link":
                _make_junction(dest, bundle)
            else:
                shutil.copytree(bundle, dest)
                _write_marker(dest, bundle, "copy")
        except Exception as exc:  # noqa: BLE001 - surfaced to the operator
            errors.append(f"failed     {name}: {exc}")

    return actions, errors


def check(source: Path, target: Path) -> tuple[list[str], int]:
    lines: list[str] = []
    problems = 0
    for bundle in source_bundles(source):
        dest = target / bundle.name
        if not dest.exists():
            lines.append(f"MISSING    {bundle.name}")
            problems += 1
        elif dest.is_symlink():
            lines.append(f"LINKED     {bundle.name} -> {dest.resolve()}")
        elif _dirs_equal(bundle, dest):
            lines.append(f"ok         {bundle.name}")
        else:
            lines.append(f"STALE      {bundle.name} (differs from source)")
            problems += 1
    return lines, problems


def uninstall(target: Path, *, dry_run: bool) -> tuple[list[str], list[str]]:
    actions: list[str] = []
    errors: list[str] = []
    if not target.is_dir():
        return actions, errors

    for entry in sorted(target.iterdir(), key=lambda p: p.name.lower()):
        if not entry.is_dir() and not entry.is_symlink():
            continue
        if entry.is_symlink():
            actions.append(f"remove link {entry.name}")
            if not dry_run:
                entry.unlink()
        elif _is_managed(entry):
            actions.append(f"remove      {entry.name}")
            if not dry_run:
                shutil.rmtree(entry)
    return actions, errors


def print_config(source: Path) -> None:
    """Emit the customSkillDirs patch for live, copy-free discovery."""
    print(
        "# Add to the profile patch file (cordis.patch.yml), then reload.\n"
        "# This makes DSH watch the workspace directory directly instead of a copy.\n"
        "# Confirm the plugin id against your profile before applying; an unknown id is\n"
        "# ignored silently and the skills simply will not appear.\n"
        "\n"
        "- id: skill-filesystem\n"
        '  name: "@deepseek-ai/dsh-skill-filesystem"\n'
        "  config:\n"
        "    customSkillDirs:\n"
        f"      - {json.dumps(str(source))}\n"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", nargs="?", default="install", choices=["install", "check", "uninstall", "print-config"])
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--target", type=Path, default=None, help="skill root (default: <DSH_HOME>/skills)")
    parser.add_argument("--copy", action="store_const", const="copy", dest="link_mode", default="copy")
    parser.add_argument("--link", action="store_const", const="link", dest="link_mode", help="junction instead of copy")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true", help="overwrite even when the copy looks identical")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    source = args.source.expanduser().resolve()
    target = resolve_target(args.target)

    if args.mode == "print-config":
        print_config(source)
        return 0

    bundles = source_bundles(source)
    if not bundles:
        print(f"error: no skill bundles found under {source}", file=sys.stderr)
        return 2

    if args.mode == "check":
        lines, problems = check(source, target)
        if args.json:
            print(json.dumps({"source": str(source), "target": str(target), "problems": problems, "lines": lines}, indent=2))
        else:
            print(f"source {source}\ntarget {target}\n")
            for line in lines:
                print(f"  {line}")
            print(f"\n{problems} problem(s)")
        return 1 if problems else 0

    if args.mode == "uninstall":
        actions, errors = uninstall(target, dry_run=args.dry_run)
    else:
        actions, errors = install(source, target, mode=args.link_mode, dry_run=args.dry_run, force=args.force)

    if args.json:
        print(json.dumps({"source": str(source), "target": str(target), "mode": args.mode,
                          "dry_run": args.dry_run, "actions": actions, "errors": errors}, indent=2))
    else:
        prefix = "[dry-run] " if args.dry_run else ""
        print(f"source {source}\ntarget {target}\nmode   {args.mode}{' (dry-run)' if args.dry_run else ''}\n")
        for action in actions:
            print(f"  {prefix}{action}")
        for error in errors:
            print(f"  ERROR {error}")
        print(f"\n{len(actions)} action(s), {len(errors)} error(s)")
        if args.mode == "install" and not args.dry_run:
            print("\nDSH watches this root, so the skills appear in the session catalog without a restart.")

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
