"""Fetch the external reference repositories this framework draws on.

The framework does not vendor its sources. It references them, at pinned
commits, into `references/` — which is gitignored. That keeps the repository
self-contained (your code only) while making the corpus reproducible on any
host, and it keeps other people's licensing terms out of your tree:

* `bountyforge` carries **no license grant at all**, so republishing it under
  your repository would be a licensing problem. Cloning it locally is fine.
* `claude-kit` is **GPL-3.0-or-later**. Referencing is fine; vendoring would
  impose copyleft on this repository.
* `Anthropic-Cybersecurity-Skills` is Apache-2.0 and could be vendored, but
  pinning is still better than forking — a fork rots silently as upstream moves.
* `bug-bounty-hunting-prompts` is MIT and deliberately non-runnable without its
  author's private infrastructure; it is a design reference only, not a skill
  source, so it is fetched but never scanned for skills.

Usage:
    python bootstrap.py                 # fetch everything missing
    python bootstrap.py --check         # report state, change nothing
    python bootstrap.py --force         # re-fetch even if present
    python bootstrap.py --only corpus   # fetch one source
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

FRAMEWORK_ROOT = Path(__file__).resolve().parent
DEFAULT_DEST = FRAMEWORK_ROOT / "references"


@dataclass(frozen=True)
class Reference:
    """One pinned external source."""

    label: str
    name: str          # directory name under references/
    url: str
    commit: str
    license: str
    role: str
    skills_subdir: str | None  # None => design reference only, never scanned


REFERENCES: tuple[Reference, ...] = (
    Reference(
        label="corpus",
        name="Anthropic-Cybersecurity-Skills",
        url="https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git",
        commit="54a79883",
        license="Apache-2.0",
        role="skill corpus, packaging standard, validation tooling",
        skills_subdir="skills",
    ),
    Reference(
        label="kit",
        name="claude-kit",
        url="https://github.com/yeswehack/claude-kit.git",
        commit="3928c34",
        license="GPL-3.0-or-later",
        role="evidence-discipline layer (policy reference only; prose not copied)",
        skills_subdir="skills",
    ),
    Reference(
        label="forge",
        name="bountyforge",
        url="https://github.com/Gabson0x/bountyforge.git",
        commit="068399d",
        license="none - all rights reserved",
        role="oracle/control and lead-lifecycle design reference",
        skills_subdir="skills",
    ),
    Reference(
        label="prompts",
        name="bug-bounty-hunting-prompts",
        url="https://github.com/mdpsec/bug-bounty-hunting-prompts.git",
        commit="5ed4158",
        license="MIT",
        role="phase-pipeline design reference (not a skill source)",
        skills_subdir=None,
    ),
)


def _run(args: Sequence[str], cwd: Path | None = None) -> tuple[int, str]:
    """Run a command, returning (returncode, combined output)."""
    try:
        result = subprocess.run(
            list(args), cwd=str(cwd) if cwd else None,
            capture_output=True, text=True, timeout=900,
        )
    except FileNotFoundError:
        return 127, f"command not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"timed out: {' '.join(args)}"
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def _current_commit(path: Path) -> str | None:
    if not (path / ".git").exists():
        return None
    code, out = _run(["git", "-C", str(path), "rev-parse", "--short", "HEAD"])
    return out.strip() if code == 0 else None


def _matches_pin(actual: str | None, pin: str) -> bool:
    # Pins are short SHAs from upstream; accept any unambiguous prefix match.
    return bool(actual) and (actual.startswith(pin) or pin.startswith(actual))


def state_of(ref: Reference, dest: Path) -> str:
    """One of: missing, wrong-commit, ok, not-a-clone."""
    path = dest / ref.name
    if not path.exists():
        return "missing"
    commit = _current_commit(path)
    if commit is None:
        return "not-a-clone"
    return "ok" if _matches_pin(commit, ref.commit) else "wrong-commit"


def fetch(ref: Reference, dest: Path, *, force: bool, quiet: bool) -> tuple[bool, str]:
    """Clone and pin one reference. Returns (ok, message)."""
    path = dest / ref.name
    current = state_of(ref, dest)

    if current == "ok" and not force:
        return True, f"{ref.label:<8} already at {ref.commit}"

    if path.exists() and current != "missing":
        if force or current == "wrong-commit":
            shutil.rmtree(path, ignore_errors=True)
        elif current == "not-a-clone":
            return False, f"{ref.label:<8} {path} exists and is not a git clone; refusing to overwrite"

    if not path.exists():
        if not quiet:
            print(f"  cloning {ref.name} ...", flush=True)
        # Try a shallow fetch of the pinned commit first: far cheaper than a
        # full clone, and pins are immutable.
        code, out = _run([
            "git", "clone", "--quiet", "--filter=blob:none", "--no-checkout",
            ref.url, str(path),
        ])
        if code != 0:
            return False, f"{ref.label:<8} clone failed: {out.strip()[:200]}"

    code, out = _run(["git", "-C", str(path), "fetch", "--quiet", "--depth", "1",
                      "origin", ref.commit])
    if code == 0:
        code, out = _run(["git", "-C", str(path), "checkout", "--quiet", "FETCH_HEAD"])
    if code != 0:
        # Fall back to a full fetch when the server disallows by-SHA fetches.
        code, out = _run(["git", "-C", str(path), "fetch", "--quiet", "--all", "--tags"])
        if code == 0:
            code, out = _run(["git", "-C", str(path), "checkout", "--quiet", ref.commit])
    if code != 0:
        return False, f"{ref.label:<8} could not check out {ref.commit}: {out.strip()[:200]}"

    actual = _current_commit(path)
    if not _matches_pin(actual, ref.commit):
        return False, f"{ref.label:<8} pinned {ref.commit} but HEAD is {actual}"
    return True, f"{ref.label:<8} {ref.name} at {actual}"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dest", type=Path, default=DEFAULT_DEST,
                        help="where references are placed (default: framework/references)")
    parser.add_argument("--check", action="store_true", help="report state and exit")
    parser.add_argument("--force", action="store_true", help="re-fetch even when present")
    parser.add_argument("--only", action="append", default=None,
                        help="limit to one label (repeatable): corpus, kit, forge, prompts")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    code, out = _run(["git", "--version"])
    if code != 0:
        print("error: git is required but was not found on PATH", file=sys.stderr)
        return 2

    wanted = REFERENCES
    if args.only:
        labels = {label.lower() for label in args.only}
        wanted = tuple(r for r in REFERENCES if r.label in labels)
        if not wanted:
            print(f"error: no reference matched {sorted(labels)}", file=sys.stderr)
            return 2

    dest = args.dest.resolve()

    if args.check:
        print(f"references in {dest}\n")
        problems = 0
        for ref in wanted:
            state = state_of(ref, dest)
            mark = {"ok": "ok      ", "missing": "missing ", "wrong-commit": "WRONG   ", "not-a-clone": "NOT-GIT "}[state]
            detail = f" (want {ref.commit})" if state == "wrong-commit" else ""
            print(f"  [{mark}] {ref.label:<8} {ref.name:<34} {ref.license}{detail}")
            if state != "ok":
                problems += 1
        print(f"\n{problems} reference(s) not in the pinned state")
        if problems:
            print("run: python bootstrap.py")
        return 1 if problems else 0

    dest.mkdir(parents=True, exist_ok=True)
    print(f"fetching {len(wanted)} reference(s) into {dest}\n")
    failures = 0
    for ref in wanted:
        ok, message = fetch(ref, dest, force=args.force, quiet=args.quiet)
        print(("  " if ok else "  FAIL ") + message)
        failures += 0 if ok else 1

    print()
    if failures:
        print(f"{failures} reference(s) failed. The framework still runs; those sources are optional.")
    else:
        print("all references pinned. Next: python tools/build_index.py")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
