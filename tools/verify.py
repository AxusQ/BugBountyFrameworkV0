"""One-command validation of a fresh checkout.

Run this first on a new host. It checks the environment, then runs every gate
the framework enforces, and prints a single pass/fail summary.

    python tools/verify.py
    python tools/verify.py --full     # include the slower corpus audit

Exit code is 0 only when every required check passes. Reference-source checks
are reported but do not fail the run, because the external repos are optional —
the framework's own tools and skills work without them.
"""

from __future__ import annotations

import argparse
import importlib
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

FRAMEWORK_ROOT = Path(__file__).resolve().parent.parent
TOOLS = FRAMEWORK_ROOT / "tools"

#: Python version floor. The code uses ``X | None`` annotations and
#: ``dataclass`` features that need 3.10+, and is tested on 3.12.
MIN_PYTHON = (3, 10)


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    required: bool = True


def _run(args: Sequence[str], cwd: Path | None = None) -> tuple[int, str]:
    result = subprocess.run(
        [sys.executable, *args], cwd=str(cwd) if cwd else None,
        capture_output=True, text=True,
    )
    return result.returncode, ((result.stdout or "") + (result.stderr or "")).strip()


def check_environment() -> list[Check]:
    checks: list[Check] = []

    version = sys.version_info
    ok = version[:2] >= MIN_PYTHON
    checks.append(Check(
        "python version", ok,
        f"{version.major}.{version.minor}.{version.micro} (need >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]})",
    ))

    try:
        import yaml  # noqa: F401
        checks.append(Check("PyYAML", True, f"version {yaml.__version__}"))
    except ImportError:
        checks.append(Check(
            "PyYAML", False, "not installed - run: python -m pip install -r requirements.txt"
        ))

    git = shutil.which("git")
    checks.append(Check(
        "git", git is not None,
        git or "not on PATH - needed only by bootstrap.py for reference sources",
        required=False,
    ))

    return checks


def check_modules() -> list[Check]:
    """Every tool must import cleanly, and the package must expose its API."""
    expected = [
        "skillreg", "build_index", "validate_skills", "detect_collisions", "select_skills",
        "collectors", "evidence", "leads", "prerequisites", "gates", "cvss", "report",
        "pipeline", "audit_content", "install_dsh", "verify",
    ]
    if str(TOOLS) not in sys.path:
        sys.path.insert(0, str(TOOLS))

    failed: list[str] = []
    for name in expected:
        try:
            importlib.import_module(name)
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            failed.append(f"{name} ({type(exc).__name__}: {exc})")

    return [Check(
        "tool imports", not failed,
        f"{len(expected)} modules ok" if not failed else "failed: " + "; ".join(failed),
    )]


def check_tests() -> list[Check]:
    code, out = _run([str(FRAMEWORK_ROOT / "tests" / "test_framework.py")])
    tail = [line for line in out.splitlines() if line.startswith(("Ran ", "OK", "FAILED"))]
    return [Check("test suite", code == 0, " | ".join(tail) or out[-160:])]


def check_skill_lint() -> list[Check]:
    code, out = _run([str(TOOLS / "validate_skills.py"), str(FRAMEWORK_ROOT / "skills")])
    checked = next((line for line in out.splitlines() if line.startswith("checked")), "")
    counts = next((line for line in out.splitlines() if line.startswith("errors")), "")
    detail = " | ".join(part for part in (checked, counts) if part) or out[-160:]
    return [Check("skill lint", code == 0, detail)]


def check_content_audit() -> list[Check]:
    code, out = _run([str(TOOLS / "audit_content.py"), str(FRAMEWORK_ROOT / "skills"), "--severity", "high"])
    last = out.splitlines()[-1] if out else ""
    return [Check("self content-audit", code == 0, last or "no output")]


def check_index() -> list[Check]:
    index = FRAMEWORK_ROOT / "index.json"
    if not index.is_file():
        return [Check("skill index", False, "index.json absent - run: python tools/build_index.py")]
    import json
    data = json.loads(index.read_text(encoding="utf-8"))
    return [Check(
        "skill index", data.get("total_skills", 0) > 0,
        f"{data.get('total_skills', 0)} skills from {len(data.get('sources', []))} source(s)",
    )]


def check_references() -> list[Check]:
    """External sources are optional; report their state either way."""
    refs = FRAMEWORK_ROOT / "references"
    if not refs.is_dir():
        return [Check(
            "reference sources", True,
            "not bootstrapped (optional) - run: python bootstrap.py", required=False,
        )]
    present = [p.name for p in sorted(refs.iterdir()) if p.is_dir()]
    return [Check(
        "reference sources", True,
        f"{len(present)} present: {', '.join(present)}" if present else "empty (optional)",
        required=False,
    )]


def check_dsh_target() -> list[Check]:
    """Report where skills would install, without installing anything."""
    import os

    home = os.environ.get("DSH_HOME")
    base = Path(home) if home else Path.home() / ".dsh"
    target = base / "skills"
    exists = target.is_dir()
    return [Check(
        "dsh install target", True,
        f"{target} ({'exists' if exists else 'will be created'}) - install with: python tools/install_dsh.py install",
        required=False,
    )]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--full", action="store_true",
                        help="also audit the bootstrapped reference corpus (slow)")
    args = parser.parse_args(argv)

    checks: list[Check] = []
    checks += check_environment()
    checks += check_modules()
    checks += check_tests()
    checks += check_skill_lint()
    checks += check_content_audit()
    checks += check_index()
    checks += check_references()
    checks += check_dsh_target()

    if args.full:
        refs = FRAMEWORK_ROOT / "references"
        if refs.is_dir() and any(refs.iterdir()):
            code, out = _run([str(TOOLS / "audit_content.py"), str(refs), "--severity", "high"])
            # A non-zero exit here means the gate found hijack-family content in
            # third-party sources, which is information, not a failure of this
            # checkout.
            last = out.splitlines()[-1] if out else ""
            checks.append(Check("reference content-audit", True, f"{last} (informational)", required=False))

    width = max(len(c.name) for c in checks) + 2
    print(f"framework verification - {FRAMEWORK_ROOT}\n")
    for check in checks:
        mark = "PASS" if check.ok else ("FAIL" if check.required else "warn")
        print(f"  [{mark:4}] {check.name:<{width}} {check.detail}")

    required = [c for c in checks if c.required]
    failed = [c for c in required if not c.ok]
    print()
    if failed:
        print(f"{len(failed)} of {len(required)} required check(s) failed")
        return 1
    print(f"all {len(required)} required check(s) passed")
    print("\nnext steps:")
    print("  python bootstrap.py            # optional: fetch pinned reference sources")
    print("  python tools/build_index.py    # regenerate index.json")
    print("  python tools/install_dsh.py install --dry-run")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
