"""Audit ingested content for prompt injection and agent-directed risk.

This framework consumes third-party skill corpora: 800+ markdown files written
*by agents, for agents*. That is a hostile input class. Prose that reads as a
procedure to a human is executable instruction to a model, and the framework
surfaces this text into an agent's context by design — `select_skills.py` prints
descriptions, `build_index.py` indexes bodies, and installed skills load whole.

So the corpus must be audited like any other untrusted input.

WHAT THIS DETECTS
-----------------
Rules are grouped by the outcome an attacker wants, not by keyword:

* **override**      — attempts to replace the agent's instructions
* **introspection** — steering the agent to read its own system prompt or model
* **exfiltration**  — reading or transmitting credentials, keys, or agent config
* **permission**    — instructing the agent to skip confirmation or authorisation
* **stealth**       — instructing the agent to conceal its actions from the user
* **persistence**   — writing into agent configuration so the effect survives
* **toolabuse**     — unprompted destructive or remote-executing commands
* **obfuscation**   — zero-width characters, encoded blobs, hidden comments
* **network**       — session-start fetches and suspicious callback endpoints

THE FALSE-POSITIVE PROBLEM
--------------------------
Security writing legitimately contains the words *exploit*, *payload*, *bypass*,
*remote code execution*. A scanner that flags those is useless — it flags the
entire corpus and gets ignored. Rules here therefore match **agent-directed
phrasing** (imperatives addressed to a model, meta-instructions about the agent's
own context and credentials), never bare security vocabulary. A skill about SQL
injection should score zero.

Exit code is non-zero when any finding at or above ``--fail-on`` is present, so
this doubles as a gate over any corpus before it is ingested.

Usage:
    python tools/audit_content.py <path>... [--severity high] [--json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Sequence

__all__ = ["Finding", "Rule", "RULES", "audit_text", "audit_paths", "SEVERITY_ORDER"]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

#: Files this scanner reads. Binary and vendor trees are skipped.
TEXT_SUFFIXES = {".md", ".markdown", ".txt", ".json", ".yaml", ".yml", ".py", ".sh", ".js", ".toml"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache"}


#: How far back to look for a context that inverts a match's meaning.
CONTEXT_WINDOW = 90

#: Negation immediately before the trigger word. "run it silently" is an attack;
#: "rather than silently ignoring them" is a safety property.
_SUPPRESS_ANCHORED = re.compile(
    r"(?:rather\s+than|instead\s+of|as\s+opposed\s+to|avoid|avoids|never\b|do\s+not\b|don'?t\b|"
    r"must\s+not\b|should\s+not\b|cannot\b|not\b|no\s+longer\b|without\s+ever\b)\s*$",
    re.IGNORECASE,
)

#: Rejection or attribution vocabulary anywhere in the window. Security writing
#: necessarily *quotes* attacks in order to warn about them, and a review that
#: says "rejected: don't ask permission to probe" is the opposite of an attack.
_SUPPRESS_NEARBY = re.compile(
    r"\b(?:rejected|reject|refuse[d]?|prohibit(?:ed)?|forbidden|disallow(?:ed)?|malicious|"
    r"attacker|attack\s+example|injection|payload|quote[sd]?|verbatim|example\s+only|"
    r"never\s+permitted|not\s+permitted|do\s+not\s+do|anti-?pattern|warning|caution)\b",
    re.IGNORECASE,
)

_SUPPRESS_DEFAULT = _SUPPRESS_ANCHORED

#: Files never scanned. The auditor's own source contains every pattern it
#: searches for, as literals, so scanning it produces guaranteed false positives
#: at maximum severity. This is a property of any signature-based scanner, not a
#: loophole: the rule table is not attacker-controlled input.
SELF_SKIP = {"audit_content.py"}


# --------------------------------------------------------------------------- #
# Rule families — the calibration that makes this usable
# --------------------------------------------------------------------------- #
#
# MEASURED PROBLEM. Run against the ingested security corpus, the rule set
# produced 2,091 findings over 4,247 files, and manual review found that
# essentially all of them were legitimate offensive-security writing. A corpus
# that teaches agents to do security work necessarily contains the same strings
# as a corpus that tries to subvert them: "bypass authorization" is a
# vulnerability class, "do not use without explicit authorization" is a safety
# warning, and a skill for *detecting* zero-width characters must contain
# zero-width characters. Two rules alone (`tlb-sudo`, `tlb-install-untrusted`)
# accounted for 1,529 findings, or 73% of the total, by matching `sudo` and
# `pip install`.
#
# CONCLUSION. Attack *vocabulary* has no diagnostic value on a security corpus.
# What does have value is a **meta-instruction about the agent's own identity,
# context, or permissions** — language that has no defensive reading in a skill
# body. The families below encode that distinction, and only ``hijack`` should
# ever gate ingestion.

#: Meta-instructions about the agent itself. Low volume, low false-positive rate,
#: and the only family worth failing a build over.
HIJACK_RULES = frozenset({
    "ovr-ignore-previous", "ovr-new-instructions", "ovr-you-are-now", "ovr-stop-being",
    "int-system-prompt", "int-model-family",
    "per-dont-ask", "per-just-do-it", "per-write-config",
    "stl-dont-tell",
    "obs-bidi-control",
})

#: Context-free rules whose hits are dominated by ordinary technical prose.
NOISE_RULES = frozenset({
    "tlb-install-untrusted", "tlb-sudo", "per-install-hook",
    "obs-encoded-blob", "obs-long-line", "obs-zero-width",
})

def family_of(rule_id: str) -> str:
    """Classify a rule as ``hijack``, ``noise``, or ``vocabulary``."""
    if rule_id in HIJACK_RULES:
        return "hijack"
    if rule_id in NOISE_RULES:
        return "noise"
    return "vocabulary"


#: Per-rule suppression overrides: ``rule_id -> (window_chars, unanchored)``.
#: A wider, unanchored window catches prohibitions that sit a clause away, as in
#: "Do not use this skill on production devices without explicit authorization".
_SUPPRESS_OVERRIDES: dict[str, tuple[int, bool]] = {
    "per-no-auth": (220, True),
    "per-ignore-scope": (160, True),
    "stl-silently": (160, False),
    "per-dont-ask": (160, True),
}

#: Prohibition vocabulary used by the unanchored overrides.
_SUPPRESS_PROHIBITION = re.compile(
    r"\b(?:do\s+not|don'?t|never|must\s+not|should\s+not|only\s+(?:with|after|when|if)|"
    r"prohibited|forbidden|not\s+permitted|requires?\s+(?:written\s+)?(?:authorisation|authorization|permission)|"
    r"pitfall|avoid|without\s+updating|rejected|refuse)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Rule:
    """One detection rule.

    ``suppress`` is consulted over the text immediately preceding a match. If it
    matches there, the finding is dropped: the trigger word was being used in a
    prohibitive, contrastive, or quoted sense rather than as a directive.
    """

    id: str
    category: str
    severity: str
    why: str
    pattern: re.Pattern[str]
    suppress: re.Pattern[str] | None = None
    also_suppress_nearby: bool = True

    def as_dict(self) -> dict[str, str]:
        return {"id": self.id, "category": self.category, "severity": self.severity, "why": self.why}


def _r(
    id: str,
    category: str,
    severity: str,
    why: str,
    pattern: str,
    flags: int = re.IGNORECASE,
    suppress: re.Pattern[str] | None = _SUPPRESS_DEFAULT,
    also_suppress_nearby: bool = True,
) -> Rule:
    return Rule(
        id, category, severity, why, re.compile(pattern, flags), suppress, also_suppress_nearby
    )


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

RULES: tuple[Rule, ...] = (
    # --- instruction override -------------------------------------------------
    _r("ovr-ignore-previous", "override", "critical",
       "Tells the agent to discard its existing instructions.",
       r"\b(?:ignore|disregard|forget|override|discard)\b[^.\n]{0,40}\b(?:previous|prior|earlier|above|all)\b[^.\n]{0,20}\b(?:instruction|prompt|rule|direction|context)"),
    _r("ovr-new-instructions", "override", "high",
       "Announces a replacement instruction set addressed to the agent.",
       r"(?:^|[.;!?]\s+)(?:your\s+)?(?:new|updated|revised|real|actual)\s+(?:instructions?|system\s+prompt|directives?)\s*(?:are\b|[:=]\s*\S)"
       r"|^\s*(?:new|updated)\s+instructions?\s*:",
       flags=re.IGNORECASE | re.MULTILINE),
    _r("ovr-you-are-now", "override", "high",
       "Reassigns the agent's role mid-document.",
       r"\byou\s+are\s+now\s+(?:a|an|the|no longer)\b"),
    _r("ovr-stop-being", "override", "high",
       "Instructs the agent to abandon its current behaviour.",
       r"\b(?:stop|cease)\s+being\b|\bfrom\s+now\s+on\s+you\b"),

    # --- introspection --------------------------------------------------------
    _r("int-system-prompt", "introspection", "high",
       "Directs the agent to inspect its own system prompt or context.",
       r"\b(?:read|reveal|print|show|repeat|output|dump|inspect|detect)\b[^.\n]{0,30}\byour\s+(?:own\s+)?(?:system\s+prompt|instructions|context\s+window|hidden\s+prompt)"),
    _r("int-model-family", "introspection", "medium",
       "Directs the agent to identify its own model — a fingerprinting step with no legitimate task purpose.",
       r"\b(?:detect|identify|determine|discover|read)\b[^.\n]{0,30}\byour\s+(?:own\s+)?(?:model|model\s+family|provider|version)\b"),

    # --- exfiltration ---------------------------------------------------------
    # Requires an *action* against a credential target, not a bare mention of a
    # path. Documentation legitimately names these paths; only reading or
    # transmitting them is an attack. Matching the bare path flagged the
    # framework's own docs and every scanner's rule table.
    _r("exf-credentials", "exfiltration", "critical",
       "Combines accessing or transmitting agent/host credential stores with an action.",
       r"(?:(?:read|cat|open|load|dump|upload|post|send|exfiltrat\w*|steal|retrieve|copy|grab|print|scrape)\b[^\n]{0,60}"
       r"(?:\.credentials\.ya?ml|\.netrc|id_rsa|\.ssh/|\.aws/credentials|\.env\b|ANTHROPIC_AUTH_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY)"
       r"|(?:\.credentials\.ya?ml|\.netrc|id_rsa|\.aws/credentials)\b[^\n]{0,60}(?:curl|wget|POST|upload|send|base64)"
       r"|\b(?:export|set|env)\b[^\n]{0,30}(?:ANTHROPIC_AUTH_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY)"
       r"|api[_-]?key\s*[:=]\s*['\"]?sk-)"),
    _r("exf-send-secret", "exfiltration", "critical",
       "Combines reading a secret with sending it somewhere.",
       r"\b(?:curl|wget|fetch|requests\.post|Invoke-WebRequest|nc)\b[^.\n]{0,120}(?:\$\{?\w*(?:TOKEN|KEY|SECRET|PASS)\w*\}?|\.credentials|\.env\b|id_rsa)"),
    _r("exf-encode-then-send", "exfiltration", "high",
       "Encodes content then transmits it — a conventional cover for exfiltration.",
       r"\bbase64\b[^.\n]{0,80}\b(?:curl|wget|post|upload|send|fetch)\b|\b(?:curl|wget)\b[^.\n]{0,80}\bbase64\b"),
    _r("exf-env-dump", "exfiltration", "high",
       "Dumps the process environment, which holds live credentials.",
       r"\b(?:env|printenv|set)\b\s*(?:\|\s*(?:curl|wget|nc|base64))|\bGet-ChildItem\s+env:|\bos\.environ\b\s*\)?\s*(?:,#|\)\s*$)"),

    # --- permission / authorisation bypass -----------------------------------
    # Targets seeking *authorisation to proceed*, not generic "don't ask the
    # user" workflow rules. "Don't ask permission to probe" is the attack;
    # "do not ask the user for the resource guide" is housekeeping.
    _r("per-dont-ask", "permission", "critical",
       "Instructs the agent to skip authorisation or confirmation before acting.",
       r"(?:don'?t|do\s+not|never|no\s+need\s+to|without)\s+"
       r"(?:ask|wait|seek|get|obtain)\s+(?:for\s+)?(?:permission|authorisation|authorization|consent|approval|confirmation|sign[\s-]?off)"
       r"|\bskip\s+(?:the\s+)?(?:approval|confirmation|authorisation|authorization|permission|sign[\s-]?off)"
       r"|\bno\s+need\s+to\s+(?:ask|confirm|wait)\b"
       r"|\b(?:ask|seek|obtain)\s+permission\s+(?:later|afterwards|after)\b"),
    _r("per-just-do-it", "permission", "high",
       "Urges immediate action over deliberation.",
       r"\bjust\s+(?:do\s+it|go\s+ahead|run\s+it|try\s+it|send\s+it|probe)\b|\bno\s+need\s+to\s+wait\b"),
    _r("per-ignore-scope", "permission", "critical",
       "Encourages testing outside declared scope.",
       r"\b(?:ignore|forget|bypass|disregard|skip)\b[^.\n]{0,25}\b(?:scope|authorisation|authorization|rate\s+limit|policy|rules?\s+of\s+engagement)\b"),
    _r("per-no-auth", "permission", "high",
       "Describes acting without authorisation, in a non-prohibitive context.",
       r"\bwithout\s+(?:written\s+|explicit\s+|prior\s+)?(?:authorisation|authorization|permission|consent)\b"),

    # --- stealth --------------------------------------------------------------
    _r("stl-dont-tell", "stealth", "critical",
       "Instructs the agent to conceal its actions from the operator.",
       r"\b(?:do\s+not|don'?t|never)\b[^.\n]{0,25}\b(?:tell|inform|mention|notify|reveal|disclose|show)\b[^.\n]{0,25}\b(?:the\s+)?(?:user|human|operator|them)\b"),
    _r("stl-silently", "stealth", "high",
       "Instructs silent action.",
       r"(?:\b(?:silently|quietly|covertly|secretly)\s+(?:run|execute|perform|do|act|proceed|send|delete|modify|add|write|install|probe|scan|test)"
       r"|\b(?:run|execute|perform|do|act|proceed|send|delete|modify|write|install|probe|scan|test)\b[^.\n]{0,20}\b(?:silently|quietly|covertly|secretly)\b"
       r"|\bwithout\s+(?:telling|informing|notifying|mentioning)\b)"),

    # --- persistence ----------------------------------------------------------
    _r("per-write-config", "persistence", "high",
       "Writes into agent configuration so the behaviour survives the session.",
       r"(?m)^\s*(?:[-*+]\s*|\d+\.\s*)?(?:append|add|write|insert|persist)\s+(?:to\s+)?(?:your\s+|the\s+)?"
       r"(?:CLAUDE\.md|AGENTS\.md|\.cursorrules|settings\.ya?ml|cordis\.patch\.ya?ml|\.dsh/|system\s+prompt)\b"),
    _r("per-install-hook", "persistence", "high",
       "Registers a hook that executes automatically.",
       r"\b(?:SessionStart|PreToolUse|PostToolUse|UserPromptSubmit)\b|\bhooks?\.json\b"),

    # --- tool abuse -----------------------------------------------------------
    _r("tlb-remote-exec", "toolabuse", "critical",
       "Pipes a remote document straight into a shell.",
       r"\b(?:curl|wget)\b[^|\n]{0,120}\|\s*(?:sudo\s+)?(?:ba)?sh\b|\biex\s*\(|Invoke-Expression"),
    _r("tlb-destructive", "toolabuse", "high",
       "Unprompted destructive filesystem or git operation.",
       r"\brm\s+-rf\s+[~/]|\bgit\s+(?:reset\s+--hard|clean\s+-[a-z]*f)|\bRemove-Item\b[^\n]{0,40}-Recurse[^\n]{0,20}-Force"),
    _r("tlb-perms", "toolabuse", "medium",
       "Loosens filesystem permissions.",
       r"\bchmod\s+(?:777|666)\b|\bchown\s+root\b|\bicacls\b[^\n]{0,40}/grant\b"),
    _r("tlb-install-untrusted", "toolabuse", "medium",
       "Installs packages at runtime from an unvetted source.",
       r"\b(?:pip|npm|pnpm|yarn)\s+(?:install|i|add)\s+(?:--?\w+\s+)*[a-z0-9@/._-]+"),
    _r("tlb-sudo", "toolabuse", "medium",
       "Escalates privilege in a shell command.",
       r"(?:^|\s)sudo\s+\w|\bRunAs\s+Administrator\b"),

    # --- network --------------------------------------------------------------
    _r("net-session-fetch", "network", "high",
       "Fetches remote instruction content at session start, which may execute.",
       r"(?:session\s*start|at\s+startup|SessionStart|every\s+session)\b[^\n]{0,120}\b(?:curl|wget|fetch|download)\b"
       r"|\b(?:curl|wget|fetch|download)\b[^\n]{0,120}\b(?:instruction|rules?|prompt|policy|directive)s?\b[^\n]{0,60}https?://"),
    _r("net-callback-endpoints", "network", "medium",
       "References a disposable collection endpoint.",
       r"\b(?:webhook\.site|requestbin|pipedream\.net|ngrok\.io|transfer\.sh|pastebin\.com|0x0\.st|interact\.sh|burpcollaborator)\b"),
    _r("net-unknown-upload", "network", "medium",
       "Uploads local content to a remote endpoint.",
       r"\bcurl\b[^\n]{0,80}(?:-F|--data-binary|--upload-file|-T)\b"),
)


# --------------------------------------------------------------------------- #
# Structural checks (not regex over prose)
# --------------------------------------------------------------------------- #

_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD}
_BIDI_CONTROLS = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_LONG_LINE_THRESHOLD = 4000
_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{300,}={0,2}")


@dataclass
class Finding:
    """One detected risk."""

    rule_id: str
    category: str
    severity: str
    why: str
    path: str
    line: int
    snippet: str
    family: str = "vocabulary"

    def as_dict(self) -> dict[str, object]:
        return asdict(self)

    def __str__(self) -> str:
        return f"[{self.severity.upper():8}] {self.family:<10} {self.rule_id:<24} {self.path}:{self.line}  {self.snippet[:80]}"


def _line_of(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def _snippet(text: str, position: int, width: int = 160) -> str:
    start = max(0, position - width // 3)
    return " ".join(text[start : position + width].split())


def audit_text(text: str, path: str) -> list[Finding]:
    """Audit one document, returning every finding."""
    findings: list[Finding] = []

    for rule in RULES:
        for match in rule.pattern.finditer(text):
            if rule.suppress is not None:
                window_size, unanchored = _SUPPRESS_OVERRIDES.get(rule.id, (CONTEXT_WINDOW, False))
                window = text[max(0, match.start() - window_size) : match.start()]
                if unanchored:
                    # Prohibitions often sit a clause away from the trigger.
                    if _SUPPRESS_PROHIBITION.search(window):
                        continue
                elif rule.suppress.search(window):
                    continue
                if rule.also_suppress_nearby and _SUPPRESS_NEARBY.search(window):
                    continue
            findings.append(
                Finding(
                    rule_id=rule.id,
                    category=rule.category,
                    severity=rule.severity,
                    why=rule.why,
                    path=path,
                    line=_line_of(text, match.start()),
                    snippet=_snippet(text, match.start()),
                    family=family_of(rule.id),
                )
            )

    # Invisible characters used to hide instructions from human review.
    for index, char in enumerate(text):
        code = ord(char)
        if code in _ZERO_WIDTH:
            findings.append(Finding(
                "obs-zero-width", "obfuscation", "high",
                "Zero-width character: invisible to a human reviewer but visible to a model.",
                path, _line_of(text, index),
                f"U+{code:04X} at offset {index}: {' '.join(text[max(0,index-60):index+60].split())}",
            ))
            break
        if code in _BIDI_CONTROLS:
            findings.append(Finding(
                "obs-bidi-control", "obfuscation", "high",
                "Bidirectional control character can reorder displayed text so it reads differently than it executes.",
                path, _line_of(text, index), f"U+{code:04X} at offset {index}",
            ))
            break

    # Instructions hidden in HTML comments, which render as nothing in a viewer.
    for match in _HTML_COMMENT_RE.finditer(text):
        body = match.group(1)
        if re.search(r"(?i)\b(?:you\s+(?:must|should|are)|ignore|instruction|system\s+prompt|do\s+not\s+tell)\b", body):
            findings.append(Finding(
                "obs-hidden-comment", "obfuscation", "high",
                "Agent-directed language inside an HTML comment, which is invisible when the document is rendered.",
                path, _line_of(text, match.start()), " ".join(body.split())[:160],
            ))

    for match in _BASE64_BLOB_RE.finditer(text):
        findings.append(Finding(
            "obs-encoded-blob", "obfuscation", "medium",
            "Long encoded blob: content a reviewer cannot read without decoding it.",
            path, _line_of(text, match.start()), f"{len(match.group(0))} chars of base64-like data",
        ))
        break

    for number, line in enumerate(text.splitlines(), start=1):
        if len(line) > _LONG_LINE_THRESHOLD:
            findings.append(Finding(
                "obs-long-line", "obfuscation", "low",
                "Extremely long line: often used to push content out of a reviewer's view.",
                path, number, f"line of {len(line)} characters",
            ))
            break

    return findings


def _iter_files(paths: Iterable[Path]) -> Iterator[Path]:
    for path in paths:
        if path.is_file():
            yield path
            continue
        for candidate in sorted(path.rglob("*")):
            if not candidate.is_file():
                continue
            if any(part in SKIP_DIRS for part in candidate.parts):
                continue
            if candidate.suffix.lower() in TEXT_SUFFIXES:
                yield candidate


def audit_paths(paths: Sequence[Path]) -> tuple[list[Finding], int]:
    """Audit every text file under ``paths``. Returns ``(findings, files_scanned)``."""
    findings: list[Finding] = []
    scanned = 0
    for file in _iter_files(paths):
        if file.name in SELF_SKIP:
            continue
        try:
            if file.stat().st_size > 8 * 1024 * 1024:
                continue
            text = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        findings.extend(audit_text(text, str(file)))
    return findings, scanned


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--severity", default="info", choices=list(SEVERITY_ORDER),
                        help="minimum severity to report")
    parser.add_argument("--fail-on", default="critical", choices=list(SEVERITY_ORDER),
                        help="exit non-zero when a finding at or above this severity exists in the gate family")
    parser.add_argument("--gate-family", default="hijack", choices=["hijack", "vocabulary", "noise", "all"],
                        help="which rule family the exit code reflects (default: hijack, the only calibrated one)")
    parser.add_argument("--top", type=int, default=60, help="max findings to print")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--rules", action="store_true", help="list the rule set and exit")
    args = parser.parse_args(argv)

    if args.rules:
        for rule in RULES:
            print(f"{rule.severity.upper():8} {rule.id:<26} {rule.category:<14} {rule.why}")
        print(f"\n{len(RULES)} rule(s)")
        return 0

    findings, scanned = audit_paths(args.paths)

    threshold = SEVERITY_ORDER[args.severity]
    findings = [f for f in findings if SEVERITY_ORDER[f.severity] <= threshold]
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id, f.path, f.line))

    counts = Counter(f.severity for f in findings)
    categories = Counter(f.category for f in findings)
    by_rule = Counter(f.rule_id for f in findings)

    fail_level = SEVERITY_ORDER[args.fail_on]
    # Only the gate family drives the exit code. Failing a build on attack
    # vocabulary would fail every security corpus ever written.
    blocking = [
        f for f in findings
        if (args.gate_family == "all" or f.family == args.gate_family)
        and SEVERITY_ORDER[f.severity] <= fail_level
    ]

    if args.json:
        print(json.dumps({
            "files_scanned": scanned,
            "findings": len(findings),
            "by_family": dict(Counter(f.family for f in findings)),
            "by_severity": dict(counts),
            "by_category": dict(categories),
            "by_rule": dict(by_rule.most_common()),
            "blocking": len(blocking),
            "fail_on": args.fail_on,
            "gate_family": args.gate_family,
            "results": [f.as_dict() for f in findings],
        }, indent=2, ensure_ascii=False))
        return 1 if blocking else 0

    print(f"scanned {scanned} file(s); {len(findings)} finding(s)")
    print("by family:   " + (", ".join(f"{k}={v}" for k, v in Counter(f.family for f in findings).most_common()) or "none"))
    print("by severity: " + (", ".join(f"{k}={v}" for k, v in sorted(counts.items(), key=lambda kv: SEVERITY_ORDER[kv[0]])) or "none"))
    print("by category: " + (", ".join(f"{k}={v}" for k, v in categories.most_common()) or "none"))
    print()
    for finding in findings[: args.top]:
        print(f"  {finding}")
    if len(findings) > args.top:
        print(f"  ... and {len(findings) - args.top} more")

    if blocking:
        print(f"\n{len(blocking)} '{args.gate_family}' finding(s) at or above '{args.fail_on}'")
        return 1
    print(f"\nno '{args.gate_family}' finding at or above '{args.fail_on}'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
