"""Pre-submission gates: scope, duplication, and report self-triage.

The source material describes three families of gate in prose and implements
none of them. Prose gates get skipped under deadline pressure, so these are
executable: :class:`ScopeGate` refuses to proceed without a recorded
authorisation basis, :class:`DuplicateGate` deduplicates on the key that
actually identifies a finding, and :class:`TriageGate` lints a draft report for
the specific patterns that get submissions closed as AI slop.

Design stance: a gate returns a :class:`~evidence.GateResult` and never raises
on a policy failure. Callers decide whether to stop.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Any, Iterable, Sequence

from cvss import CvssError, score as cvss_score
from evidence import GateResult

__all__ = [
    "AssetBoundary",
    "Authorization",
    "DuplicateGate",
    "FindingKey",
    "HostVerdict",
    "ScopeGate",
    "TriageGate",
]

#: Absolute URLs embedded in a target's own artefacts. These routinely point at
#: analytics providers, CDNs, and *other customers'* hosts, so a collector that
#: cheerfully "resolves every endpoint it found" will send requests to systems
#: the program never authorised.
_URL_RE = re.compile(r"https?://([A-Za-z0-9._\-]+)(?::\d+)?", re.IGNORECASE)

#: Linear candidate scan for bare hosts. This deliberately replaces a
#: nested-quantifier domain pattern, which was quadratic on attacker-controlled
#: bundle text: a 40 KB run of ``a.a.a...`` took 26 seconds to reject. A simple
#: bounded character class cannot backtrack catastrophically, and the real
#: validation happens in Python where it is readable and provably linear.
_HOST_CANDIDATE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.\-]{1,252}")
_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

#: A bare dotted token in source code is usually a property access, not a host:
#: ``app.js.map``, ``axios.get`` and ``db.whereRaw`` all look like domains to a
#: naive regex. Requiring the final label to be an actual TLD removes essentially
#: all of that noise. This is a heuristic filter, not a public-suffix
#: implementation; it errs toward rejecting, and every rejection is reported so
#: a human can override it.
_TLD_SET = frozenset(
    """
    com net org edu gov mil int io dev app co ai cloud tech info biz pro name mobi
    me tv cc ly gg to sh fm am is li lu sk cz hu ro bg gr pt ie nl de fr uk se no dk
    fi pl be at ch it es us ca au nz za mx br ar cl sg hk tw kr th vn id my ph tr il
    sa ae eg ng ke pk bd lk np ru cn jp in eu asia xyz online site store shop blog
    page zone network systems solutions services group digital media agency studio
    design live life world today news email team works tools run host space website
    fun art zip mov travel jobs cats dev
    """.split()
)

#: Captured immediately after one of these characters, a dotted token is part of
#: a path or identifier rather than a hostname.
_HOST_PREFIX_BLOCKERS = frozenset('/\\-_@$"\'')


def _plausible_host(token: str) -> str | None:
    """Return a normalised hostname if ``token`` genuinely looks like one.

    Validation is explicit rather than regex-nested: at most ten labels, each
    RFC-1123 shaped (alphanumeric ends, hyphens inside, 63 characters maximum),
    a real-looking TLD, and a total length inside the DNS limit.
    """
    candidate = token.strip(".").lower()
    if "." not in candidate or len(candidate) > 253:
        return None
    labels = candidate.split(".")
    if not 2 <= len(labels) <= 10:
        return None
    if labels[-1] not in _TLD_SET:
        return None
    for label in labels:
        if not _LABEL_RE.fullmatch(label):
            return None
    return candidate


# --------------------------------------------------------------------------- #
# Scope / authorization
# --------------------------------------------------------------------------- #


@dataclass
class Authorization:
    """The recorded basis for testing. Nothing proceeds without this.

    ``policy_url`` and ``policy_seen`` are mandatory because "I read the rules
    somewhere" is not an authorisation basis, and program rules change: a class
    permitted last quarter may be excluded today.
    """

    program: str
    policy_url: str
    policy_seen: str  # ISO date the policy was read
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    excluded_classes: list[str] = field(default_factory=list)
    automated_scanning_allowed: bool = False
    max_severity_per_class: dict[str, str] = field(default_factory=dict)
    data_handling: str = ""

    def asset_in_scope(self, asset: str) -> tuple[bool, str]:
        """Wildcard-aware scope test. Explicit exclusions win over inclusions."""
        host = asset.strip().lower()
        for pattern in self.out_of_scope:
            if fnmatch(host, pattern.strip().lower()):
                return False, f"matches out-of-scope pattern {pattern!r}"
        for pattern in self.in_scope:
            if fnmatch(host, pattern.strip().lower()):
                return True, f"matches in-scope pattern {pattern!r}"
        return False, "does not match any in-scope entry (wildcards are exact; do not infer scope from a domain name)"


class ScopeGate:
    """Block work that lacks a recorded authorisation basis."""

    def __init__(self, authorization: Authorization | None) -> None:
        self.authorization = authorization

    def check(
        self,
        asset: str | None = None,
        *,
        bug_class: str | None = None,
        claimed_severity: str | None = None,
        uses_automation: bool = False,
    ) -> GateResult:
        result = GateResult(name="scope", passed=True)
        auth = self.authorization

        if auth is None:
            result.passed = False
            result.reasons.append(
                "no authorization record; share the program scope page before any probe is sent"
            )
            return result

        if not auth.policy_url.strip():
            result.passed = False
            result.reasons.append("authorization record has no policy URL")
        if not auth.policy_seen.strip():
            result.passed = False
            result.reasons.append("authorization record has no policy-seen date; rules change between programs and quarters")
        if not auth.in_scope:
            result.passed = False
            result.reasons.append("authorization record lists no in-scope assets")

        if asset:
            allowed, why = auth.asset_in_scope(asset)
            if not allowed:
                result.passed = False
                result.reasons.append(f"asset {asset!r}: {why}")

        if bug_class:
            lowered = bug_class.strip().lower()
            for excluded in auth.excluded_classes:
                if excluded.strip().lower() == lowered:
                    result.passed = False
                    result.reasons.append(f"bug class {bug_class!r} is excluded by this program")

        if uses_automation and not auth.automated_scanning_allowed:
            result.passed = False
            result.reasons.append(
                "automated scanning is not permitted by this program; sqlmap and similar tools are out"
            )

        if bug_class and claimed_severity:
            cap = auth.max_severity_per_class.get(bug_class.strip().lower())
            if cap and _severity_rank(claimed_severity) > _severity_rank(cap):
                result.passed = False
                result.reasons.append(
                    f"claimed severity {claimed_severity} exceeds this program's cap of {cap} for class {bug_class!r}; "
                    "overclaiming is itself a reason for closure"
                )

        if not auth.data_handling.strip():
            result.warnings.append("no data-handling/retention rule recorded; confirm before storing evidence")

        return result


_SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]


def _severity_rank(value: str) -> int:
    try:
        return _SEVERITY_ORDER.index(value.strip().lower())
    except ValueError:
        return -1


# --------------------------------------------------------------------------- #
# Asset boundary
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class HostVerdict:
    """Whether a discovered host may be contacted, and why."""

    host: str
    allowed: bool
    reason: str
    seen_in: tuple[str, ...] = ()

    def __str__(self) -> str:
        state = "allow" if self.allowed else "BLOCK"
        where = f" (seen in {', '.join(self.seen_in)})" if self.seen_in else ""
        return f"[{state}] {self.host}: {self.reason}{where}"


class AssetBoundary:
    """Enforce scope on hosts *discovered* rather than hosts *declared*.

    The scope page lists the assets you may test. It does not list the hundreds
    of hosts embedded in a target's own JavaScript, and those routinely include
    analytics providers, CDNs, documentation sites, and hosts belonging to other
    customers of the same platform. A pipeline that "resolves every endpoint it
    found in the bundle" will therefore send requests to systems nobody
    authorised, which turns a bug hunt into unauthorised access.

    This class treats discovery as untrusted: every host extracted from an
    artefact must independently satisfy the authorisation record. Unknown hosts
    are blocked by default, because the absence of an exclusion is not
    permission.
    """

    def __init__(self, authorization: "Authorization | None", *, allow_subdomains_of_scope: bool = True) -> None:
        self.authorization = authorization
        self.allow_subdomains = allow_subdomains_of_scope

    def classify(self, host: str, *, seen_in: Sequence[str] = ()) -> HostVerdict:
        """Decide whether one host may be contacted."""
        cleaned = host.strip().lower().rstrip(".")
        if ":" in cleaned:  # strip a port
            cleaned = cleaned.split(":", 1)[0]
        if not cleaned:
            return HostVerdict(cleaned, False, "empty host", tuple(seen_in))

        if self.authorization is None:
            return HostVerdict(
                cleaned, False,
                "no authorization record; discovered hosts are blocked until scope is recorded",
                tuple(seen_in),
            )

        allowed, why = self.authorization.asset_in_scope(cleaned)
        if allowed:
            return HostVerdict(cleaned, True, why, tuple(seen_in))

        # An explicit exclusion always wins over a wildcard include or the
        # subdomain fallback below. Getting this wrong would send requests to a
        # host the program named as out of bounds, which is the single worst
        # mistake this class exists to prevent.
        for pattern in self.authorization.out_of_scope:
            if fnmatch(cleaned, pattern.strip().lower()):
                return HostVerdict(
                    cleaned, False,
                    f"explicitly excluded by out-of-scope pattern {pattern!r}; "
                    "an exclusion always overrides a wildcard include",
                    tuple(seen_in),
                )

        # A host under an in-scope apex is normally covered by the program's
        # wildcard, but only when the apex itself is listed.
        if self.allow_subdomains:
            for pattern in self.authorization.in_scope:
                apex = pattern.strip().lower().lstrip("*.")
                if apex and (cleaned == apex or cleaned.endswith("." + apex)):
                    return HostVerdict(
                        cleaned, True, f"subdomain of in-scope apex {apex!r}", tuple(seen_in)
                    )

        return HostVerdict(
            cleaned, False,
            f"{why}; discovered inside a target artefact and NOT independently in scope",
            tuple(seen_in),
        )

    def hosts_in(self, texts: Iterable[tuple[str, str]]) -> dict[str, list[str]]:
        """Extract hosts from artefacts, mapping each to where it was seen.

        Absolute URLs are trusted as hosts. Bare dotted tokens are accepted only
        when the final label is a plausible TLD *and* the token is not part of a
        path or identifier, which keeps ``app.js.map`` and ``axios.get`` out of
        the results.
        """
        found: dict[str, list[str]] = {}
        for label, text in texts:
            for match in _URL_RE.finditer(text):
                found.setdefault(match.group(1).lower().rstrip("."), []).append(label)

            for match in _HOST_CANDIDATE_RE.finditer(text):
                before = text[match.start() - 1] if match.start() else ""
                if before in _HOST_PREFIX_BLOCKERS:
                    continue
                host = _plausible_host(match.group(0))
                if host:
                    found.setdefault(host, []).append(label)
        return found

    def partition(self, texts: Iterable[tuple[str, str]]) -> tuple[list[HostVerdict], list[HostVerdict]]:
        """Return ``(allowed, blocked)`` verdicts for every host in ``texts``."""
        allowed: list[HostVerdict] = []
        blocked: list[HostVerdict] = []
        for host, seen in sorted(self.hosts_in(texts).items()):
            verdict = self.classify(host, seen_in=sorted(set(seen)))
            (allowed if verdict.allowed else blocked).append(verdict)
        return allowed, blocked

    def check(self, texts: Iterable[tuple[str, str]]) -> GateResult:
        """Gate result for the hosts discovered in ``texts``.

        Always passes; the point is to hand the caller the block list rather
        than to stop collection. Contacting a blocked host is a separate,
        deliberate act that the caller must not perform.
        """
        allowed, blocked = self.partition(texts)
        result = GateResult(name="asset-boundary", passed=True)
        if blocked:
            result.warnings.append(
                f"{len(blocked)} discovered host(s) are outside the recorded scope and must not be contacted: "
                + ", ".join(v.host for v in blocked[:10])
                + (" ..." if len(blocked) > 10 else "")
            )
        else:
            result.warnings.append(f"all {len(allowed)} discovered host(s) fall inside the recorded scope")
        return result


# --------------------------------------------------------------------------- #
# Duplication
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class FindingKey:
    """The identity of a finding for duplication purposes.

    All three components are required. Deduplicating on endpoint alone merges
    distinct bugs at one URL; deduplicating on class alone merges the same bug
    across hosts. The source material advertised this triple but implemented
    coarser keys, which is why this is a first-class type here.
    """

    target: str
    location: str
    bug_class: str

    def normalised(self) -> "FindingKey":
        return FindingKey(
            target=self.target.strip().lower(),
            location=re.sub(r"\s+", " ", self.location.strip().lower()),
            bug_class=self.bug_class.strip().lower(),
        )

    def as_tuple(self) -> tuple[str, str, str]:
        n = self.normalised()
        return (n.target, n.location, n.bug_class)

    def __str__(self) -> str:
        return " | ".join(self.as_tuple())


class DuplicateGate:
    """Detect intra-session duplicates and require a prior-disclosure check."""

    def __init__(self, known: Iterable[FindingKey] = ()) -> None:
        self._seen: dict[tuple[str, str, str], int] = {}
        for key in known:
            self.record(key)

    def record(self, key: FindingKey) -> int:
        slot = key.as_tuple()
        self._seen[slot] = self._seen.get(slot, 0) + 1
        return self._seen[slot]

    def check(
        self,
        key: FindingKey,
        *,
        prior_report_check: str | None = None,
        known_issue_list_checked: bool = False,
    ) -> GateResult:
        """``prior_report_check`` describes what was searched and what was found."""
        result = GateResult(name="duplicate", passed=True)

        existing = self._seen.get(key.as_tuple(), 0)
        if existing:
            result.passed = False
            result.reasons.append(
                f"already recorded {existing} time(s) in this session for key: {key}"
            )

        if not prior_report_check or not prior_report_check.strip():
            result.passed = False
            result.reasons.append(
                "no prior-disclosure check recorded; search the program's known/duplicate list and "
                "public disclosures on this exact surface, then record what you searched"
            )
        if not known_issue_list_checked:
            result.passed = False
            result.reasons.append("program known-issues / hacktivity list not checked")

        # Near-duplicate warning: same target and class, different location.
        target, _location, bug_class = key.as_tuple()
        neighbours = [
            slot for slot in self._seen
            if slot[0] == target and slot[2] == bug_class and slot[1] != _location
        ]
        if neighbours:
            result.warnings.append(
                f"{len(neighbours)} prior finding(s) on {key.target} in class {key.bug_class!r}; "
                "a triager may treat these as one root cause — consider merging into a single report"
            )

        return result


# --------------------------------------------------------------------------- #
# Report self-triage
# --------------------------------------------------------------------------- #

#: Phrases that assert impact nobody demonstrated.
THEORETICAL_IMPACT = (
    r"\bcould lead to\b",
    r"\bmay allow\b",
    r"\bmight allow\b",
    r"\bcould allow\b",
    r"\bpotentially\s+\w+",
    r"\ban attacker with the right conditions\b",
    r"\bwould enable\b",
    r"\bcould result in\b",
    r"\bleading to (?:full|complete|total)\b",
)

#: Confidence asserted without a measurement behind it.
UNSUPPORTED_CONFIDENCE = (
    r"\bclearly\s+(?:vulnerable|exploitable|broken)\b",
    r"\bobviously\b",
    r"\bdefinitely\s+(?:vulnerable|exploitable)\b",
    r"\btrivially\s+exploitable\b",
)

#: Structural boilerplate that marks a machine-written report.
AI_STRUCTURE = (
    r"^#+\s*introduction\b",
    r"^#+\s*background\b",
    r"^#+\s*executive summary\b",
    r"^#+\s*conclusion\b",
    r"\bvalidate (?:all )?user input\b",
    r"\bfollow (?:the )?owasp\b",
    r"\bimplement (?:proper )?input sanitization\b",
)

PLACEHOLDER = (
    r"\bTODO\b", r"\bTBD\b", r"\bFIXME\b", r"<[a-z][a-z0-9 _-]{2,30}>", r"\bXXX\b",
)

#: Sections a submission-ready report must contain, matched loosely.
REQUIRED_SECTIONS = {
    "description": (r"^#+\s*\d*\.?\s*description", r"^#+\s*summary"),
    "reproduction": (r"^#+\s*\d*\.?\s*(?:steps to reproduce|reproduction|proof of concept|poc)\b",),
    "impact": (r"^#+\s*\d*\.?\s*impact\b",),
}


def _find_any(patterns: Sequence[str], text: str) -> str | None:
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            return match.group(0)
    return None


@dataclass
class TriageReport:
    """Deterministic self-triage outcome."""

    verdict: str
    result: GateResult

    def __str__(self) -> str:
        lines = [f"VERDICT: {self.verdict}", str(self.result)]
        return "\n".join(lines)


class TriageGate:
    """Lint a draft report before it is submitted.

    Deliberately mechanical. A model asked "is this ready?" tends to say yes;
    a regex over the draft does not care about tone.
    """

    def check(
        self,
        draft: str,
        *,
        cvss_vector: str | None = None,
        claimed_severity: str | None = None,
        boundary_named: bool = False,
        poc_present: bool = False,
    ) -> TriageReport:
        result = GateResult(name="triage", passed=True)

        if not draft.strip():
            result.passed = False
            result.reasons.append("draft is empty")
            return TriageReport("DO NOT SUBMIT", result)

        for name, patterns in REQUIRED_SECTIONS.items():
            if not _find_any(patterns, draft):
                result.passed = False
                result.reasons.append(f"missing required section: {name}")

        hit = _find_any(THEORETICAL_IMPACT, draft)
        if hit:
            result.passed = False
            result.reasons.append(
                f"theoretical impact phrasing {hit!r}; state only what the proof demonstrated, "
                "or label the claim explicitly as unverified"
            )

        hit = _find_any(UNSUPPORTED_CONFIDENCE, draft)
        if hit:
            result.warnings.append(f"unsupported confidence {hit!r}; attach the measurement that justifies it")

        hit = _find_any(AI_STRUCTURE, draft)
        if hit:
            result.warnings.append(f"boilerplate detected {hit!r}; remove scaffolding that adds no evidence")

        hit = _find_any(PLACEHOLDER, draft)
        if hit:
            result.passed = False
            result.reasons.append(f"unfilled placeholder {hit!r}")

        if not poc_present:
            result.passed = False
            result.reasons.append(
                "no proof of concept confirmed present; a triager with zero context must be able to replay it"
            )
        if not boundary_named:
            result.passed = False
            result.reasons.append(
                "the query-construction boundary crossed is not named; this is the core of a modern "
                "SQL injection report and its absence reads as a scanner dump"
            )

        if cvss_vector:
            try:
                computed = cvss_score(cvss_vector)
            except CvssError as exc:
                result.passed = False
                result.reasons.append(f"CVSS vector rejected: {exc}")
            else:
                result.warnings.extend(computed.notes)
                if claimed_severity and computed.severity.lower() != claimed_severity.strip().lower():
                    result.passed = False
                    result.reasons.append(
                        f"claimed severity {claimed_severity!r} disagrees with the vector, "
                        f"which scores {computed.base_score:.1f} ({computed.severity})"
                    )
        elif claimed_severity:
            result.warnings.append(
                f"severity {claimed_severity!r} claimed with no CVSS vector; supply metrics so the score is reproducible"
            )

        if result.passed and not result.warnings:
            verdict = "READY TO SUBMIT"
        elif result.passed:
            verdict = "NEEDS FIXES"
        else:
            verdict = "DO NOT SUBMIT"

        return TriageReport(verdict, result)
