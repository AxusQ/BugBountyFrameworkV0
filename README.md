# Bug Bounty Agent Framework

A portable, evidence-driven framework for authorised bug bounty hunting,
assembled from four reference repositories and a body of prior SQL injection
research. It provides four things the source material did not have together:

1. **A skill registry** that reads the agentskills/DSH contract correctly, merges
   many sources with deterministic collision resolution, and keeps the
   diagnostics the harness throws away.
2. **An evidence model** in which no claim survives without a controlled
   measurement, and an unresolved question always outranks a wrong negative.
3. **Executable gates** between phases, so authorisation, evidence quality,
   duplication, and report readiness are enforced by code rather than described
   in prose.
4. **A deterministic gathering layer**, so model usage scales with promising
   leads rather than with the size of the scan.

Nothing here sends network requests, runs exploitation tooling, or submits
reports. The framework records, judges, and refuses to let a claim advance
without support.

**This repository is private and carries no license grant.** All rights reserved.

## Quick start on a new host

```bash
git clone https://github.com/AxusQ/BugBountyFrameworkV0
cd BugBountyFrameworkV0
python -m pip install -r requirements.txt

python tools/verify.py          # validates the checkout; add --full to audit references
python bootstrap.py             # optional: fetch the pinned reference sources
python tools/install_dsh.py install --dry-run
```

`tools/verify.py` is the entry point on an unfamiliar machine: it checks the
Python version, PyYAML, git, that all 14 tools import, the 129-test suite, the
skill lint, the self content-audit, and the index — then prints one summary.
External reference sources are reported but never fail the run, because the
framework's own tools and skills work without them.

## Layout

```
framework/                    <- this repository's root
  tools/          the framework (Python 3.10+, PyYAML)
  skills/         portable skills in agentskills/DSH format
  corpus/         external source registry (sources.yaml)
  tests/          129 tests, plus labelled fixtures
  references/     pinned external sources (gitignored, fetched by bootstrap.py)
  index.json      generated merged catalog
  bootstrap.py    fetches reference sources at pinned commits
  requirements.txt
```

`references/` is gitignored on purpose. One of the four sources,
`bountyforge`, carries **no license grant at all**, so republishing it here would
be a licensing problem; `claude-kit` is GPL-3.0-or-later and vendoring it would
impose copyleft on this repository. Cloning them locally for reference is fine,
which is what `bootstrap.py` does — at pinned commits, so the corpus is
reproducible rather than a fork that rots.

## Skills

Six portable skills ship in the repository, so a fresh clone is self-contained —
including the SQLi method the others defer to:

| Skill | Role |
|---|---|
| `sqli-bug-bounty` | **the method**: recon, surface inventory, value-vs-structure, oracle choice, boundary naming, reporting. Carries six references (recon, surface-catalog, blindspots, detection, case-studies, reporting) |
| `bounty-hunt-run` | pipeline driver across the seven phases |
| `bounty-recon-collect` | deterministic gathering, model-free |
| `sqli-surface-triage` | ranks evidence into testable hypotheses; records leads |
| `sqli-oracle-probe` | paired test/control experiments; judges the result |
| `sqli-boundary-report` | prerequisite ledger, counterevidence, CVSS, platform emission |

The three SQLi pipeline skills deliberately do **not** restate the method. Each
carries an explicit negative trigger — *"for the SQL injection method itself, use
`sqli-bug-bounty`"* — so the two do not compete for the same request. That is why
`sqli-bug-bounty` is vendored here rather than left as an external expectation:
without it those triggers point at nothing.

Skills are indexed from the working tree at the highest rank. If you also install
a copy into `<dshHome>/skills`, the repository copy wins the name collision and
the registry reports the shadowed one rather than failing — so an installed copy
cannot silently override what this repository says.

## The tools

| Tool | Does |
|---|---|
| `skillreg.py` | scans skill roots one level deep, parses frontmatter with PyYAML, validates names/descriptions/invocation flags, merges by root rank |
| `build_index.py` | builds `index.json` across all configured sources |
| `validate_skills.py` | contract plus quality lint; non-zero exit doubles as a CI gate |
| `detect_collisions.py` | name collisions and *trigger* collisions between differently named skills |
| `select_skills.py` | ranks catalog skills against a task, honouring negative triggers |
| `collectors.py` | deterministic JS/API surface extraction, snapshot diffing, freshness ranking |
| `evidence.py` | oracle classification, control baselines, redaction, hash-chained provenance |
| `leads.py` | lead lifecycle with a kill guard that refuses one-sided refutations |
| `prerequisites.py` | attacker-reachability ledger and the counterevidence gate |
| `gates.py` | scope gate, asset boundary, duplicate gate, report self-triage |
| `cvss.py` | CVSS v3.1 base score calculator (verified against reference vectors) |
| `report.py` | HackerOne / Bugcrowd / Intigriti / Immunefi / generic emitters |
| `pipeline.py` | phase driver: authorise → gather → hypothesise → probe → gate → deduplicate → report |
| `audit_content.py` | audits ingested content for prompt injection and agent-directed risk |
| `install_dsh.py` | installs the skills into a DSH-scanned root |

## Install into DSH

DSH discovers skills from fixed roots, one level deep, and watches them:

```
<dshHome>/skills/<name>/SKILL.md        rank 400   <- install_dsh.py targets this
<projectRoot>/.dsh/skills/<name>/SKILL.md   rank 100
```

```bash
python tools/install_dsh.py install --dry-run
python tools/install_dsh.py install
python tools/install_dsh.py check
python tools/install_dsh.py uninstall
```

The installer targets `<DSH_HOME>/skills` (or `~/.dsh/skills`). It deliberately
does **not** target the project root, because DSH resolves `projectRoot` as the
nearest ancestor containing `.git` — and if a checkout happens to sit under a
directory whose ancestor has `.git` (on Windows, `C:\` itself), that resolves to
an unrelated path and would scatter harness state across the filesystem root.

Because DSH watches the root, installed skills appear in the session catalog
without a restart. `--link` creates a directory junction instead of copying, so
the checkout stays the single source of truth. `uninstall` removes only
directories carrying the framework's own marker file.

For copy-free discovery of the working tree, `install_dsh.py print-config`
emits the `customSkillDirs` snippet for the DSH profile patch file. It is not
applied automatically — editing harness configuration is your decision.

**Platform notes.** On Windows the linker uses `mklink /J`, which needs no
elevation; path arguments are quoted and shell metacharacters rejected, because
`subprocess.list2cmdline` does not quote `&`, `|` or `^`. On POSIX the installer
uses symlinks instead.

## Usage

```bash
python tools/pipeline.py status <target>
python tools/pipeline.py authorise <target> --scope-file scope.json
python tools/pipeline.py gather  <target> --js bundle.js
python tools/pipeline.py hypothesise <target>
python tools/pipeline.py gate    <target> --boundary "ORDER BY identifier position"
python tools/pipeline.py verify  <target>
```

```bash
python tools/verify.py                     # all gates in one command
python tests/test_framework.py -v          # 129 tests
python tools/validate_skills.py skills
python tools/audit_content.py skills       # prompt-injection self-check
python tools/detect_collisions.py --threshold 0.5
python tools/select_skills.py --class sqli --top 12
python tools/build_index.py
python bootstrap.py --check
```

## The invariants this framework enforces

These are the load-bearing rules. Each is covered by tests.

1. **One-level discovery.** Only `<root>/<name>/SKILL.md` and `<root>/<name>.md`
   are skills. Nested trees are deliberately invisible, matching DSH.
2. **PyYAML for frontmatter, never a regex.** Skill descriptions legally span
   multiple lines. The source corpus records that three hand-rolled regex
   parsers truncated 604 of 817 descriptions to their first line.
3. **A bad invocation flag drops the whole skill.** `disable-model-invocation`
   and `user-invocable` accept YAML booleans plus the documented spellings; a
   rejected value removes the skill rather than silently permitting a surface.
4. **No signal without a control.** A differential or timing claim with no paired
   null variant is `UNKNOWN`, however clean it looked.
5. **Unknown beats refuted.** Missing or ambiguous measurements are never
   `REFUTED`. Refutation needs repeated positive evidence of no effect.
6. **An oracle that fires in the control does not separate.** Reported as
   `UNKNOWN` — likely caching or a shared baseline.
7. **Refutation of a lead requires both arms.** The kill guard refuses a
   one-sided kill and parks the lead with a counter instead.
8. **One variable per probe.** Confounded mutations are flagged.
9. **Discovered hosts are untrusted.** Hosts found inside a target's own
   artefacts must independently satisfy the scope record. With no authorization
   recorded, everything is blocked.
10. **An explicit exclusion beats a wildcard include.**
11. **Severity follows the vector.** A stated severity disagreeing with its own
    CVSS vector is a validation error that blocks emission.
12. **No report without a named boundary.** An otherwise clean observation with
    no query-construction seam named is blocked.
13. **Redaction at record time.** Unredacted third-party data never reaches an
    artifact on disk.
14. **Every action is hash-chained.** Tamper-evident, not tamper-proof.
15. **A run target cannot leave the runs root.** Validated against a hostname
    grammar and re-checked for containment after resolution.
16. **Artifact scanning is linear.** Bundle text is attacker-controlled, so no
    regex may backtrack catastrophically on it.
17. **Parsed metadata is bounded.** Aliased YAML that would expand on
    serialisation is rejected at discovery, not at index time.
18. **Nothing discovered is executed.** No lifecycle scripts, no `os.system`,
    no `eval`; the only subprocess call is the hardened `mklink`, and installing
    copies data into the skill root, never code.
19. **Only the hijack family gates ingestion.** Attack vocabulary is not
    evidence of an attack on a corpus whose purpose is attack.
20. **A demonstrated primitive is not a finding.** Every value, role, state, or
    action an attacker needs must be shown obtainable through an in-scope path
    before the finding is provable.
21. **A negative prerequisite is an open question until the hunt is documented.**
    `NOT_REACHABLE` without a written acquisition hunt is downgraded to
    `UNVERIFIED` — failing to obtain something is not evidence it cannot be
    obtained. The same asymmetry as `UNKNOWN`-beats-`REFUTED`, one level up.
22. **A proven finding must argue against itself.** The strongest benign
    explanation, the control that ruled it out, and one fact that would change
    the severity are all required; placeholders block the claim.
23. **Report emission is chained to the gates before it.** `emit()` refuses
    unless at least one observation cleared the evidence bar, any prerequisite
    ledger that was evaluated is `PROVEN`, and a duplication check was recorded
    and passed. There is no bypass flag — an ungated render is
    `report.render()`, called explicitly rather than concealed behind a switch.

## Source provenance and licensing

This framework **references** its sources rather than forking them. That is a
licensing requirement as much as an engineering choice.

| Source | License | What was taken |
|---|---|---|
| [Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | Apache-2.0 | packaging standard, validation approach, the PyYAML lesson. Permissive; vendoring allowed with attribution. |
| [claude-kit](https://github.com/yeswehack/claude-kit) | **GPL-3.0-or-later** | the evidence-discipline *policies*, reimplemented in original wording. Copyleft: its prose was **not** copied. |
| [bountyforge](https://github.com/Gabson0x/bountyforge) | **none — all rights reserved** | the oracle/control and lead-lifecycle *designs*, reimplemented from scratch. No LICENSE file exists, so reuse of its content requires the author's permission. |
| [bug-bounty-hunting-prompts](https://github.com/mdpsec/bug-bounty-hunting-prompts) | see its LICENSE | the phase-pipeline shape. Deliberately non-runnable without the author's private infrastructure. |

Only `bountyforge/skills/pashov` and `bountyforge/skills/web3` are MIT-licensed
subtrees; the engine carries no grant at all.

**Two defects found in the source material, worth knowing before reuse:**
`bountyforge/skills/pashov` and `bountyforge/skills/web3` contain no `SKILL.md`
and are therefore invisible to DSH; and `bountyforge/skills/godmod/SKILL.md` has
no YAML frontmatter, so DSH drops it silently.

## Safety

This framework is for authorised testing only. It encodes that requirement
rather than assuming it: the gather phase refuses to run without a recorded
authorization basis, discovered hosts are blocked unless independently in scope,
and the scope gate refuses automation where a program disallows it.

One caution about the source material: `bountyforge` instructs agents to
"not ask permission to probe — just do it." That directive is incompatible with
the authorization-first discipline this framework enforces, and it should not be
carried over.

## Security sweep

The framework was audited before its skills were installed into DSH, because a
tool that ingests third-party agent-authored prose and then surfaces it into an
agent's context is itself an attack surface. Five vulnerabilities were found in
the framework's own code and fixed; all are covered by regression tests.

| # | Vulnerability | Impact | Fix |
|---|---|---|---|
| 1 | **Path traversal via run target** | `Path(root) / "/etc/pwned"` discards the root in pathlib, and `../` walks up, so an unvalidated target gave a **write-anywhere primitive** over every artifact the pipeline produces — scope, evidence, observations, reports | `safe_target_slug()` validates the target against a hostname grammar, plus a containment re-check on the resolved path |
| 2 | **ReDoS in host extraction** | A nested-quantifier domain regex was quadratic on attacker-controlled bundle text: 40 KB of `a.a.a…` took **26.5 s to reject** | Replaced with a linear candidate scan plus explicit label validation; same input now takes **0.0007 s** |
| 3 | **YAML alias bomb** | PyYAML resolves aliases to shared references, so a **316-byte** `SKILL.md` expanded to **26.9 MB of JSON in 6.6 s** the moment the index builder serialised it | `check_expansion()` counts dereferences as serialisation would and rejects at discovery |
| 4 | **Unbounded skill read** | An oversized `SKILL.md` in any ingested source was read wholly into memory | 2 MiB limit enforced before reading |
| 5 | **`cmd.exe` argument injection** | `subprocess.list2cmdline` quotes only on whitespace, so a source directory named `evil&calc` reached cmd.exe as live metacharacters — relevant precisely because installing from a third-party path is the point | Paths are quoted and metacharacters rejected; bundle names must be kebab-case |

### Prompt injection in ingested content

`audit_content.py` scans the corpus for agent-directed risk across nine
categories: instruction override, self-introspection, exfiltration, permission
bypass, concealment, persistence, tool abuse, obfuscation, and network fetches.

**The calibration matters more than the rules.** A naive scanner reported 2,091
findings across the 4,247 ingested files, and essentially all of them were
legitimate offensive-security writing: `sudo` and `pip install` alone accounted
for 1,529 findings (73%), and the rest matched security *vocabulary* — "bypass
authorization" is a vulnerability class, "do not use without explicit
authorization" is a safety warning, and a skill for *detecting* zero-width
characters necessarily contains zero-width characters. A corpus that teaches
agents to do security work contains the same strings as one that tries to subvert
them.

Rules are therefore split into three families, and **only one gates ingestion**:

- **`hijack`** (28 findings) — meta-instructions about the agent's own identity,
  context, or permissions. This is what the exit code reflects.
- **`noise`** (1,532) — context-free rules dominated by ordinary technical prose.
- **`vocabulary`** (389) — real vocabulary requiring human judgement.

Of the 28 hijack findings, 27 are explainable: prompt-injection *detection*
skills necessarily contain attack strings as test data, and the mdpsec phase pack
contains defensive prose. **One is genuine**: `bountyforge`'s vendored
`pashov/solidity-auditor/SKILL.md:39` instructs the agent to *"Read your system
prompt to detect your own model family"* and then use that to mark its own family
as "(Recommended)" in a question posed to the user — self-introspection used to
bias an operator's choice.

Verified precision: the framework's own 21 files produce **zero** hijack
findings, and the labelled positive-control fixture trips all nine categories.

### What was checked and found clean

- **No auto-execution path.** No `package.json` lifecycle scripts exist in any
  ingested repo, so nothing runs on install. `claude-kit/hooks/hooks.json` is a
  Claude Code `SessionStart` hook that only `cat`s a markdown file, and DSH does
  not read it. The corpus does contain two `.ps1` deploy scripts, which is
  exactly why the framework never executes anything it discovers.
- **The framework itself executes almost nothing.** One `subprocess` call in
  total (the hardened `mklink`); no `os.system`, `exec`, `eval`, or
  `__import__` anywhere. Installing copies `SKILL.md` files and a metadata
  marker — no Python enters the skill root.
- **No credentials, keys, or real hosts** in the mdpsec pack; `bountyforge`
  requests `ANTHROPIC_AUTH_TOKEN` in its own setup, which the framework does not
  follow.
