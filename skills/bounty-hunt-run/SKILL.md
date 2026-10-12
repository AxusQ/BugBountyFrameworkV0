---
name: bounty-hunt-run
description: Drive the end-to-end bug bounty pipeline for one in-scope target, moving through authorise, gather, hypothesise, probe, gate, deduplicate, and report while enforcing the executable gates between phases and persisting every artifact to a resumable run directory. Use when starting a hunt on a new target, when resuming a hunt after a break, when a phase appears blocked and you need to know why, or when you need a hash-chained record of what was done and observed.
whenToUse: As the entry point for any authorised hunt. Run it before the phase-specific skills.
license: Apache-2.0
metadata:
  framework: bug-bounty-agent-framework
  orchestrates: bounty-recon-collect, sqli-surface-triage, sqli-oracle-probe, sqli-boundary-report
  tools: framework/tools/pipeline.py
  negative-trigger: Do not use this skill for the vulnerability method itself; use `sqli-bug-bounty`. Do not use it on a target without a recorded authorization basis.
---

# Running the pipeline end to end

This skill sequences the phase-specific skills and enforces the gates between
them. It exists so that the discipline is a property of the system rather than of
the operator's memory at the end of a long session.

**One phase at a time. A gate that fails stops the run.**

## When to use

- Starting a hunt against a target you are authorised to test.
- Resuming after a break — the run directory holds everything you need.
- A phase is blocked and you need the concrete reason.
- You need to show what was done, in order, without gaps.

## Do not use

For the SQL injection method — value-versus-structure reasoning, payload grammar,
impact demonstration. That is `sqli-bug-bounty`, which remains the authority on
the technique. This skill is the pipeline around it.

## The phases

| Phase | Does | Writes | Gate |
|---|---|---|---|
| `authorise` | records program, policy URL, date read, in/out of scope, automation permission, per-class caps | `scope.json` | **refuses to gather without it** |
| `gather` | deterministic collectors over supplied artefacts; asset-boundary classification | `evidence.json`, `boundary.json` | refuses if authorization invalid |
| `hypothesise` | ranks evidence into one-claim leads | `leads.jsonl` | requires the evidence bundle |
| `probe` | judges paired test/control observations | `observations.jsonl` | requires repeats and a control |
| `gate` | applies the evidence bar per observation | `gate.json` | **a finding cannot advance without a named boundary** |
| `deduplicate` | checks key, prior disclosures, known issues | `dedup.json` | requires a recorded search |
| `report` | renders the platform report and self-triages it | `reports/` | **`DO NOT SUBMIT` blocks emission** |

## Procedure

### 1. Start and check state

```bash
python framework/tools/pipeline.py status <target>
```

Resuming is normal. Every phase reads the artifacts of the phases before it, so
the run picks up wherever it stopped.

### 2. Authorise first, always

Record the basis before anything else: the program, the policy URL, the date you
read the policy, in-scope patterns, out-of-scope patterns, whether automated
scanning is allowed, and any per-class severity cap.

```bash
python framework/tools/pipeline.py scope <target>
```

If any of it is unclear, ask for the scope page. Do not infer scope from a
domain name, and do not treat the absence of an exclusion as permission.

### 3. Gather deterministically

```bash
python framework/tools/pipeline.py gather <target> --js bundle.js
```

Read `boundary.json` and treat its `blocked` list as a hard prohibition before
contacting anything. Then hand off to `sqli-surface-triage` for classification
and ranking, and to `sqli-oracle-probe` for the paired experiments.

### 4. Gate, then report

```bash
python framework/tools/pipeline.py gate <target> --boundary "<the seam crossed>"
```

Name the seam. An observation that is otherwise clean but has no named boundary
is blocked, deliberately.

Then emit through `sqli-boundary-report`, which reconciles severity against the
CVSS vector and self-triages the draft.

### 5. Verify the record

```bash
python framework/tools/pipeline.py verify <target>
```

Recomputes the hash chain over every recorded action. This is tamper-*evident*,
not tamper-proof: someone who rewrites the whole chain produces a consistent one,
so record the head hash out of band if you need real assurance.

## Reading a blocked phase

A blocked phase prints its reasons. The common ones and what they actually mean:

- **"no authorization record"** — you have not established a basis. Stop and get
  the scope page; this is not a formality.
- **"verdict is UNKNOWN, not SIGNAL"** — the measurement did not separate from
  the control. It is an open question, not a negative.
- **"N repeats, at least 3 required"** — you have not shown the effect is
  reproducible.
- **"no control measurements"** — a paired null variant is mandatory.
- **"no query-construction boundary named"** — you have a signal but not yet a
  finding. Say which seam was crossed.
- **"already recorded N times"** — duplicate within the session.
- **"no prior-disclosure check recorded"** — search the known and duplicate
  lists, then record what you searched.

## What the pipeline deliberately will not do

It will not send network requests, will not run exploitation tooling, and will
not submit anything. Probing is performed by the operator or an authorised
driver; the pipeline's job is to decide whether what was recorded is reportable,
and to refuse to let it advance when it is not.

## Anti-patterns

- **Skipping authorise.** Every later gate depends on it, and "I read the rules
  somewhere" is not a basis.
- **Reporting from a probe phase.** The gate exists between them for a reason.
- **Treating `UNKNOWN` as done.** It stays open.
- **Trusting a green run over the evidence.** The gates check structure and
  discipline; they cannot tell you the bug is real. Read the observations.
- **Storing unredacted third-party data.** Redaction happens at record time, so
  unredacted values never reach an artifact.
