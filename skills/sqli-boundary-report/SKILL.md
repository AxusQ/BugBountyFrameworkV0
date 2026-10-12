---
name: sqli-boundary-report
description: Name the exact query-construction boundary a confirmed injection crossed, score it with reproducible CVSS 3.1 base metrics, emit a platform-ready report for HackerOne, Bugcrowd, Intigriti, or Immunefi, and self-triage the draft before submission. Use when a probe has cleared the evidence bar, when a draft report needs a verdict before it is submitted, when a severity claim must be reconciled with its CVSS vector, or when a triager has asked which ORM API or identifier position was actually crossed.
whenToUse: After a lead has cleared the evidence gate. Also to re-triage any draft, including one written by hand.
license: Apache-2.0
metadata:
  framework: bug-bounty-agent-framework
  implements: boundary naming, CVSS 3.1 base scoring, platform emitters, self-triage
  tools: framework/tools/report.py, framework/tools/cvss.py, framework/tools/gates.py
  negative-trigger: Do not use this skill to find the vulnerability or to probe it; use `sqli-surface-triage` and `sqli-oracle-probe`.
---

# Naming the boundary, scoring it, and reporting it

This skill turns a confirmed signal into a submission-ready report. Its central
claim is that **the query-construction boundary is the finding**. A report that
shows a payload and a response without naming the seam that was crossed reads as
a scanner dump and invites a "cannot reproduce / working as intended" close.

## When to use

- A probe has cleared the evidence bar and the finding is ready to write up.
- A draft needs a verdict before submission.
- A severity label needs reconciling against its CVSS vector.
- A triager has asked which sink was reached.

## Do not use

To find or probe the vulnerability — that is `sqli-surface-triage` and
`sqli-oracle-probe`. This skill assumes the evidence already exists and will
refuse to report without it.

## Procedure

### 1. Name the boundary

State precisely which seam the input crossed. Be specific enough that a
developer could locate it in the source from your sentence alone:

- which ORM API or query builder was reached — `whereRaw`, `extra()`, a `$queryRaw`
  call, a `createQueryBuilder` fragment;
- which syntactic position the input occupied — an `ORDER BY` identifier, a
  column list, a table name, a JSON path, an operator, a raw fragment;
- which layer failed to constrain it — a validator that passed a string through,
  an allowlist that was absent, a cast that never happened;
- for a second-order flow, both hops: where the value was stored, and where it
  was later re-interpreted as SQL.

### 2. Score with metrics, not adjectives

```bash
python framework/tools/cvss.py "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
```

Supply base metrics only. Temporal and Environmental metrics need knowledge of
exploit maturity and the customer's environment that a hunter generally does not
have, and setting them invents certainty — the calculator rejects them rather
than silently ignoring them.

The severity label is derived from the vector. A stated severity that disagrees
with its own vector is a validation error and blocks emission, because a
triager who spots the mismatch discounts the whole report.

Set `PR` to the privilege level you actually demonstrated, not the one that
would make the bug look worse. Set `UI` to `R` only if a victim action is
genuinely part of the chain, and say what the action is.

### 3. Emit for the platform

```bash
python framework/tools/report.py finding.json --platform hackerone --out report.md
```

Four platform shapes are supported, each with its own required fields:

| Platform | Distinguishing requirement |
|---|---|
| HackerOne | CVSS plus affected asset and component |
| Bugcrowd | VRT category and a P1–P5 priority derived from severity |
| Intigriti | affected URL and a CVSS 3.1 vector |
| Immunefi | asset type, tech stack, and contract or protocol details |

`--check` validates without rendering, which is the fastest way to find a
missing prerequisite before you write prose.

### 4. Self-triage the draft before submitting

```bash
python framework/tools/gates.py  # via pipeline: python framework/tools/pipeline.py gate <target>
```

The triage gate is deliberately mechanical, because a model asked "is this
ready?" tends to say yes. It returns one of `READY TO SUBMIT`, `NEEDS FIXES`, or
`DO NOT SUBMIT`, and it blocks on:

- **missing required sections** — description, reproduction, impact;
- **theoretical impact phrasing** — "could lead to", "may allow", "an attacker
  with the right conditions";
- **a missing boundary** — no named seam means no finding;
- **a PoC that cannot be replayed** by a triager with zero prior context;
- **severity disagreeing with the vector**;
- **unfilled placeholders**.

Report only what the proof demonstrated. If the impact you believe in exceeds
what you showed, say so explicitly as unverified rather than asserting it as
demonstrated.

### 5. Check duplication before you submit

Confirm the asset is in scope, the class is not excluded, your severity claim
does not exceed the program's cap for that class, and the surface has not
already been reported. Search the program's known-issues list and public
disclosures on the exact surface first.

## Output

A platform-formatted report under `framework/runs/<target>/reports/`, a triage
verdict, and the validation problems if any remain.

## Anti-patterns

- **Impact inflation.** Quoting a theoretical maximum, such as escalation to
  remote code execution, without demonstrating or at least honestly arguing the
  privilege prerequisites.
- **Severity by feel.** A label unsupported by metrics cannot survive scrutiny.
- **Omitting the boundary.** The seam is the finding; without it the report is
  unreproducible.
- **Publishing the data you reached.** Demonstrate the scope of access; do not
  republish third-party data. Redaction happens at record time.
- **Re-reporting.** Check the known and duplicate lists first.
