---
name: sqli-surface-triage
description: Rank gathered injection-surface evidence into a small ordered set of testable hypotheses, classify each input as value-role or structure-role, and record the lead in a persistent ledger. Use when you have an evidence bundle and need to decide what to test first, when a sort/filter/column parameter has been found and its role in query construction is unclear, when several candidate surfaces compete for limited testing time, or when a lead must be parked rather than killed because the evidence is not yet conclusive.
whenToUse: After bounty-recon-collect, before any probe. Also when re-prioritising mid-hunt.
license: Apache-2.0
metadata:
  framework: bug-bounty-agent-framework
  implements: data versus structure classification, hypothesis ranking, kill guard
  tools: framework/tools/leads.py, framework/tools/pipeline.py
  negative-trigger: Do not use this skill to send probes or payloads; use `sqli-oracle-probe`. Do not use it for the report; use `sqli-boundary-report`.
---

# Ranking the injection surface into hypotheses

This skill converts a ranked evidence bundle into a small ordered set of leads,
each stating one testable claim, and records them in a ledger that is built to
resist premature closure.

## When to use

- An evidence bundle exists and something must be tested first.
- A structure-selection parameter has been found and its role is unclear.
- Several surfaces compete for limited time and the order matters.
- A lead looks dead but the evidence is one-sided.

## Do not use

To send probes — that is `sqli-oracle-probe`. To write the report — that is
`sqli-boundary-report`. This skill produces ordered hypotheses and nothing else.

## Procedure

### 1. Classify every input before ranking it

The single most useful question about an input is not *does it reach the
database* — almost everything does — but **what part of the generated query can
it influence**. Classify each candidate:

| Input role | Typical names | The question to answer |
|---|---|---|
| Value | `username`, `email`, `status`, `age` | Is it parameterised end to end? |
| Query control | `limit`, `page`, `per_page` | Is it cast or constrained before it reaches SQL? |
| **Structure** | `sort`, `order`, `column`, `field`, `group`, `fields` | Is it mapped to an allowlist, or concatenated? |
| **ORM structure** | `operator`, `filter` object, JSON keys | Can input choose the query operation itself? |
| Data re-used later | any value previously stored | Where is it re-interpreted as SQL? |

### 2. Rank by payoff, not by reachability

In order:

1. **Structure-selection parameters.** Identifiers cannot be parameterised, so
   *something* is building syntax here.
2. **Object or dict expansion into an ORM call.** The modern `' OR 1=1--`.
3. **Escape hatches** — raw-query APIs, template interpolation, reporting jobs.
4. **Second-order stores** — inserted safely, then concatenated elsewhere.
5. **Framework and ORM version bugs**, checked against the exact fingerprinted
   version. A version gap is a prioritisation hint, never a finding by itself.
6. **Non-obvious entry points** — machine-to-machine APIs, admin panels, backup
   surfaces, token-check middleware.

### 3. State each lead as one testable claim

```bash
python framework/tools/pipeline.py hypothesise <target>
```

Each lead records the target, entry point, parameter, role, and a hypothesis
phrased so that a single experiment could falsify it. "The `sort` parameter
selects query structure and is concatenated rather than allowlisted" is testable.
"The report page might be vulnerable" is not.

### 4. Vary one thing at a time

When probing, change exactly one variable per request and record it. If several
things change together a negative result is uninterpretable, and the ledger
flags those as confounded:

```python
lead.record_mutation("payload", "'", "''", verdict=Verdict.UNKNOWN)
lead.record_mutation("encoding", "plain", "json", companions=["header"])  # flagged confounded
```

### 5. Refuse to kill on one-sided evidence

This is the rule the ledger enforces, and it is the one that matters most.

A lead may move to `KILLED` **only when both arms of the experiment are refuted
with evidence** — the test arm *and* the control arm. A one-sided refutation
parks the lead instead and increments a dismissal counter, so a lead that keeps
being circled back to surfaces for a human decision rather than quietly
disappearing.

```python
kill_lead(lead)   # refuses unless both arms are refuted, each with evidence
```

Parking is not a soft kill. A parked lead keeps its state, its evidence, and its
tripwires, and still appears in the active review list.

## Output

`framework/runs/<target>/leads.jsonl`, plus a summary of counts by state and a
count of confounded mutations.

## Anti-patterns

- **Payload spraying.** Firing a generic payload at every parameter without
  classifying its role first. Modern SQL injection is not where classic payloads
  land.
- **"ORM equals safe."** ORMs parameterise values; they cannot parameterise
  structure, and their own query builders have shipped injection CVEs.
- **Killing on one negative probe.** One refuted arm proves nothing about the
  other.
- **Version-gap reporting.** A version gap without a reachable input-to-sink
  chain is a hint, not a finding.
- **Unbounded lead creation.** A hundred unprioritised leads is the same as
  none. Rank, bound, and work them in order.
