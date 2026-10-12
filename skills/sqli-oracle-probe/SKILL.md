---
name: sqli-oracle-probe
description: Probe a classified lead with a paired test-and-control experiment, select the weakest sufficient oracle, and judge the result into SIGNAL, REFUTED, UNKNOWN, or ERROR with repeats rather than a single sample. Use when testing whether an input influences SQL structure, when a timing or boolean reading looks anomalous but might be caching or load balancing, when a WAF appears to block a payload, or when a negative result needs to be trustworthy enough to abandon a lead.
whenToUse: After sqli-surface-triage has ranked a lead. Also whenever a previous result is ambiguous.
license: Apache-2.0
metadata:
  framework: bug-bounty-agent-framework
  implements: oracle selection, control baselines, unknown-beats-refuted
  tools: framework/tools/evidence.py, framework/tools/pipeline.py
  negative-trigger: Do not use this skill to choose payload grammar or fingerprinted DBMS syntax; use `sqli-bug-bounty` and its detection reference. Do not use it to demonstrate impact; use `sqli-boundary-report`.
---

# Oracle-based probing with control baselines

Detection means **demonstrating control**, not firing a payload library. This
skill runs a paired experiment and judges it under a rule set designed so that a
negative result is trustworthy and an ambiguous one is never mistaken for either
answer.

## When to use

- A ranked lead is ready to test.
- A reading looks anomalous and you need to know whether it is real.
- A payload appears filtered and you need to distinguish "blocked" from "not
  injectable".
- You are about to abandon a lead and need the negative to hold up.

## Do not use

To choose payload grammar, breakout syntax, or DBMS-specific functions — that is
`sqli-bug-bounty` and its detection reference, which covers error-based,
boolean, timing, and out-of-band payloads per engine and per injection position.
This skill is the measurement discipline wrapped around them.

## Procedure

### 1. Pick the weakest sufficient oracle

Prefer, in order: reflection (an error or echoed fragment), differential (a
boolean or state change), timing, then out-of-band. Timing is fourth, not first:
a sleep payload is a denial-of-service argument on shared infrastructure, and it
is the easiest signal to fake. Use it only when nothing cheaper separates.

### 2. Always take a control

Every probe is a pair: the test arm carrying the payload, and a null or benign
variant of the *same* request under the *same* conditions. A signal without a
control is not evidence, and the judge will refuse to promote it:

```python
from evidence import Observation, InputRole, OracleKind

obs = Observation(
    id="o1", target="app.example.com", entry_point="GET /api/v1/reports",
    parameter="sort", role=InputRole.STRUCTURE, oracle=OracleKind.DIFFERENTIAL,
    payload="sort=(SELECT 1)", control="sort=created_at",
    measurements=[1, 1, 1], control_measurements=[0, 0, 0],
)
```

### 3. Repeat, and judge deterministically

```bash
python framework/tools/pipeline.py gate <target> --boundary "<the seam crossed>"
```

The judge applies four rules:

- **No signal without a control.** A differential or timing claim with no control
  is `UNKNOWN`, however clean it looked.
- **An oracle that fires in the control does not separate.** If the control arm
  shows the effect too, the result is `UNKNOWN` — likely caching, a load
  balancer, or a shared baseline. This is never reported as a signal.
- **Timing needs a floor and a margin.** The median delta must exceed both an
  absolute floor and a multiple of the observed spread, with at least three
  repeats per arm.
- **Unknown beats refuted.** Missing, malformed, or ambiguous measurements give
  `UNKNOWN`, never `REFUTED`. Refutation requires repeated positive evidence of
  no effect.

That last rule is the important one. Calling something refuted on weak evidence
is how a real vulnerability gets closed as a false positive and never revisited.

### 4. Establish a known-true and known-false baseline

Before trusting any oracle, prove it can separate. Send a payload you *know*
should trigger it and a null variant you know should not. An oracle that cannot
separate those two cannot tell you anything about a third case. Caches, cold
starts, and rate limiters all fake boolean and timing signals.

### 5. Re-test before concluding "filtered"

A WAF is a tripwire, not a fix. Before recording a negative, re-test the same
route with a different transport or encoding — JSON escapes, unicode
normalisation, non-standard content types, parameter duplication. Conversely, the
absence of a WAF proves nothing.

### 6. Confirm with the cheapest possible pair

Once you have a signal, reduce it to a minimal payload and its null variant that
differ in exactly the property you claim to control. Never touch another user's
data, never run destructive grammar, and keep request counts inside policy. A
confirmation that would require breaking the program's rules is a hypothesis to
report as unverified, not a test to run.

## Output

Judged observations in `framework/runs/<target>/observations.jsonl` and a gate
result in `gate.json`. Every observation carries its rationale, so a reviewer can
see why it was classified as it was.

## Anti-patterns

- **Single-sample oracles.** One anomalous response is noise until repeated.
- **Error message equals injection.** A reflected SQL fragment is an oracle
  candidate, not proof.
- **Timing first.** Use it only when nothing cheaper separates, and never
  against shared infrastructure without restraint.
- **WAF-blocked equals safe.** A block is a claim to test, not a boundary.
- **Reading `UNKNOWN` as a negative.** It is an open question, and it should stay
  open until it is answered.
