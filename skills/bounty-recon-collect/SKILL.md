---
name: bounty-recon-collect
description: Deterministic, model-free gathering of a target's attack surface from saved artefacts, producing a bounded ranked evidence bundle and an asset-boundary report. Use when starting a hunt against an in-scope target, when a JavaScript bundle or OpenAPI document needs to be mined for API paths and query-parameter names, when you need to know which discovered hosts are out of scope before contacting anything, or when a fresh asset or a revived host should be prioritised over a re-scan.
whenToUse: Run first, before any hypothesis. Also run on a schedule to turn change signals into leads.
license: Apache-2.0
metadata:
  framework: bug-bounty-agent-framework
  implements: code gathers, agent judges
  tools: framework/tools/collectors.py, framework/tools/gates.py
  negative-trigger: Do not use this skill for the SQL injection method itself; use `sqli-bug-bounty` for surface classification, oracle choice, and impact demonstration.
---

# Deterministic reconnaissance and collection

This skill performs the gathering half of the hunt. It calls no model, sends no
network request, and makes no judgement. It turns saved artefacts into a bounded,
ranked evidence bundle and refuses to let discovered hosts be contacted without
independent scope cover.

**The principle: code gathers, agent judges.** Gathering is repetitive — find a
host, check liveness, map endpoints, parse JavaScript — and deterministic code
does it reproducibly for free. Judgement is what the model is actually good at.
Keeping the split sharp is what stops model usage from scaling with the size of
the scan instead of with the number of promising leads.

## When to use

- At the start of a hunt, before any hypothesis is formed.
- When a JavaScript bundle, source map, or OpenAPI document is available and its
  API surface and parameter names need extracting.
- Whenever assets have been observed more than once, to turn the difference into
  leads.
- Before contacting anything discovered inside a target's own artefacts.

## Do not use

For the SQL injection method itself — value-versus-structure classification,
oracle selection, payload grammar, impact demonstration, or report shape. That
is `sqli-bug-bounty`. This skill only gathers; that skill decides what it means.

## Procedure

### 1. Establish the authorization basis

Nothing is gathered until scope is recorded. The pipeline refuses otherwise,
because gathering from a target you have no basis for is the mistake the gate
exists to prevent.

```bash
python framework/tools/pipeline.py status <target>
python framework/tools/pipeline.py scope <target>
```

Record the program name, policy URL, the date the policy was read, in-scope
patterns, out-of-scope patterns, whether automated scanning is permitted, and any
per-class severity cap. If any of that is unclear, ask for the scope page rather
than inferring it from a domain name.

### 2. Mine the artefacts

Point the collector at every JavaScript bundle, source map, and API document you
have saved. It extracts five things, each with the matched text recorded so you
can confirm the hit in the source:

| Output | Why it matters |
|---|---|
| API paths | the surface to probe; privileged-looking segments are boosted |
| Query-parameter names | **the injection surface**, classified by role |
| Raw-SQL sink hints | escape hatches where the framework's guarantees stop |
| Template-literal SQL | a variable interpolated beside a SQL keyword |
| Source-map references | original sources may be recoverable |

```bash
python framework/tools/pipeline.py gather <target> --js bundle.js --js app.json
```

A parameter whose name selects *structure* — `sort`, `order`, `column`, `field`,
`group`, `filter`, `operator`, `direction`, `include`, `expand`, `limit`,
`offset` — is typed as structure-role and ranked three times higher than an
ordinary value parameter. That is the whole point: identifiers and keywords
cannot be parameterised, so a structure selector is where injection survives in
an ORM-era application. An ordinary value parameter such as `username` is
correctly *not* promoted.

### 3. Read the boundary report before contacting anything

Hosts embedded in a target's own JavaScript routinely belong to analytics
vendors, CDNs, and *other customers*. Discovery is not authorisation. The
collector classifies every host it finds against the recorded scope and blocks
anything not independently covered.

```bash
cat framework/runs/<target>/boundary.json
```

Treat the `blocked` list as a hard prohibition. Nothing in this framework will
contact a blocked host, and neither should you. Note that the host extractor is
a precision-favouring heuristic: it rejects dotted code identifiers such as
`app.js.map` rather than reporting them, and a host it wrongly rejects is far
cheaper than a request to a system you were never authorised to touch.

### 4. Turn change into leads

When you have two observations of the same target, diff them. A host that is
present now and absent before is `NEW`; a host that was unreachable and is now
alive is `REVIVED`. `REVIVED` outranks `NEW`, because a change in reachability
more often accompanies a misconfiguration than mere existence does.

**New is better than revisited.** A newly published asset is the one nobody has
tested yet, so never park a fresh asset behind a queue of re-scans. Rank by
freshness with a decay, not a hard filter: a stale but very promising target
should still outrank a fresh but boring one.

### 5. Hand off

The bundle is bounded on purpose. Report the dropped count alongside the kept
items so the filter is visible rather than silent, and pass the ranked items to
`sqli-surface-triage`.

## Output

`framework/runs/<target>/` gains `scope.json`, `evidence.json`, `boundary.json`,
and an appended `provenance.jsonl`. Every write is hash-chained, so the sequence
of actions can be replayed and tampering detected after the fact.

## Anti-patterns

- **Sending every host to the model.** Usage then scales with the scan. Filter
  deterministically first.
- **Resolving every endpoint found in a bundle.** Some of them are not yours to
  touch. Check the boundary report first, every time.
- **Treating a collector hit as a finding.** A structure parameter is a
  hypothesis. It becomes a finding only by clearing the evidence bar.
- **Trusting a fresh full sweep over a targeted new-asset check.** Time to first
  contact is the metric that matters.
