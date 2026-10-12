# Design notes and roadmap

Where the framework's ideas come from, what was deliberately rejected, and what
is not built yet.

## The architectural principle: code gathers, agent judges

Gathering is repetitive — resolve a host, check liveness, map endpoints, parse
JavaScript — so deterministic code does it, reproducibly and cheaply. Judgement
is what a model is actually for. The split matters for cost and correctness
alike:

- **Cost.** If every discovered host goes through a model, usage scales with the
  size of the scan. If deterministic code filters first, usage scales with the
  number of promising leads.
- **Correctness.** A regex that extracts parameter names from a bundle is
  reproducible, reviewable, and regression-testable. A model asked to "find the
  interesting endpoints" is none of those, and its output drifts between runs.

Implemented in `collectors.py` and enforced by the phase split in `pipeline.py`:
the gather phase calls no model at all.

## Freshness: new is better than revisited

A newly published asset is the one nobody else has tested yet, so time to first
contact is the metric that matters, and a fresh asset must never be parked behind
a queue of re-scans. Implemented as `FreshnessRanker`, which *multiplies* a base
priority by an exponential decay with a floor rather than filtering on age — so a
stale but very promising target still outranks a fresh but boring one.

## Change signals become leads

Differencing two observations of the same target yields `NEW`, `REVIVED`, and
`DISAPPEARED`. `REVIVED` outranks `NEW`, because a change in reachability more
often accompanies a misconfiguration than mere existence does. Implemented in
`SnapshotDiffer`.

## JavaScript bundles are the injection-surface map

Client bundles enumerate the API: paths, parameter names, and often the
structure-selection parameters (`sort`, `filter`, `fields`, `column`) that are
the actual modern injection surface. Bundles also name raw-SQL escape hatches and
frequently expose source maps. This is the highest-yield deterministic step for
SQLi work, and it is entirely offline — so it is fully testable.

## The asset boundary

A scope page lists the assets you may test. It does not list the hundreds of
hosts embedded in a target's own JavaScript, and those include analytics vendors,
CDNs, and hosts belonging to *other customers* of the same platform. A pipeline
that resolves everything it finds will send requests nobody authorised.

`AssetBoundary` therefore treats discovery as untrusted: every host found in an
artifact must independently satisfy the authorization record, unknown hosts are
blocked by default, and an explicit exclusion always beats a wildcard include.

The host extractor deliberately favours precision over recall. An early version
treated the dotted JavaScript identifiers `app.js.map`, `axios.get`, and
`db.whereRaw` as hostnames. They were blocked rather than allowed — fail-closed,
so not dangerous — but a lead generator that cries wolf gets ignored, which is
its own failure mode. Requiring the final label to be a plausible TLD removed the
noise.

## Rejected from the source material

- **"Don't ask permission to probe — just do it."** Incompatible with
  authorization-first discipline. The opposite is enforced here: the gather phase
  refuses to run without a recorded basis.
- **Advertised capabilities with no implementation.** A documented dedup key that
  no code read; a CVSS "calculator" that was a hardcoded severity map; local
  tool orchestration claimed but absent. Where a mechanism was worth having, it
  was implemented and tested rather than restated. `cvss.py` is a real
  implementation verified against eleven reference vectors.
- **Prose-only gates.** A gate described in a prompt gets skipped under deadline
  pressure. Every gate here is executable and returns a result a caller must
  handle.
- **Copying copyleft or unlicensed prose.** claude-kit is GPL-3.0-or-later and
  bountyforge has no license at all, so both were treated as design references
  and reimplemented in original wording.

## Not built yet

Honest list of what exists as design intent only:

1. **Scheduling.** Freshness ranking exists, but there is no scheduler. Running
   the gather phase on a cadence — daily asset discovery, a weekly full sweep —
   is left to the operator or an external cron.
2. **Tool-native artifact emission.** Reports render as markdown. Emitting a
   proxy-ready request collection (Caido or Burp) from a lead, so the next step is
   hands-on fuzzing rather than transcription, is designed but not implemented.
3. **Session handoff document.** Run artifacts are resumable, but there is no
   single "current state" summary written for a human returning after a break.
4. **Yield metrics.** "Verifiable leads per unit of model spend" is the right
   north-star metric and nothing computes it yet.
5. **Collector coverage.** Only JavaScript/JSON artifacts. OpenAPI documents,
   HAR files, and HTTP response corpora would each be straightforward additions
   using the same `EvidenceItem` shape.
6. **Independent escalation pass.** The design reference runs a separate
   read-only verification pass on a finding after it is verified and before it is
   gated for submission, with hard containment (only its own output root is
   writable, the report is hash-pinned so it cannot be edited to fit a theory, and
   sibling branches must not be read so the result stays independent). The
   framework's gates are single-pass; adding a second independent pass with those
   constraints is the next structural improvement.

## The mdpsec integration: reachability and counterevidence

The `bug-bounty-hunting-prompts` pack is MIT-licensed, so unlike `bountyforge`
(no grant) and `claude-kit` (GPL) its design could be adopted directly. Two of
its mechanisms are now executable in `tools/prerequisites.py`.

**The prerequisite ledger.** Its central insight is that a demonstrated primitive
is not a finding. "The endpoint returns another user's record when you supply
their UUID" is a report that the UUID was known, not a vulnerability report — the
attacker's ability to obtain that UUID has to be established by a *separate*
argument. The ledger forces one row per required value, state, role, or action,
each naming the attacker's starting capability and a concrete in-scope
acquisition step, and a finding is provable only when every row is `REACHABLE`.

**The rule that makes it honest.** The pack states it plainly: *lack of time or
one negative request is not disproof*. Implemented as a status downgrade — a
`NOT_REACHABLE` row without a documented acquisition hunt is reported as
`UNVERIFIED`, so it leaves the finding open rather than closing it. This is the
same asymmetry as `UNKNOWN`-beats-`REFUTED` in the evidence model, applied one
level up, and it is the reason the ledger is worth having rather than being a
checklist. Precedence is also encoded: a documented disproof outranks a blockage,
because "this cannot be done" is a stronger statement than "I could not finish
testing it".

**The counterevidence gate.** Before a finding may be called proven, the author
must write the strongest benign or intended explanation, the control that ruled
it out, and one fact that would change the severity. The last field is the one
that does the work: if you cannot name a single fact that would move the rating,
you have not thought about the boundary conditions. Placeholders (`N/A`, `TBD`,
`none`) and short filler are rejected, so the section cannot be satisfied
cosmetically.

Both gates are wired into `EvidenceGate.check()` structurally — it accepts any
object exposing `check() -> GateResult` — so the evidence module gains no import
cycle, and the probe-level question ("is this a signal?") stays distinct from the
finding-level question ("may I report this?").

## Testing stance

98 tests, and the two most valuable ones are regression guards for specific
documented failures rather than generic coverage:

- `test_multiline_description_not_truncated` guards the parser trap that
  truncated 604 of 817 descriptions in the source corpus.
- The `AssetBoundaryTests` and `EvidenceTests` classes guard fail-closed
  behaviour: unknown hosts blocked, unknown verdicts not read as negatives.

Three of the bugs found during development were found by these tests, not by
inspection: an invalid regex backreference that broke every redaction call, a
subdomain fallback that allowed an explicitly excluded host, and the hostname
false positives described above.
