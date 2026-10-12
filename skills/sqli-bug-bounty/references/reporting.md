# SQLi reporting — impact demonstration and the report shape

A SQLi report is judged on three things: **is it reproducible**, **which query-construction
boundary did it cross**, and **what authority does it grant the attacker**. Write to those
three explicitly. Everything else is supporting material.

## 1. Impact demonstration standards

Prove the *smallest sufficient instance* of each claim, on your own account and data:

| Claim | Sufficient proof | Insufficient (report will bounce) |
|---|---|---|
| Arbitrary query read | Read **your own** row from a table you cannot legitimately query (e.g., your own `users` record via a UNION or error oracle) | "Could theoretically dump the users table" with no extraction |
| Cross-tenant access | Read your own record through another tenant's context | Screenshots of schema/version only |
| Auth bypass | Login response returns a valid session for a controlled payload | Payload reflected in an error page |
| Boolean oracle | Two payloads differing in exactly one character produce two stable, distinct responses (3+ repeats each) | One response that differs once |
| Time oracle | A delta you measured 3 times (e.g., ~5s vs ~200ms), stated as ranges, with baseline variance | A single slow response (could be caching, load) |
| OOB oracle | A callback to **your own** collab server, for the test payload only, with control payload silent | — |
| Escalation to RCE | Argue the specific chain: stacked-query support, DB privileges, feature (`COPY PROGRAM`, `xp_cmdshell`, extension install), each prerequisite named | "SQLi can become RCE" with no chain |

Never run: extraction of other users' data, password cracking, destructive grammar
(`DROP`, `UPDATE`, `DELETE` on real data), or mass dumping (`--dump`) — nearly every program
forbids it, and the report does not need it. The VRT-severity argument does not require
the data, only the *demonstrated authority to get it*.

## 2. Severity mapping

Severity follows **demonstrated authority × authentication prerequisites × data sensitivity**:

- **Critical**: unauthenticated arbitrary query execution; auth bypass leading to admin;
  cross-tenant read at scale; demonstrated path to RCE. (Examples from real disclosures:
  Django FilteredRelation CVSS 10.0, WPGraphQL `node(id:)` unauth blind SQLi, Drupal core
  unauth arbitrary SQL.)
- **High**: authenticated (low-priv) arbitrary read or limited write; blind SQLi in a
  high-value surface; ORM-internal injection reachable by ordinary users. (GitLab
  MilestoneFinder order-by, TypeORM escape bugs, WordPress plugin SQLi in authenticated
  contexts.)
- **Medium**: injection requiring unusual prerequisites (admin panel, internal tool, specific
  plugin configuration), low-sensitivity data, heavy user interaction.
- Remember: many programs pay **on CVSS or VRT class**, and blind SQLi is usually *not*
  downgraded for being blind — the oracle difficulty is your effort, not their risk.

## 3. The report template

```markdown
# Title: SQL injection in <endpoint> via <parameter> (<short mechanism>)

## Summary
One paragraph: what is injected, where, and what authority it grants. e.g.
"User-controlled `sort` parameter in GET /api/items is concatenated into the
ORDER BY clause of the items query. A boolean oracle over the response order
allows arbitrary subquery reads; I read my own user record from `users`,
which this endpoint cannot legitimately return."

## Environment
Product/version (exact build), endpoint, fingerprinted stack (framework/ORM/DBMS),
your account/prerequisites (e.g. "any registered user; no special privileges").

## Steps to reproduce
1. Baseline request + response (control payload).
2. Test request + response (actual payload, URL-encoded as sent).
3. The differential/oracle explanation: what changes and why that proves control.
4. Repeat evidence (stability): "differed in 3/3 paired attempts".
Number every step; make each one a request a triager can copy-paste.

## Root cause (the boundary crossed)
Name the query-construction boundary: which API builds this SQL, which part
(identifier / connector / raw fragment / stored value) the input controls, and
why the framework's normal guarantee did not apply here.

## Impact
The demonstrated instance (what you actually showed) and the argued scope
(what the same primitive allows), kept separate and labeled as such.

## Remediation
Parameterize values; allowlist identifiers; patch the ORM version if a framework
CVE applies; least-privilege DB account; log SQL errors. Short and specific.

## Attachments
Full request/response transcript (HAR export), timestamps, any callback logs.
```

## 4. Common rejection reasons and pre-empting them

- **"No impact demonstrated"** — attach the smallest-instance proof from §1; never leave
  impact as an argument alone when a safe demonstration exists.
- **"Filtered / WAF blocks it"** — include the transport/encoding variant that worked;
  if you only got a WAF block, say so honestly and argue the underlying sink.
- **"Theoretical / version-based"** — never submit "framework X has CVE-Y" without a
  reproduced input→sink chain on this target.
- **"Duplicate"** — search prior disclosures for the same endpoint before submitting; cite
  what is *different* (new entry point, deeper authority) if the surface was reported before.
- **"Out of scope / automated scanning"** — state that every request was manual, give counts
  if asked, and confirm the asset is in scope in the report's first section.

## 5. Evidence hygiene

- Redact anything belonging to other users *before* pasting; if a query could have returned
  other users' rows, select only your own row (`WHERE id = <your id>`) in the PoC.
- Record the exact request you sent, including encoding — the single most common
  reproducibility failure is a re-typed payload that no longer breaks out the same way.
- Keep the baseline/control request in the transcript: the differential **is** the finding.
