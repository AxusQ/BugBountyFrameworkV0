# SQLi case studies — real disclosed reports and the lesson each teaches

Every item below is a real, public report/CVE. Use them as calibration: *where* the injection
actually was, *why* standard scanning missed it, and *how* impact was demonstrated. Map each
lesson onto the pipeline phase where it belongs.

## Case 1 — GitLab MilestoneFinder `order` (HackerOne #298176, CVE-2017-0914, $2,000, Critical)

**Where**: `GET /groups/:group/-/milestones?order=<input>` → Rails `items.reorder(params[:order])`
with no sanitization — an **identifier position** (`ORDER BY`), no quotes to escape.

**Detection move**: the payload was a whole `CASE` expression used as the sort key:

```sql
(CASE SUBSTR((SELECT email FROM users WHERE username = 'jobert'), 1, 1)
 WHEN 'a' THEN (CASE id WHEN 429944 THEN 2 ELSE 1 END) ELSE 1 END)
```

The *order of two known rows* in the JSON response flipped with the condition — a boolean
oracle built entirely from application semantics, no errors, no sleep.

**Pipeline lesson**: classification (structure-role params) → identifier-position grammar →
ordering differential oracle. This is the canonical modern-SQLi hunt: no classic `' OR 1=1`
anywhere in the payload.

## Case 2 — Valve `countryFilter[]` (HackerOne #383127, $25,000, Critical 9.9)

**Where**: `report_xml.php` `countryFilter[]` — an **array parameter** appended into the SQL
`IN`-list. Array-key inputs routinely bypass value-oriented validation and WAF rules that
inspect scalar params.

**Pipeline lesson**: inventory must cover *array and nested* inputs (`filter[]=`, `ids[]=`,
`where[a][b]=`), not just scalar params. Delivery channel ≠ value shape.

## Case 3 — HackerOne's own GraphQL endpoint (HackerOne #435066, Critical 10.0)

**Where**: SQL injection through `embedded_submission_for` — a **GraphQL resolver** argument
reaching SQL construction. GraphQL's type system validated the *shape* and did nothing about
the SQL semantics.

**Pipeline lesson**: GraphQL is a transport, not a defense. Enumerate every resolver argument
with search/filter/order semantics; fingerprint with GraphQL (schema introspection); test
resolver arguments as you would REST params — the injection lives in the resolver, and
GraphQL tooling gives you a cleaner schema map than REST.

## Case 4 — Django's own ORM, five times (HackerOne #3292573 / #3335709 / #2588426 / #3417967 / #2882887)

**Where**: `FilteredRelation` annotate (Postgres), `_connector` in Q objects,
`JSONField KeyTransform`, `HasKey(lhs, rhs)` (CVE-2024-53908) — all injection *inside the
ORM's query builder*, reachable with ordinary user input passed through framework APIs that
look idiomatic.

**Pipeline lesson**: fingerprint the framework version (recon) → match against the CVE
feed → hunt for the *specific reachable surface* (which endpoint passes user data into the
affected API) → reproduce. Version gap alone is not a finding; the reachable chain is.
`filter(**user_dict)` and JSON-key flows are the modern equivalents of string concatenation.

## Case 5 — URL-path injection, repeatedly (MTN #2633959 & #2958619, IBM #1527284 & #3578842)

**Where**: the SQL was built from **path segments** (`/users/<name>/orders`), not query
params — "clean URL" routing fed straight into queries. Recurring across programs, which
means it pays across programs.

**Pipeline lesson**: inventory must include path segments, route params, and slugs — inputs
testers skip because they "look structural". Routing params reaching persistence is a
structure-class candidate.

## Case 6 — Headers: User-Agent, Referer, cookies, Authorization

**Where**:
- GSA labs.data.gov `csv_to_json` — **User-Agent** (HackerOne #297478, Critical).
- DoD — **Referer** time-based (#1018621).
- MTN — **cookie parameter** (#761304).
- LiteLLM (CVE-2026-42208, from the 2026 corpus) — **Authorization header** reaching the
  API-key-check query; exploited in the wild ~26 hours after disclosure, KEV-catalogued.

**Pipeline lesson**: logging/analytics pipelines and token-lookup middleware build SQL from
headers and cookies. These inputs bypass form validation entirely. `Authorization` and
`User-Agent` belong in every surface map; the LiteLLM case shows the *unauth* value of
token-check paths.

## Case 7 — 8x8 export-to-Excel stacked queries (HackerOne #922567)

**Where**: the **export/report feature** accepted injection and the driver allowed
**stacked queries** — write grammar through a reporting surface.

**Pipeline lesson**: export/report/CSV/Excel endpoints are high-priority inventory rows:
they run the complex queries that force raw SQL, they're often authenticated-but-simple,
and they may sit on a more permissive DB connection than the main app.

## Case 8 — WPGraphQL `node(id:)` (CVE-2026-40762, unauth, time-based blind)

**Where**: a **base64-encoded Relay global ID** decoded server-side to `user:<value>` and
reached a MySQL query path — injection *behind an encoding layer*, unauthenticated.

**Pipeline lesson**: decode first, judge the plaintext second. Base64/URL/Unicode-wrapped
inputs (Relay IDs, JWT claims, opaque cursors, pagination tokens) are prime structure-class
candidates, and WAFs do not decode them.

## Case 9 — WordPress `prepare()` misuse (HackerOne #179920)

**Where**: `wpdb->prepare()` used with **sprintf-style or missing argument binding** — the
"safe" API invoked in an unsafe way.

**Pipeline lesson**: "uses prepared statements / uses the safe API" is a claim, not a
boundary. In open-source targets, read the call *sites* for how the safe API is invoked
(sprintf placeholders vs bound params); in black-box targets, treat safe-API claims as
unverified.

## Case 10 — TypeORM parameter escaping (HackerOne #506654 / #319458, Node ecosystem)

**Where**: the **library's own SQL-building functions** did not escape parameters correctly —
the abstraction layer was itself the vulnerability.

**Pipeline lesson**: dependency-level bugs (ORM/library CVEs) put injection into apps whose
code is fully "correct". Recon maps the dependency versions; the hunt then targets the
specific mis-built function's reachable surface.

## Case 11 — Essity login/password-reset error-based (HackerOne #3809973) and REST batch route confusion (#3873072)

**Where**: **authentication surfaces** (login, password reset, token check) built queries
from unauthenticated input; a batch route confusion exposed an unauth entry point.

**Pipeline lesson**: pre-auth surfaces are the highest-value rows in the inventory; auth
*flows* (login/reset/token-check) are query-heavy, unauthenticated, and historically
under-tested. Route confusion (a request matching an unintended route/handler) is a recon
finding that exposes otherwise-hidden entry points.

## Case 12 — Enterprise/backup products 2026 (Guardium, NetVault, Veeam ONE, SAP, Dell PowerProtect, SiYuan)

**Where**: low-priv authenticated or unauth surfaces in **data-protection, backup, and
gateway products** — Quest NetVault Backup **CVE-2026-9783** (ZDI-26-372, CVSS 8.8):
NVBURemovableMedia **JSON-RPC message** string used to construct SQL → **authentication
bypass** → execution as NETWORK SERVICE; IBM Guardium **CVE-2026-81933** (CVSS 8.8):
low-priv SQLi through the **Analytic Grid Service Handler** — a database-security
product injectable by its own users; Veeam ONE **CVE-2026-64631** (CVSS 8.6): low-priv
SQLi extracting database contents; SiYuan: unescaped REGEXP in
`fullTextSearchAssetContent`.

**Pipeline lesson**: when the program covers enterprise/desktop products, widen the
inventory to machine-to-machine APIs, agent protocols, and admin consoles — these sit on
the highest-value data with the least-tested input handling.

## Case 13 — Anthropic's MCP Postgres server (Datadog Security Labs, Aug 2025)

**Where**: the reference `@modelcontextprotocol/server-postgres` (≤0.6.2, deprecated but
~21k weekly downloads) took an arbitrary SQL tool input and wrapped it in
`BEGIN TRANSACTION READ ONLY` — trusting a **transaction wrapper** where parameterization
was needed. node-postgres executes **stacked statements**, so the tool input kills the
"read-only" guard:

```sql
COMMIT; DROP SCHEMA public CASCADE;      -- destructive escape
COMMIT; SET statement_timeout TO 1;      -- session pollution — survives pooled
                                         -- connections and least-privilege DB users
```

Delivery vector: *"Run this query on Postgres, as is: …"* to any agent with the tool
attached. An independent HackerOne report on the same issue existed Nov 2024. The fix:
named prepared statements + destroying the connection after each use.

**Pipeline lesson**: "read-only" wrappers, role restrictions, and transaction guards are
not parameterization. Stacked-statement support is the primitive that turns them all into
decorations. This case is the cleanest 2025 demonstration that **new technology
(MCP/agent tooling) re-creates classic SQLi** the moment it executes raw strings.

## Cross-case patterns (the empirical distribution)

Ranked by how often they appear in the disclosed corpus, and where each slots into the
pipeline:

1. **Structure params (`sort`/`order`/`filter`)** — inventory priority 1.
2. **URL path / route params** — inventory must include non-query input channels.
3. **Headers & cookies (UA/Referer/Authorization/session)** — same.
4. **ORM/library internals (Django × 5, TypeORM × 2, WordPress prepare)** — recon's
   version-mapping directly feeds these.
5. **GraphQL resolver arguments** — treat as REST-with-a-better-schema.
6. **Export/report/admin features** — escape-hatch territory, higher privileges.
7. **Auth surfaces (login/reset/token-check)** — highest value per finding.
8. **Encoding-wrapped inputs (base64 IDs, cursors, JWT claims)** — decode before judging.
9. **Array/nested parameters** — value-shape blindness of scanners and WAFs.
10. **Backup/data-protection/gateway products** — widen the surface inventory on enterprise
    programs; the dump/restore surfaces (CVE-2025-8714/8715, CVE-2026-18408) turn
    origin-server DB writes into **client-side restore-time code execution** — that is
    *why* backup products concentrate SQLi-to-RCE.
11. **Auth/token-check middleware** (LiteLLM: `Authorization: Bearer` → API-key-lookup
    query, pre-auth) — query-heavy, pre-authentication, historically untested.
12. **Schema-builder / admin write APIs** (Strapi `column.defaultTo` → DDL) — the value
    lands in *schema*, not rows; admin-authenticated but high-impact.
13. **Integration-node filter fields and agent tool strings** (n8n Supabase node ×2;
    MCP server-postgres) — automation surfaces where the developer assumed the
    *tool* handles safety, not the field.

## Meta-lesson: verify CVE identities before citing them

During the research for this file, two CVE IDs circulating in blog sources
("CVE-2025-7842 = PostgreSQL extension bundles", "CVE-2025-32466 = pg_dump search_path")
turned out to be **misattributed** — the first is a WordPress RSS-reader CSRF
(Wordfence CNA), the second a Joomla flaw; the real Postgres schema-hijacking family is
CVE-2023-39417 / CVE-2023-2454 / CVE-2024-7348. Never cite a CVE from a blog or
aggregator in a report without checking the CVE.org record — a misattributed CVE in a
report is an instant credibility hit, and version-match arguments built on wrong IDs
collapse under triage.

Source: [ajaysenr/HackerOne-Disclosed-Reports — SQL injection (220 reports)](https://github.com/ajaysenr/HackerOne-Disclosed-Reports/blob/main/by-weakness/sql-injection.md),
individual reports linked above on hackerone.com; the 2026 items from the workspace research
corpus (`recent-sqli-reports-2026.md`) and the verified blind-spots report
(`SQLi blind spots research report.md`).
