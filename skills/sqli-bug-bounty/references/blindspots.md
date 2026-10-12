# SQLi blind spots — things assumed safe that are not

Every entry is an assumption that *feels* like a defense and fails at a specific place.
When a target (or a triager) offers one of these as the reason something is safe, that
reason is the next thing to test. Claims below are verified against CVE.org records,
vendor advisories, or canonical articles; unverifiable patterns are marked as such.

## 1. "The escaping/quoting function handles it"

- **PQescapeLiteral / PQescapeString bypass (CVE-2025-1094, CVSS 8.1, CWE-149)**: the
  functions fail to neutralize quoting syntax in text that **fails encoding validation**.
  Attacker supplies invalid UTF-8 containing a raw `0x27` (quote); the "escaped" output is
  used to construct `psql` input, which misinterprets statement structure → query
  splitting → **psql meta-commands, including `\!` shell execution** (Stephen Fewer /
  Rapid7). A second variant hits CLI utilities when `client_encoding=BIG5` and
  `server_encoding=EUC_TW/MULE_INTERNAL` — encoding conversion re-interprets bytes.
  Fixed in PostgreSQL 17.3/16.7/15.11/14.16/13.19 (2025-02-13).
- **Chained in the wild — BeyondTrust CVE-2024-12356 (CVSS 9.8, in KEV)**: unauth web
  request → SQLi → `psql` meta-command → RCE as site user; exploited by a state-linked
  actor Dec 2024. Rapid7: the vendor *did* escape input and route via psql — the exploit
  **required** CVE-2025-1094 to work. Hunter evidence: apps shelling out to `psql`;
  `pg_escape_*`/`PQescape*` used instead of parameterization; repeated
  *"invalid byte sequence for encoding UTF8"* log entries (listed as an exploitation
  indicator).
- **GBK/SJIS multibyte escaping (the classic)**: in GBK, `0xbf27` is invalid but `0xbf5c`
  is a valid multibyte character; `addslashes` turns `0xbf27` into `0xbf5c27` — a valid
  multibyte char **plus a live quote** (Shiflett's canonical demo). Works for any
  encoding with a valid multibyte char ending in `0x5c` (GBK/Big5/SJIS).
  `mysql_real_escape_string` is safe **only when the client library knows the charset**:
  `SET NAMES gbk` changes the server view but not the escaper's charset state — only
  `mysql_set_charset` / DSN `charset=` does (phpdelusions). PDO < 5.3.6 + GBK +
  `ATTR_EMULATE_PREPARES=true` reproduced injection even through "prepared statements".
- **Identifier quoting**: backticks (MySQL), double quotes (Postgres/SQLite), brackets
  (MSSQL) protect identifiers *only if the quote character in the input is escaped* —
  and `PQescapeIdentifier` itself is inside CVE-2025-1094's scope. Naïve
  "wrap it in backticks" breaks on input containing a backtick.
- **Second-order identifier injection**: a value safely INSERTed (tenant name,
  saved-filter name, report title) is later interpolated as an *identifier* — e.g. a
  table-per-tenant `tenant_<name>` schema. Verified case class: the pg_dump family
  (CVE-2025-8715, §6) — stored object names re-emitted into SQL/psql streams.

## 2. "It's a prepared statement"

- **Client-side emulated prepares (PDO `ATTR_EMULATE_PREPARES=true`)**: the driver
  substitutes placeholders *client-side* — security collapses into client-side escaping
  in the connection charset (the GBK class above). Emulation additionally **enables
  stacked/multi-queries** in one `prepare()`, and binds everything as strings —
  `LIMIT '10'` becomes a syntax error, which pushes developers to concatenate
  LIMIT/OFFSET values → injection returns exactly where the driver "helped".
- **Only literals are bindable, in any prepare API**: identifiers, comma-lists, partial
  literals, and keywords are not bindable **anywhere** — the structural root of modern
  SQLi (phpdelusions: "PDO has no placeholder for identifiers").
- **Stacked queries per driver**: preparing one statement does not mean the driver
  rejects multi-statement strings — `pg_query`-family drivers accept them; the 8x8
  export-to-Excel report (H1 #922567) showed write grammar through a reporting feature.
  (Per-driver matrix beyond PDO: general knowledge, unverified.)
- **Second-order**: the INSERT was prepared and safe; the *later* reader that
  concatenates the stored value is not (admin search, CSV export, scheduled jobs,
  migrations, "internal" tooling). Safety is a property of the point of interpretation,
  not of entry.

## 3. "The ORM protects this"

- **`filter(**request.GET)` / dict expansion — CVE-2025-64459** (Django 5.2<5.2.8,
  5.1<5.1.14, 4.2<4.2.26; NVD CVSS 9.1): `QuerySet.filter()/exclude()/get()` and `Q()`
  are "subject to SQL injection when using a suitably crafted dictionary" expanded via
  `**` — the attacker controls query-construction options like `_connector`. The same
  shape exists in every ecosystem: `findAll({ where: req.query })`, `Model.filter(**payload)`.
- **JSONField keys → column aliases — CVE-2024-42005** (Django 5.0<5.0.8, 4.2<4.2.15,
  CVSS 9.8): `values()`/`values_list()` inject via a crafted **JSON object key** passed
  as an arg — JSON keys are structure, not values. Django's 2025–2026 series
  (FilteredRelation etc.) lived entirely in query-construction machinery — code that
  *looked* idiomatic.
- **TypeORM sort *direction* — GHSA-9ggv-8w38-r7pm**: blind SQLi in
  `UpdateQueryBuilder`/`SoftDeleteQueryBuilder` `orderBy`/`addOrderBy` on MySQL/MariaDB
  — the **direction** parameter is not validated against ASC/DESC and is concatenated
  verbatim; "an attacker can inject arbitrary SQL via the sort direction — even when
  the column name itself is hardcoded." `SelectQueryBuilder` validates correctly; the
  update builders did not. Fixed 0.3.29 (introduced 0.1.12). Demonstrated: `SLEEP()`-based
  blind exfiltration, LIMIT row targeting, DoS.
- **TypeORM `save()`/`update()` — CVE-2025-60542** (<0.3.26, CVSS 6.5): sqlstring called
  with `stringifyObjects` defaulting to false → nested-JSON mishandling → unintended
  column modification.
- **MyBatis `${}`**: the framework's *other* placeholder is raw string substitution;
  the official docs themselves bless `ORDER BY ${columnName}` because the position
  cannot be parameterized — while warning it "leads to potential SQL Injection attacks."
- **Rails raw-SQL surface** (rails-sqli.org, tested on 6.1.4): `calculate/average/count/
  max/min/sum` accept SQL **in the column argument** (`params[:column]` =
  `"age) FROM users WHERE name = 'Bob';"`); `where/not/rewhere/delete_by/destroy_by`
  string args are "not escaped at all"; `from/group/having/joins/lock/select/reselect/
  update_all` accept arbitrary SQL; `exists? params[:user]` is unsafe because Rails
  converts params to arrays/hashes → injectable structure.
- **"Uses the safe API" claims**: WordPress `prepare()` invoked with sprintf-style
  placeholders or missing binding (H1 #179920) — the safe API mis-invoked is just
  concatenation with extra steps.
- **The ORM itself has CVEs**: TypeORM escaping bugs (H1 #506654/#319458), Rails
  annotate (CVE-2023-22794) — clean application code does not outrank the library's
  own bugs.

## 4. "The stored procedure / the function handles it"

- A procedure that builds and `EXECUTE`s dynamic SQL has the same data/structure
  boundary one layer deeper — OWASP A05:2025 carries this caveat explicitly.
- **Postgres `SECURITY DEFINER` + dynamic SQL**: the function runs as its *owner*;
  injection inside it is a privilege jump, and in Supabase-style apps this is the
  single most common place raw SQL lives.
- Triggers, scheduled jobs, and reporting queries re-read stored values — second-order
  carriers no request-scoped review sees.

## 5. "The tenant schema / search_path isolates everyone"

Verified Postgres family (beware misattributed CVE IDs — check CVE.org, not blogs):

- **CVE-2023-39417**: extension scripts using `@extowner@`/`@extschema@` inside a
  quoting construct let an attacker with database-level **CREATE** privilege execute
  arbitrary code **as the bootstrap superuser**.
- **CVE-2023-2454**: `CREATE SCHEMA … schema_element` defeats protective search_path
  changes — schema-element execution ignores the sandboxing search_path reset that
  multi-tenant apps rely on.
- **CVE-2024-7348** (CVSS 8.8): TOCTOU in `pg_dump` — object creator swaps a relation
  for a view/foreign table mid-dump → **execute arbitrary SQL functions as the user
  running pg_dump (often a superuser)**; trivially winnable with an open transaction.
- **CVE-2026-14673** (amcheck does not clear untrusted search path), **CVE-2026-18408**
  (psql `\unrestrict` — follow-up to the `\restrict` fix), and the generic pattern:
  an unqualified function name resolving into a tenant-controlled schema after
  `SET search_path` (supported by 2454+39417; no single named CVE).
- **False attributions seen in the wild** (do not propagate): CVE-2025-7842 is a
  *WordPress RSS-reader CSRF* (Wordfence CNA), CVE-2025-32466 is a *Joomla
  RSMediaGallery* flaw — neither is a PostgreSQL extension/pg_dump issue.

## 6. "The connection pool resets state"

Verified for PgBouncer-style transaction pooling (pgbouncer.org + engineering
writeups):

- **`SET` (non-LOCAL) persists on the backend session** → the pooled connection handed
  to the next request **still carries the previous tenant** — a cross-tenant leak when
  the app relies on `SET` for tenant context or RLS roles.
- **`SET LOCAL` needs an explicit transaction**: with driver autocommit, each statement
  gets its own transaction — the `SET LOCAL` commits/resets *before* the query →
  policy evaluates empty/fallback → **permissive fallback = all tenants' rows**.
- **Protocol-level PREPARE/EXECUTE across pooled backends**: a named statement can be
  prepared on one backend and executed on another (statement-name collisions, stale
  plans) — hence `server_reset_query=DISCARD ALL` and the recommendation to disable
  server-side prepares under transaction pooling.
- Related verified session-state CVE: **CVE-2024-10978** — `SET ROLE` /
  `SET SESSION AUTHORIZATION` reset to the wrong user ID.
- No formal 2024–2026 academic pool-state paper exists; the engineering writeups are
  the best sources. (Flagged.)

## 7. "It's not a query parameter, it can't matter"

Inputs that bypass form validation and WAF inspection entirely, each with real
disclosures:

- **Headers**: `User-Agent` (GSA labs.data.gov, H1 #297478, Critical — csv_to_json built
  SQL from the UA), `Referer` (DoD, time-based), cookies (MTN #761304),
  `Authorization` (LiteLLM CVE-2026-42208 — token-check query, unauth, exploited ~26h
  after disclosure, KEV).
- **URL path segments / route params / slugs** (MTN #2633959, #2958619; IBM #1527284,
  #3578842).
- **Array/nested parameters** (`countryFilter[]`, Valve H1 #383127, $25,000):
  value-shaped validation does not see array keys.
- **Decoded/encoded inputs**: base64 Relay IDs (WPGraphQL CVE-2026-40762 — decoded
  `user:<value>` reaching MySQL), opaque cursors, JWT claims — the plaintext behind
  the encoding is what reaches SQL, and WAFs do not decode it.
- **File-import surfaces**: CSV/Excel import column *names* become identifiers.

## 8. "The structured/typed API layer handles it"

- **PostgREST/Supabase**: the structured filter API (`.eq/.like`) *is* parameterized —
  but `.filter()` passes operator and value as-is (documented escape hatch), and RPC
  functions are arbitrary SQL (see §4). The safe-looking client cannot protect the
  unsafe-looking server function.
- **n8n's Supabase node "Filters (String)" mode** (GHSA-xrqg-3xcp-h45x): filter field
  inserted unescaped, accepts expressions → read/update/delete every row.
- **GraphQL's type system**: validates shape, not SQL semantics — the resolver is
  where injection lives (H1 #435066 on HackerOne itself).

## 9. "Validation / allowlist already checked it"

- **The verified falsification — TypeORM GHSA-9ggv-8w38-r7pm**: the column *was*
  hardcoded, the **direction was not**, and `asc; <SQL>` was concatenated verbatim →
  blind SQLi. Audit every `direction`/`order`/`dir` value as structure, not a safe enum.
- **Validate-then-transform**: input allowlisted, then lowercased/trimmed/normalized
  into SQL — the transformed form was never checked. Byte-level cousin: CVE-2025-1094's
  BIG5↔EUC_TW mismatch = "validated in one alphabet, executed in another."
- **Regex anchoring mistakes**: unanchored allowlist regex passes `name; <SQL>` through.
- **Dotted-path traversal**: `user.profile.name` resolves an association and injects
  structure past a column-name allowlist (Rails order-by association traversal —
  documented behavior, unfetched source, flagged).
- **LIMIT/OFFSET**: PDO emulation binds them as strings → syntax errors → developers
  concatenate → injection (verified chain, phpdelusions).
- Correct reference pattern: `array_search` against a fixed allowlist + a separate
  ternary allowing only `ASC|DESC`.

## 10. "The AI layer is just natural language"

- **Text-to-SQL backdoors — arXiv:2503.05445** (also ACM 10.1145/3769762): poisoned
  fine-tuning makes Text-to-SQL models emit attacker-chosen SQL (credential
  exfiltration) on trigger inputs; defenses found inadequate.
- **Prompt injection → SQL injection — arXiv:2308.01990**: the pipeline for
  LLM-backed NL-to-SQL systems.
- **DaMiT-SQL (CASCON 2025/IEEE)**: prompt-engineering attacks on Text-to-SQL are
  "much harder to defend against than traditional SQL injection."
- **Keysight NWVS (2025-07-31)**: malicious prompts make an LLM agent "generate and
  execute harmful SQL queries" — practical NL/MCP database-gateway attacks.
- Hunter evidence: NL chat-to-data features, MCP `query_database`/`sql` tools reachable
  by low-priv users; whether generated SQL runs through parameterized paths or
  concatenated strings; stored user content feeding prompts = second-order via prompt
  injection. (MCP-specific formal research: not found, flagged.)

## 11. "The WAF blocks it"

A WAF is a tripwire, not a fix: grammar-aware mutations (`1-1` for truth, `‖` for `OR`,
`<=>`, derived tables instead of `UNION`) bypass pattern rules — demonstrated against
`AWSManagedRulesSQLiRuleSet` at default sensitivity (H1 #3591725), with AWS's own
remediation acknowledging the gap (inspect *all* components, apply repeated decoding).
Conversely, a blocked payload proves nothing about the sink — the sink either exists or
does not, independent of the filter in front of it.

## 12. "It's an internal tool / test environment"

- **Quest NetVault Backup — CVE-2026-9783 (ZDI-26-372, CVSS 8.8)**: NVBURemovableMedia
  **JSON-RPC message** processing lacks validation of a user-supplied string before
  constructing SQL → **authentication bypass** → code execution as NETWORK SERVICE.
- **IBM Guardium — CVE-2026-81933 (CVSS 8.8)**: SQLi in the **Analytic Grid Service
  Handler** — a *database-security product* SQLi-able by its own low-priv users through
  an admin grid endpoint (ibm.com/support/pages/node/7288040).
- **Veeam ONE — CVE-2026-64631 (CVSS 8.6)**: "low-privileged user to inject SQL and
  extract database contents" (infrastructure, backup, account data; KB4892).
- **Starbucks H1 #592400**: "just a test environment" → unauth blind SQLi → RCE.
- Pattern: JSON-RPC handlers, admin "grid"/filter endpoints, backup/monitoring
  consoles, machine-to-machine APIs — surfaces whose engineers assumed trusted callers.
