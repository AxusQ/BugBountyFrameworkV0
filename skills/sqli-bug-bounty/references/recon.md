# SQLi recon — stack fingerprinting and surface enumeration

Recon answers three questions before any payload is sent: **what stack** (framework, ORM,
driver, DBMS — with versions), **which entry points** carry attacker-controlled input toward
persistence, and **what is already known** about this target (prior disclosures, known CVEs
for the fingerprinted versions). No hypothesis before the surface inventory exists; no
inventory before fingerprinting.

## 1. Program-level recon

- Read the program's scope, exclusions, and policy on **automated scanning** and **data
  handling** before touching the target. Record the policy URL and date.
- Check the program's known/reported list and disclosed reports (HackerOne disclosure feed,
  full-text search on the vendor name) — surfaces with prior SQLi reports are either patched
  *or* re-broken in sibling features. Both are leads.
- Identify which asset you are testing: the web app, the API, the admin panel, mobile
  backend, or an appliance/backup product. Scopes frequently differ per asset.

## 2. Stack fingerprinting (passive first)

Sources, best first:

- **Response headers and cookies**: `X-Powered-By`, framework cookies (`csrftoken`,
  `laravel_session`, `phpsessid`, `rack.session`), `Server`, API gateway headers.
- **Error pages**: the 404/500 page shape; any debug page (Django's yellow debug page with
  full SQL is a jackpot — a *separate* information-disclosure finding); Laravel trace;
  Rails `ActiveRecord::StatementInvalid`; stack traces naming the ORM package.
- **JS bundles and sourcemaps**: framework strings, GraphQL playground endpoints, ORM
  client names in API calls, `__graphql` routes, generated API clients (Prisma/PostGraphile/
  Hasura/Strapi fingerprints in bundle strings).
- **API schema discovery**: `/graphql` (introspection enabled?), OpenAPI/Swagger
  `/swagger.json`, `/api/docs`, `/openapi.json`, `.well-known` endpoints, PostgREST-style
  `/` root listing tables and columns.
- **Public artifacts**: the vendor's changelog/release notes, GitHub org (open-source
  client libs, sometimes server code), CVE advisories for the product line, job posts
  naming the stack.

Record for the inventory artifact: framework + version if visible, ORM, DBMS, API style
(REST/GraphQL/gRPC), authentication scheme, WAF presence (blocked payloads come later —
first map behavior).

## 3. DBMS identification through the entry points

You rarely need a banner — the entry points themselves identify the database. Probe with
payloads that are harmless when handled, and compare **error shape, quoting, comment
handling, and concatenation grammar**:

| Probe | MySQL | PostgreSQL | MSSQL | SQLite | Oracle |
|---|---|---|---|---|---|
| Error prefix | `You have an error in your SQL syntax` | `ERROR: syntax error at or near` | `Unclosed quotation mark after` / `SQLState: …` | `SQLITE_ERROR: near` | `ORA-00900/…` |
| Comment | `--` (with space), `#` | `--`, `/* */` | `--`, `/* */` | `--`, `/* */` | `--` |
| Concat | `CONCAT(a,b)`, `'a' 'b'` | `a ‖ b` | `a + b` (needs cast) | `a ‖ b` | `a ‖ b`, `CONCAT` |
| Sleep | `SLEEP(5)` | `pg_sleep(5)` | `WAITFOR DELAY '0:0:5'` | none — heavy query (`randomblob`, `LIKE '%…%'` on big data) | `DBMS_LOCK.SLEEP` (priv) / heavy query |
| Version fn | `VERSION()` | `version()` | `@@VERSION` | `sqlite_version()` | banner queries |
| Identifier quote | backtick `` ` `` | double quote `"` | `[]` | double quote `"` | double quote |
| String escape | backslash `\` also works | no backslash in standard strings (`E''` does) | no backslash | no backslash | no backslash |

Notes: an application behind a pool/proxy (PgBouncer, ProxySQL, cloud connection strings)
may behave differently across requests — repeat fingerprint probes before trusting one
result. A JSON API that swallows errors (always `{ "error": "invalid" }`) pushes you toward
boolean/time/OOB oracles instead — that is a detection decision, not a dead end.

## 4. ORM/driver identification from error shapes

Error text and stack frames name the query-construction machinery — which tells you which
sink catalogue to use next:

| Signal | Machinery |
|---|---|
| `sqlalchemy.exc.*`, `ProgrammingError: (psycopg2…)` | SQLAlchemy + Postgres |
| `SequelizeDatabaseError`, `QueryFailedError` | Sequelize / TypeORM |
| `PrismaClientKnownRequestError` / raw driver text | Prisma |
| `ActiveRecord::StatementInvalid`, `PG::SyntaxError` | Rails ActiveRecord |
| `QueryException … SQLSTATE[…]`, Laravel trace | Laravel/Eloquent |
| `org.hibernate.*`, `QuerySyntaxException`, `ORA-…` | Hibernate/HQL |
| `django.db.utils.OperationalError`, debug page SQL | Django ORM |
| `BadSqlGrammarException`, `${}` in logs | MyBatis |
| `QueryFailedError: ER_PARSE_ERROR` | TypeORM |

## 5. Entry-point enumeration — build the surface map

Enumerate every input that can reach persistence. Group by delivery channel and record each
in the map (artifact template below):

1. **Classic params**: `q`, `search`, `query`, `filter`, `filters`, `where`, `cond`,
   `operator`, `sort`, `order`, `orderBy`, `order_by`, `sort_by`, `sortField`, `sortDir`,
   `direction`, `column`, `field`, `fields`, `group`, `groupBy`, `include`, `exclude`,
   `expand`, `populate`, `embed`, `select`, `limit`, `offset`, `take`, `skip`, `page`,
   `per_page`, `pageSize`, `pageSizeOptions` — the structure-selection half of this
   vocabulary is where modern SQLi lives.
2. **JSON-body filter DSLs**: Mongo-style operators (`{"$gt": 1}`, `$regex`, `$where`),
   dotted-path keys (`filter[user.email]`), Strapi `_where`, PostgREST/Supabase filters
   (`name=like.*value*`), Hasura `where` args, generic `{"column": {"op": "value"}}`
   envelopes. The *keys and operators* are structure, not values.
3. **GraphQL**: introspection first (`__schema`), then every query field with `search`,
   `filter`, `where`, `sort`, `orderBy` arguments; aliased/batched queries; resolver
   error shapes. GraphQL is a transport — the injection is in the resolver's query
   construction.
4. **Headers and cookies**: `Authorization` and `X-API-Key` (token-lookup queries),
   `X-Forwarded-*`, session/remember-me cookie values, locale headers in SQL `ORDER BY` /
   `COLLATE` clauses.
5. **File and import surfaces**: CSV/Excel import (column *names* become identifiers),
   uploaded filenames stored and later queried, address-book import, scheduled reports.
6. **Stored-value (second-order) sources**: profile fields, saved-search names, report
   titles, tenant names, webhook URLs, tags — anything stored safely now and concatenated
   somewhere else later (admin search, export, jobs, migrations).
7. **Machine-to-machine surfaces**: internal JSON-RPC, backup/data-protection APIs,
   admin panels, monitoring endpoints — low-authentication surfaces sitting on
   high-value data (a recurring 2026 CVE pattern: Veeam ONE, Quest NetVault, IBM Guardium,
   LiteLLM).

## 6. Surface map artifact (produce before the first hypothesis)

| # | Entry point | Param/path | Role (value / structure / behavior) | Delivery (param/JSON/GraphQL/header/stored) | Likely sink | Priority |
|---|---|---|---|---|---|---|
| 1 | `GET /api/items` | `sort` | structure | param | `ORDER BY` construction | high |
| 2 | `POST /search` | `filter` JSON keys | ORM structure | JSON body | filter DSL → ORM | high |
| 3 | `GET /api/token-check` | `Authorization` header | value (but where?) | header | token-lookup query | med |

Fill the Role column using the triage matrix in the main skill. The Likely-sink column is a
guess from the sink catalogue — mark it as a guess. Prioritize structure rows over value
rows, unauthenticated surfaces over authenticated ones only when the program rewards them
equally; otherwise the low-priv-authenticated surface often pays better (fewer duplicate
reports, more dangerous features).

## 7. Tooling and safety

- **Manual first.** sqlmap and scanners systematically miss identifier injection,
  dict-expansion, filter DSLs, and second-order flows — the exact classes this skill
  targets. Run tools only where policy allows them, and always after manual
  classification.
- **sqlmap, when allowed**: point it at a *single* confirmed-suspicious parameter, not the
  host; `--batch --risk=1 --level=1` first; mind rate limits; never `--dump` on programs
  that forbid data extraction; use `--prefix/--suffix` when you know the injection position
  (identifier context needs it); `--technique` to avoid time-based on fragile targets.
- **Timing probes**: one request, measured delta, repeated max 3 times — a sleep payload on
  shared infrastructure is a DoS argument, and programs reject testers for it.
- **Transport tooling**: Burp (param mining, content discovery, JSON hand-editing), a
  GraphQL introspection walker (e.g., Clairvoyance when introspection is off), an
  OOB callback server (interact.sh/Burp Collaborator) — but only point callbacks at
  infrastructure you control, and check policy before making DNS exfil attempts.
- Keep every request and response from the first payload onward — the report depends on
  the transcript, and re-creating a flaky oracle later wastes the finding.
