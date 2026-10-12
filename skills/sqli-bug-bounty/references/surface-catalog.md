# SQLi surface catalog — per-technology sinks and where the guarantees stop

The catalogue lists, per technology, the APIs where the framework's parameterization guarantee
*stops applying* — and the concrete patterns to grep for (open-source targets) or probe for
(black-box). Roles follow the value/structure classification in the main skill: most sinks
below are *structure*-side.

## 1. ORM escape-hatch matrix

### Django
| Sink | Why it breaks |
|---|---|
| `Model.objects.raw(f"…'{x}'…")` | string-built raw SQL |
| `Model.objects.extra(where=[f"name = '{x}'"])` | documented as a "last resort"; `where`/`select`/`params` interpolated |
| `Model.objects.order_by(request.GET['sort'])` | identifiers cannot be parameters; unsanitized column names |
| `Model.objects.filter(**request.GET.dict())` | attacker controls **keys** → `_connector`/query-construction internals (CVE-2025-64459) |
| `values()` / `values_list()` fed JSON payload keys | JSONField **column aliases** injected (CVE-2024-42005) |
| `annotate/aggregate/alias/FilteredRelation` with user keys | query-construction machinery (Django's own 2025–2026 CVE series: FilteredRelation CVSS 10.0, PostGIS lookups) |
| JSONField lookups (`KeyTransform`, `HasKey`) | key position is structure (CVE-2024-53908) |

Safe counterparts to know on sight: `raw("… %s", [x])`, `filter(field=x)`, allowlisted
`order_by`.

### Rails / ActiveRecord
| Sink | Why it breaks |
|---|---|
| `where("name = '#{x}'")` | string conditions interpolate |
| `order(params[:sort])` / `reorder` | identifier position (GitLab MilestoneFinder CVE-2017-0914 is this exact shape) |
| `annotate(x)` / `optimizer_hints(x)` | comment text not sanitized → break out of comment (CVE-2023-22794) |
| `Arel.sql(x)` | explicitly "trusted raw SQL" |
| `find_by_sql` / `connection.select_rows` | raw strings |
| `calculate/average/count/max/min/sum(x, col)` | **column argument accepts SQL** — `params[:column] = "age) FROM users WHERE name = 'Bob';"` injects (rails-sqli.org) |
| `where`/`not`/`rewhere`/`delete_by`/`destroy_by` with string args | "not escaped at all" (rails-sqli.org, tested 6.1.4) |
| `exists? params[:user]` | Rails converts params to arrays/hashes → injectable structure |
| `from/group/having/joins/lock/select/reselect/update_all` | accept arbitrary SQL |

Association traversal: `order("association.attr")` resolves relations — allowlists that
check column names but not dotted paths miss it.

### Laravel / Eloquent
| Sink | Why |
|---|---|
| `DB::select("… '$x'")`, `DB::statement` | raw strings |
| `whereRaw` / `orderByRaw` / `havingRaw` / `selectRaw` | the `*Raw` family is unparameterized by design |
| `orderBy($request->sort)` | column name position |
| `DB::raw(x)` inside query builders | raw fragment spliced into builder |

### SQLAlchemy (Python)
| Sink | Why |
|---|---|
| `execute(text(f"… '{x}'"))` | f-string into `text()` — `text()` binds named params, not interpolation |
| `order_by(request.args['sort'])` (string) | string attrs resolved as SQL identifiers/expressions |
| hybrid properties / `.literal()` | expression string reaches SQL |

### TypeORM (Node)
| Sink | Why |
|---|---|
| `orderBy`/`addOrderBy(userCol)` | column names not parameterizable |
| `addSelect(item.column)`, `distinctOn` | identifier positions |
| **Update/SoftDelete query builder `orderBy` direction param** | **verified blind SQLi (GHSA-9ggv-8w38-r7pm)**: direction not validated against ASC/DESC, concatenated verbatim — injectable **even when the column is hardcoded**; `SelectQueryBuilder` validates, the update builders did not (fixed 0.3.29) |
| `repository.save()/update()` nested JSON | **CVE-2025-60542** (<0.3.26): sqlstring `stringifyObjects` defaults to false → unintended column modification |
| `SelectQueryBuilder.distinctOn(user)` | **CVE-2026-76848** (≤1.1.0): SQLi via distinctOn |
| library's own escaping bugs | H1 #506654 / #319458 — the ORM itself mis-escapes parameters |
| `take`/`skip` string-cast into SQL | pagination values concatenated |

### Sequelize / Prisma (Node)
| Sink | Why |
|---|---|
| `sequelize.literal(x)`, `where: sequelize.literal(...)` | always raw |
| `sequelize.query(\`… '${x}'\`)` without `replacements` | template literal = concatenation |
| **`:replacements` placeholders inside string literals** | **CVE-2023-25813 / GHSA-wrh9-cjv3-2hpw** (fixed 6.19.1): Sequelize built the query from the `where` option, then re-parsed the SQL to inject `:replacements` — substitution happened **inside string literals too**, so replacement *values* could break out. Mixing `literal()` fragments + `where` + replacements is the sink |
| `prisma.$queryRawUnsafe` / `$executeRawUnsafe` | exists precisely because tagged templates cannot cover every case (workspace research: 30%+ of ORM apps still contain SQLi via such paths) |
| `prisma.$queryRaw` + `Prisma.sql` | safe when *all* dynamic parts go through `Prisma.sql`/`Prisma.raw` is still raw |

### Hibernate / JPA / MyBatis / wpdb
| Sink | Why |
|---|---|
| `createQuery("from User where id = " + x)` | HQL concatenation — HQL compiles to SQL; injection class is identical |
| native `createNativeQuery` concat | direct |
| MyBatis `${}` | **string substitution**; `#{}` binds — `${}` in ORDER BY/column names is the single most common Java SQLi |
| `wpdb->prepare()` with sprintf placeholders or missing binding | "safe" API mis-invoked (H1 #179920) |

## 2. GraphQL / API layers

- **Resolver-built SQL**: any resolver argument (`search`, `filter`, `where`, `orderBy`)
  reaching a raw query (HackerOne's own #435066; Praetorian's GraphQL case study —
  introspection → enumerate args → find search/filter/sort args flowing into resolver
  query construction).
- **Auto-GraphQL-to-DB (Hasura, PostGraphile, Strapi)**: the generated layer compiles
  `where`/`orderBy` args safely *by itself* — the risk moves to **custom actions/functions**
  and **admin write APIs**: Strapi **CVE-2026-22599 / GHSA-3xcq-8mjw-h6mx** — SQLi in the
  **Content-Type Builder write API** via the `column.defaultTo` attribute (the attribute
  value lands in DDL; admin-authenticated; fixed 4.26.1/5.33.2). Historic calibration for
  impact: Hasura **CVE-2021-47714** (v1.3.3) — query-endpoint SQLi escalated to **local
  file read via `pg_read_file()`**.
- **Opaque/encoded IDs and cursors**: Relay `node(id:)` base64 IDs (WPGraphQL
  CVE-2026-40762 — decoded `user:<value>` reaching MySQL), opaque pagination cursors
  (often base64 JSON that lands in `WHERE`), JWT claims used in queries. Decode before
  judging what the input controls.
- **Batching/aliasing**: same field aliased N times bypasses naive rate limits while you
  run oracle pairs — but respect the program's limits regardless.

## 3. Filter DSLs and query-string mini-languages

The keys and *operators* are structure even when values are parameterized:

- Mongo-style: `{"$gt": 1}`, `$regex`, `$where`, `filter[user.email]` dotted keys — in
  SQL-backed APIs these map to operators/columns.
- **PostgREST/Supabase**: structured filters (`.eq`, `.like`) are parameterized — but
  `.filter(column, operator, value)` is the documented **escape hatch**: "operator and value
  are used as-is and need to follow PostgREST syntax… you need to make sure they are properly
  sanitized" (Supabase docs). **RPC functions** (`supabase.rpc()`) run Postgres functions —
  injection lives in `EXECUTE` with concatenation, especially **`SECURITY DEFINER`**
  functions (elevated rights + dynamic SQL = the highest-value sink in a Supabase app).
- **n8n Supabase node "Filters (String)" mode**: field inserted into the query with no
  escaping, field accepts expressions → read/update/delete every row
  (GHSA-xrqg-3xcp-h45x) — and the same node's **Row Get Many/Delete/Update** operations
  concatenated an expression-bindable value → filter widened to all rows
  (GHSA-f4f3-2g67-4vhm / CVE-2026-77071) — proof that filter mini-languages ship
  injectable in popular tooling.
- Strapi `_where`, LoopBack `filter[where][...]`, JSON:API `filter[...]` — same class:
  key and operator grammar compiled to SQL.

## 4. Cloud DB / machine-to-machine surfaces

- **PostgREST-style HTTP APIs**: the URL *is* a query language (`?select=`, `&where=`,
  `order=desc`); the structured layer is safe, custom RPC and views are the sinks.
- **AI gateways / LLM proxies**: LiteLLM CVE-2026-42208 — an **Authorization header**
  reaching an API-key-check query (unauth, CVSS 9.3, exploited in ~26h, KEV). Any
  token/key-check middleware is a query-heavy, pre-auth surface.
- **Backup/data-protection/admin appliances**: Guardium, NetVault (JSON-RPC → NETWORK
  SERVICE), Veeam ONE (low-priv user → DB contents) — the 2026 enterprise CVE pattern:
  low-priv machine-to-machine surfaces on high-value data.

## 5. AI stacks — the 2025–2026 class

- **Text-to-SQL / NL2SQL agents ("P2SQL")**: when an LLM converts a user prompt into SQL
  and the pipeline executes it, *prompt injection becomes SQL injection* — the natural
  language is attacker-controlled query structure by design (Keysight NWVS research,
  July 2025: "DB query-based prompt injection" in NL2SQL tools, AI assistants, RAG
  pipelines with database access).
- **Backdoored Text-to-SQL models** (arXiv:2503.05445, ACM 10.1145/3769762): poisoned
  fine-tuning makes the model emit attacker-chosen SQL on trigger inputs — the model
  itself is the injection carrier. Prompt→SQL pipeline analysis: arXiv:2308.01990;
  prompt-engineering attacks on Text-to-SQL judged "much harder to defend against than
  traditional SQL Injection" (DaMiT-SQL, CASCON 2025).
- **MCP database servers — the verified case** (Datadog Security Labs, Aug 2025):
  Anthropic's reference `@modelcontextprotocol/server-postgres` (≤0.6.2, deprecated but
  ~21k weekly downloads) wrapped the arbitrary SQL tool input in
  `BEGIN TRANSACTION READ ONLY` — but node-postgres executes **stacked statements**, so
  the tool input kills the guard: `COMMIT; DROP SCHEMA public CASCADE;`, or session
  pollution `COMMIT; SET statement_timeout TO 1;` (survives pooled connections and
  least-privilege DB users). Delivery: ask an agent *"Run this query on Postgres, as
  is: …"*. Lesson: **a read-only transaction wrapper is not parameterization**, and
  stacked-statement support defeats it. (Independent HackerOne report existed Nov 2024.)
- **pgvector / vector search**: the vector literal is **text syntax**
  (`'[1,2,3]'::vector`) — a string-built similarity query is structurally the same as
  any string-built SQL. *Technique-level observation: no published SQLi case found —
  treat as a hypothesis to test on RAG/"semantic search" inputs, not a cited class.*
- **LLM-generated application code**: AI-assisted code reproduces concatenation patterns
  at scale — the sink classes above, but written by models; treat fingerprinted
  AI-generated codebases as *more* likely to contain raw-query misuse, not less.

## 6. Stored procedures and DB-side sinks

- Dynamic SQL inside procedures (`EXECUTE '…' ‖ x`, `sp_executesql` with built strings).
- `SECURITY DEFINER` Postgres functions (run as owner — injection = privilege jump).
- Triggers and scheduled jobs that re-read stored values (second-order carriers).
- **Impact-side DB features** (for severity argument, not entry): Postgres `dblink`,
  `COPY PROGRAM` (superuser), large objects (file write), extensions, `pg_read_file`;
  MySQL `LOAD_FILE` (needs `secure_file_priv` off) and driver-dependent stacked queries;
  MSSQL `xp_cmdshell`, `OPENROWSET`, `WAITFOR`.

## Grep sets for open-source targets

Fast inventory over the whole catalogue (ripgrep):

```text
Django:     raw\( |extra\( |order_by\( |filter\(\*\* |values\(|values_list\(
Rails:       where\("|order\(|reorder\(|annotate\(|Arel\.sql
Laravel:     whereRaw|orderByRaw|havingRaw|selectRaw|DB::raw|DB::select|DB::statement
SQLAlchemy:  text\(f"|text\(".*%s.*"|order_by\(
TypeORM:     orderBy|addOrderBy|addSelect|distinctOn|getRawMany|literal\(
Sequelize:   literal\(|sequelize\.query\(
Prisma:      \$queryRawUnsafe|\$executeRawUnsafe
MyBatis:     \${                      # vs #{
Hibernate:   createQuery\(".*\+|createNativeQuery
wpdb:        \$wpdb->query\(|\$wpdb->prepare\(
Postgres:    EXECUTE ' |SECURITY DEFINER|format\(
```

Then classify each hit: what exactly is interpolated — a value (low) or structure
(identifier, operator, key — high)?
