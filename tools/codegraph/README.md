# codegraph — token-efficient code-graph queries for AI agents

`mygraph.json` (~2 GB, UTF-16) is a call/containment graph of the codebase —
far too large to read, grep, or put into an AI context window. `codegraph.py`
answers the two questions an agent actually asks, in as few tokens as possible:

- **where is this called from?** → `callers` (tree toward origins)
- **what does this call?** → `callees` (tree toward targets)

plus `search` / `node` / `path` / `stats` to find and inspect nodes, and a
read-only `sql` escape hatch for everything else. Anything expressible through
those was deliberately removed — fewer commands also means fewer MCP tool
schemas burning agent-context tokens every session.

## Which graph: `mygraph.json` vs `csgraph.json`

codegraph works with any graph in the supported JSON shape; point it at one with
`--graph`. Two are available here:

- **`mygraph.json`** — the original polyglot call graph (built by Trail of Bits'
  trailmark). Broad language coverage; methods/classes/modules only.
- **`csgraph.json`** — a C#-only graph built by
  [`graph_makers\csharp_roslyn`](../graph_makers/csharp_roslyn) via Roslyn. Much
  richer: it also has **properties, fields, events, attributes, accessibility
  modifiers, and accurately-resolved calls** (only ~9k unresolved targets vs
  ~240k in mygraph). Use this for member-level or attribute questions — e.g.
  "which `[Serializable]` classes have a public parameterless ctor and public
  read/write properties". The extra `modifiers`/`synthetic` data lands in the
  `mods`/`synthetic` node columns (see SQL schema below).

Both index and query identically; the only difference is how much each graph
contains. The `graph_makers\csharp_cecil` maker produces more of the same shape
from compiled DLLs — e.g. `graphs\gac_net2.json`, `graphs\gac_net4.json`,
`graphs\net10_framework.json` (the .NET Framework GACs and the .NET 10 shared
frameworks).

**Resolved vs heuristic calls.** Graphs from the C# makers set
`summary.resolved_calls` = 1: their `calls` edges point at real target nodes, so
`callers` reports exactly the real callers. `mygraph` records calls as
name strings (unresolved `ext` targets), so `callers` folds in name-matched
**aliases** (marked `~`, with `[+N alias targets]`) to recover hidden callers —
useful there, but heuristic. codegraph detects this per-graph and only applies the
alias heuristic to unresolved graphs. **For security / source-sink / taint
reachability, use a resolved graph** (csgraph or a cecil graph), where edges are
trustworthy:

- source → sink: `path <source> <sink>` (shortest call chain) or
  `callees <source> --depth N` (forward reachable set).
- sink → source: `callers <sink> --depth N` (back toward entry points).
- find sinks/sources by API: `search <Api>` or a `sql` join on `calls`.

## How it works (and why there's no background process needed)

1. **One-time index.** The first query streams the JSON (incremental
   UTF-16→UTF-8 transcode into `ijson`'s C parser — the file is never loaded
   into memory) and writes a SQLite index `mygraph.json.idx.sqlite` (~283 MB)
   next to it: nodes get stable short numbers (`#37479`), edges are
   deduplicated with counts and indexed in both directions. Measured: ~22 s,
   ~220 MB peak RAM. The index rebuilds automatically when the JSON's
   size/mtime changes.
2. **Per-query process.** Each CLI call opens the index read-only and exits:
   ~60 ms for traversals, ~170 ms for a whole-graph substring search, ~400 ms
   for alias-aware `callers` (all including Python startup); ~10 MB working
   set. All state lives on disk and the OS page cache keeps hot pages warm, so
   *no daemon is required* — an agent simply shells out per question.
3. **Optional MCP server.** `python codegraph.py mcp` runs a persistent stdio
   MCP server exposing the same operations as 7 typed tools
   (`graph_search`, `graph_node`, `graph_callers`, `graph_callees`,
   `graph_path`, `graph_stats`, `graph_sql`). Use this when you want the agent
   to call tools instead of running shell commands, including arbitrary
   read-only SQL. Register in Claude Code with:

   ```
   claude mcp add codegraph -- python tools/codegraph/codegraph.py mcp
   ```

   Both modes share the same index and the same code path; the CLI is the
   simpler default, MCP saves the ~0.2 s process startup and gives schema'd
   tools.

## Commands

```text
python codegraph.py <command> [args] [--graph <path>] [--json]

search <text>      find nodes by substring (case-insensitive)
                   [--kind method|class|module|ext] [--file <path-substr>]
                   [-n 20] [--offset N]
node <ref>         one node: id, file:lines, containing class/module chain,
                   cc, params, returns, throws, doc, edge counts  [--full]
find               nodes matching a CONJUNCTION of patterns:
                   [--kind k] [--name s] [--file s] [--mods a,b]
                   [--attr s ...] [--implements s ...] [--inherits s ...]
                   [--uses s ...] [--overrides s ...] [--calls s ...]
                   [--reaches s ...] [--reached-by s ...] [--reach-depth N]
                   [--member "kind:mod,mod,params=0|+,calls=s,uses=s,reaches=s" ...]
                   e.g. find --kind class --attr serializable
                        --member "constructor:public,params=0"
                        --member "property:public,get,set"
                   (gadget hunting: --inherits/--uses/--implements a known
                    gadget; see the codegraph skill for per-serializer recipes)
callers <ref>      tree of who calls it (toward origins)
                   [--depth 1] [--kind calls|contains|inherits|implements|any] [-n 30]
callees <ref>      tree of what it calls (toward targets)  (same options)
path <a> <b>       shortest path  [--kind calls] [--undirected] [--via-ext]
                   [--max-depth 15]
stats              graph overview
sql "<select>"     read-only SQL against the index  [-n 50]
index              force-rebuild the index
mcp                run as MCP stdio server
```

`<ref>` is `#123` / `123` (the node number shown in every output line), a full
node id, or a unique substring. The graph file is found via `--graph`, the
`CODEGRAPH_GRAPH` env var, or `mygraph.json` next to the script. `--json` switches
any command to compact machine-readable output.

### Recipes

| Question | Command |
|---|---|
| find a method | `search CheckTicksRange --kind method` |
| where do calls come from (transitively) | `callers #37479 --depth 3` |
| what does it call (transitively) | `callees #37479 --depth 2` |
| what class/module is it in | `node #37479` (the `container:` line) |
| members of a class/module | `callees #37474 --kind contains` |
| call chain between two nodes | `path #a #b` |
| who inherits from it | `callers #37474 --kind inherits` |
| most complex / most called | `sql "select id,label,cc from nodes order by cc desc limit 10"` |

### Output legend

```
#37479 fn CheckTicksRange  HijriCalendar.cs:182 x2 ~
│      │  │                │                    │  └ inferred (not certain)
│      │  │                │                    └ edge seen 2 times in source
│      │  │                └ file basename : start line
│      │  └ short label (full id via `node`)
│      └ fn=method/function cls=class mod=module ns=namespace
│        ext=external/unresolved target
└ node handle, usable as <ref> anywhere
^                node already shown above (cycle/repeat); not re-expanded
[+N alias targets]  callers also searched N unresolved forms of this method
[truncated at N] / [k/total shown]  use --limit / --offset for more
```

Exit codes: `0` ok, `2` not found / ambiguous (candidate list on stderr).

### Unresolved call targets (important)

The source graph records most calls as raw strings (`this.CheckTicksRange`,
`stringBuilder.Append`) rather than resolved node ids. These become `ext`
nodes. `callers` transparently folds them in: callers of a method include
callers of its plausible unresolved forms (`this.X`, `Class.X`, bare `X`;
suffix-matched, capped to qualified forms when the name is too common). Such
results are heuristic — they carry the `~` (inferred) marker, and a
`this.X` call from another class may match. `callees` needs no such handling
(its targets are simply shown as `ext` nodes). Because ext "hub" nodes connect
unrelated code, `path` skips them as intermediates unless `--via-ext`.

## SQL schema (for `sql` / `graph_sql`)

```
nodes(id, name, label, lname, kind, file, line1, line2, cc, nbranch,
      params, ret, throws, doc, mods, synthetic)
   -- lname = lower(unescaped name)
   -- mods  = space-joined modifiers e.g. "public get set" (NULL if the graph
   --         has none, e.g. mygraph). Match with: mods LIKE '%set%'
   -- synthetic = 1 for compiler-generated members (e.g. implicit constructors)
edges(src, dst, kind, conf, n)         -- n = times seen in source graph
files(id, path)   kinds(id, name)   ekinds(id, name)   confs(id, name)
meta(k, v)
-- joins: nodes.kind->kinds.id, nodes.file->files.id,
--        edges.src/dst->nodes.id, edges.kind->ekinds.id, edges.conf->confs.id
-- external nodes are exactly those with id >= (select v from meta where k='nodes')
```

Example using the richer `csgraph.json` — `[Serializable]` classes that are
also Json.NET-friendly (public parameterless ctor + public read/write props):

```sql
WITH ser AS (SELECT e.src cls FROM edges e JOIN nodes t ON t.id=e.dst
  JOIN ekinds k ON k.id=e.kind
  WHERE k.name='has_attribute' AND t.lname LIKE '%serializableattribute'),
ctor AS (SELECT ce.src cls FROM edges ce JOIN nodes m ON m.id=ce.dst
  JOIN kinds mk ON mk.id=m.kind JOIN ekinds ek ON ek.id=ce.kind
  WHERE ek.name='contains' AND mk.name='constructor'
    AND m.params IS NULL AND m.mods LIKE '%public%'),
prop AS (SELECT ce.src cls FROM edges ce JOIN nodes p ON p.id=ce.dst
  JOIN kinds pk ON pk.id=p.kind JOIN ekinds ek ON ek.id=ce.kind
  WHERE ek.name='contains' AND pk.name='property'
    AND p.mods LIKE '%public%' AND p.mods LIKE '%get%' AND p.mods LIKE '%set%')
SELECT n.label FROM ser JOIN ctor USING(cls) JOIN prop USING(cls)
  JOIN nodes n ON n.id=ser.cls GROUP BY ser.cls ORDER BY n.label;
```

Only `SELECT`/`WITH`/`EXPLAIN` are accepted, and the connection is read-only.

## Snippet for an agent's instructions (e.g. CLAUDE.md)

```markdown
## Code graph
A call/containment graph of the codebase is queryable via:
  python tools/codegraph/codegraph.py <cmd>
Run with no arguments for help. Flow: `search <name>` -> pick a #id ->
`callers #id --depth 2` (where it's called from) / `callees #id` (what it
calls) / `node #id` (details + containing class). Use #id handles, never full
node ids. Output is paginated; only raise --limit when needed.
```

## Development

- **Run tests:** `python -m pytest` (in this directory). 48 tests, <1 s.
- **Type check:** `python -m pyright codegraph.py tests` (pyright is Pylance's
  engine; the code is kept clean against it).
- **Layout:** everything is in `codegraph.py` (indexer → query layer → commands →
  MCP server → CLI wiring, in that order). Tests live in `tests/`:
  - `conftest.py` — a tiny synthetic graph mirroring the real file's quirks
    (UTF-16 BOM, `\.`-escaped ids, dict-shaped fields, duplicate edges,
    unresolved targets, a call cycle), with the expected node numbering in
    `ID`; build/CLI helpers (`run_cli`).
  - `test_unit.py` — pure helpers (labels, escaping, coercion, transcoder,
    encoding sniffing).
  - `test_cli.py` — every command end-to-end, including index staleness.
  - `test_mcp.py` — real JSON-RPC round-trip against an `mcp` subprocess.
- **Extending:** add a command function `cmd_x(g, a)`, a subparser, a dispatch
  entry, and (if agents should see it) an entry in `MCP_TOOLS` — the MCP
  server reuses the CLI path, so one implementation serves both. Add expected
  behavior to `test_cli.py`; extend the fixture in `conftest.py` by appending
  edges *last* to keep existing node numbers stable.
- **Requires:** Python 3.9+; `pip install ijson` (index build only),
  `pip install pytest pyright` (development only).

## License

Copyright (c) 2026 Soroush Dalili. Licensed under the same MIT License as YSoNet. See
[`LICENSE`](LICENSE). The copyright and permission notices must remain in all copies or
substantial portions of this tool.
