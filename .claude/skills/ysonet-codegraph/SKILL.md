---
name: ysonet-codegraph
description: Query the ysonet C# code graph (call / containment / inheritance / attribute edges). Use whenever you need to find where a method is called from, what it calls, call chains between two functions, class members, containing class/module, attributes/modifiers, or to do code review, security review, deserialization gadget hunting, or source-to-sink / sink-to-source (taint) reachability over the ysonet C# source. Never read or grep the multi-GB *.json graph file directly - query it through the codegraph CLI below.
---

# codegraph - ysonet code graph queries

All queries go through the CLI (fast, ~0.1-0.4 s per call; the index is built
once and reused):

```
python tools/codegraph/codegraph.py <command> [args]
```

The tool needs to know which graph JSON to read. Point it at the built ysonet
code graph in one of two ways:

- set it once per shell: `export CODEGRAPH_GRAPH=<path-to-ysonet-graph.json>`
  (PowerShell: `$env:CODEGRAPH_GRAPH = "<path>"`), then every command below runs
  as written; or
- pass `--graph <path>` on each call.

With neither set the tool errors with `graph JSON not found (use --graph <path>
or CODEGRAPH_GRAPH)`. The graph is large (often multi-GB) and is built by the
C# graph makers. It lives under the git-ignored `local/` folder and is never
committed (the generated graph may be copyrighted, so it is kept out of the
public repo). If the command above cannot find a graph, ask where it is or
build it first.

The tool auto-detects whether a graph is **resolved** (Roslyn/Cecil-built,
`resolved_calls: 1`: `calls`/`inherits`/`implements`/`type_uses`/`overrides`
edges point at real nodes) or **heuristic** (calls recorded as name strings).
The ysonet C# graph built by the Roslyn maker is resolved, so `callers`/
`callees`/`path` are exact, and it also carries properties, fields, events,
attributes, and accessibility modifiers. The recipes below assume a resolved
graph; on a heuristic graph, name-matched aliases are folded in and marked `~`.

## Commands

| Goal | Command |
|---|---|
| find a node by name | `search <text> [--kind method\|class\|module\|ext] [--file <substr>] [-n 20] [--offset N]` |
| node details + containing class/module | `node <ref> [--full]` |
| where is it called from (tree toward origins) | `callers <ref> [--depth 2-3] [-n 30]` |
| what does it call (tree toward targets) | `callees <ref> [--depth 2] [-n 30]` |
| members of a class/module | `callees <ref> --kind contains` |
| who inherits / implements it | `callers <ref> --kind inherits` (or `implements`) |
| call chain between two nodes | `path <a> <b> [--undirected] [--via-ext]` |
| **find nodes matching a pattern** | `find <predicates>` (see below) |
| graph overview | `stats` |
| anything else | `sql "select ..."` (read-only; schema below) |

## find - pattern matching (conjunction of predicates)

`find` returns nodes where ALL given conditions hold. Repeatable flags add
conditions.

```
find [--kind <k>] [--name <substr>] [--file <substr>] [--mods a,b]
     [--attr <substr> ...]          node has an attribute whose name contains substr
     [--implements <substr> ...]    implements an interface matching substr
     [--inherits <substr> ...]      inherits a base matching substr
     [--uses <substr> ...]          references a type matching substr (type_uses)
     [--overrides <substr> ...]     overrides a member matching substr
     [--calls <substr> ...]         (methods) has an outgoing call to a match (1 hop)
     [--reaches <substr> ...]       can REACH a target via calls within --reach-depth
                                    hops (transitive; source->sink, multi-hop gadgets)
     [--reached-by <substr> ...]    is reachable FROM a source (reverse)
     [--reach-depth N]              max hops for reaches/reached-by (default 4)
     [--member <spec> ...]          contains a member matching spec
     [-n N] [--offset N]
```

`--reaches`/`--reached-by` do a bounded call-graph walk in Python, so put a
structural predicate first (e.g. `--kind method`) to narrow candidates - an
unnarrowed reach scan is capped and will say so. `reaches=` is also a `--member`
token, e.g. `--member "constructor:reaches=binaryformatter.deserialize"` =
"a class with a ctor that transitively reaches BinaryFormatter" (bridge gadget).

`--member` spec = `kind[:tok,tok,...]` where toks are modifiers the member must
have (`public`/`get`/`set`/`static`/...) plus: `params=0`/`params=+`,
`type=<substr>` (member's own type - works for primitives too), `calls=<substr>`
(member calls a matching target, 1 hop), `uses=<substr>` (signature references a
type via type_uses), and `reaches=<substr>` (member transitively reaches a target
via calls - multi-hop). Examples: `constructor:public,params=0`,
`property:public,get,set`, `field:type=DataSet`, `method:calls=invoke`
(ObjectDataProvider shape), `constructor:reaches=binaryformatter.deserialize`
(bridge gadget).

Example - classes serializable+deserializable by BinaryFormatter and Json.NET
(i.e. `[Serializable]`, a public parameterless ctor, and a public read/write
property), optionally requiring `ISerializable`:

```
find --kind class --attr serializable \
     --member "constructor:public,params=0" \
     --member "property:public,get,set"
# add --implements ISerializable to also require the ISerializable contract
```

`<ref>` = `#123` or `123` (node number shown in every output line - always prefer
these), a full node id, or a unique substring. Add `--json` to any command for
machine-readable output (usually unnecessary; text is fewer tokens).

## Workflow

1. `search ModuleEditor --kind class` -> pick the right `#id` from the results.
2. `node #232` -> file:lines, `container:` chain, params, complexity, edge counts.
3. `callers #232 --depth 2` / `callees #232` -> trace in either direction.

## Reading the output

```
#232 fn ModuleEditor.Render  ModuleEditor.cs:39
```
`#id kind label file:line`; `x2` (if present) = edge appeared twice; `~` =
inferred (only on heuristic graphs); `^` = node already shown above (cycle, not
re-expanded). Kinds: `fn` method/function, `cls` class, `ctor` constructor,
`prop` property, `fld` field, `evt` event, `op` operator, `del` delegate, `ifc`
interface, `str` struct, `enum`, `enumv` enum-member, `ns` namespace, `ext`
external/unresolved target (BCL/NuGet APIs outside the graphed ysonet source).
Trees indent under the node that reached them, so a chain reads top-to-bottom as
a call path. Lists are paginated - `[k/total shown]` / `[truncated at N]`; only
raise `-n`/`--offset` when needed.

Exit code 2 = not found or ambiguous; candidate list is printed on stderr -
pick one and retry with its `#id`.

## Quirks

- On a resolved graph, `callers`/`callees` are exact (no `[+N alias targets]`
  alias-folding, no `~` unresolved-guess markers on real edges). Unresolved
  external calls (things outside the graphed ysonet source, e.g. BCL/NuGet APIs)
  still show up as `ext` nodes - that is expected, not a heuristic artifact.
- `path` skips `ext` hub nodes as intermediates (they connect unrelated code);
  pass `--via-ext` only if you explicitly want them (e.g. tracing through a
  BCL/framework call).

## Graph scope

The graph covers the ysonet C# source that the graph maker ingested. It has real
`calls` edges plus properties, fields, events, **attributes** (`has_attribute`),
accessibility **modifiers** (`mods` column, e.g. "public get set"), and
`overrides` / `type_uses` edges - reliable for security / source-sink / taint
work. External code (BCL, NuGet packages, framework internals) is not graphed;
those calls appear as `ext` nodes and are not walked into. For anything outside
the graphed C# source, fall back to `Grep`/`Glob`.

## Security, source-to-sink and review recipes

Calls are directed caller -> callee. So:

- **source -> sink** (does/how a source reaches a sink): `path <source> <sink>`
  for the shortest call chain, or `callees <source> --depth N` for the forward
  reachable set (a tree toward sinks).
- **sink -> source** (what can reach a dangerous sink, back toward entry points
  / untrusted input): `callers <sink> --depth N` (a tree toward origins).
- **find sinks / sources** by API: `search <Api>` (e.g. `Process.Start`,
  `SqlCommand`, `Deserialize`, `File.ReadAll`), then take the `#id`. Or with
  `sql`, e.g. callers of any method named like a sink:
  `sql "select s.label, t.label from edges e join nodes s on s.id=e.src join nodes t on t.id=e.dst join ekinds k on k.id=e.kind where k.name='calls' and t.lname like '%.deserialize'"`
- **code review of a unit**: `node <id>` (signature, complexity, attributes,
  container), `callees <id>` (its dependencies), `callers <id>` (its blast
  radius); rank complexity hotspots with
  `sql "select id,label,cc from nodes order by cc desc limit 20"`.
- **attribute/shape checks** (resolved graphs): join `has_attribute` and `mods`
  in `sql` - e.g. classes that are `[Serializable]` with public read/write
  properties, or methods marked `[Obsolete]`.

## Deserialization gadget hunting

ysonet builds deserialization payloads, so gadget shapes are a primary review
target. A **gadget** is a type a serializer will instantiate/populate during
deserialization whose side effects (constructor, property setters, deserialization
callbacks, finalizer) can be steered toward a dangerous sink. Gadget hunting
works directly on the resolved graph (scoped to the graphed ysonet C# source; it
has no visibility into BCL/NuGet/framework types, only how ysonet code uses them).

**1. Find candidate gadgets for a serializer** - the "is this type a target?"
condition differs per serializer; express it with `find`:

| serializer(s) | what makes a type a target | find query |
|---|---|---|
| BinaryFormatter, SoapFormatter, LosFormatter, ObjectStateFormatter, NetDataContractSerializer | `[Serializable]` or `ISerializable` | `find --kind class --attr serializable` / `find --kind class --implements ISerializable` |
| DataContractSerializer, DataContractJsonSerializer | `[DataContract]` (often with `[KnownType]`) | `find --kind class --attr datacontract` |
| Json.NET (Newtonsoft), JavaScriptSerializer, most JSON | public type, parameterless ctor, settable members | `find --kind class --member "constructor:public,params=0" --member "property:public,set"` (also `--attr jsonobject`) |
| XmlSerializer | public parameterless ctor + public read/write members | `find --kind class --member "constructor:public,params=0" --member "property:public,get,set"` |

Narrow to *dangerous* gadgets with a behavioral member condition, e.g. a
reflection-invoking gadget like ObjectDataProvider (which is NOT `[Serializable]`
- attribute rules miss it):
`find --kind class --member "method:calls=invoke" --member "property:public,set" --member "constructor:public,params=0"`
or require `--implements IDeserializationCallback`, or combine with step 3.

**2. From a known gadget G (its #id), expand the gadget/sink set:**

- classes that **extend** it (subclasses are gadgets too):
  `callers <G> --kind inherits --depth 5`  (or `find --kind class --inherits <Gname>`)
- **implementers** (if G is an interface): `callers <G> --kind implements`
- classes/members that **use** it (hold or construct it -> can become sinks):
  `callers <G> --kind type_uses` (signature references) and
  `callers <Gctor> --kind calls` (constructions). The labels show
  `Container.Member`, so you see the using class.
- who **overrides** its magic method: `callers <G.Member> --kind overrides`

**3. Find bridge gadgets by rule (no names) - multi-hop:** a `[Serializable]`
class whose deserialization constructor transitively reaches a formatter:
```
find --kind class --implements ISerializable \
     --member "constructor:reaches=binaryformatter.deserialize"
```
Drop `--implements ISerializable` or raise `--reach-depth` for wider recall;
use getter gadgets via `find --kind property --reaches binaryformatter.deserialize`.
This only sees gadget chains within the graphed ysonet source; it cannot follow
a chain into BCL/NuGet/framework internals, which are not graphed.

**4. Confirm a gadget/user is dangerous (reaches a sink):**

- list its deserialization-triggered members: `callees <G> --kind contains`
  (look at setters, `OnDeserialized`, `OnDeserialization`, ctor, finalizer);
- trace each toward a sink: `callees <member> --depth 4` or
  `path <member> <sink>`;
- find sinks first with `find --kind method --calls <DangerousApi>` (e.g.
  `Process.Start`, `Assembly.Load`, `Activator.CreateInstance`, `File.`,
  `Marshal.`), then `callers <sink> --depth N` to see what reaches them.

This same shape (find a property/edge condition, then traverse callers/callees
or path) covers general bug hunting too - e.g. unvalidated input reaching a
sink, classes missing an attribute, overrides of a security-sensitive method.

## SQL schema (for the `sql` command)

```
nodes(id, name, label, lname, kind, file, line1, line2, cc, nbranch,
      params, ret, throws, doc, mods, synthetic)
   -- lname = lower(unescaped name); mods = space-joined modifiers
   -- (populated on a resolved graph); synthetic = 1 for compiler-generated
   -- members (e.g. implicit ctors)
edges(src, dst, kind, conf, n)         -- n = times edge appeared
files(id, path)  kinds(id, name)  ekinds(id, name)  confs(id, name)  meta(k, v)
-- joins: nodes.kind->kinds.id, nodes.file->files.id,
--        edges.src/dst->nodes.id, edges.kind->ekinds.id
-- ext nodes: id >= (select v from meta where k='nodes')
```
Example - top 10 most complex methods:
`sql "select id, label, cc from nodes order by cc desc limit 10"`

If the index is missing/stale it rebuilds automatically (~22 s for a large
graph; requires the `ijson` package and prints progress to stderr). Full docs:
`tools/codegraph/README.md`.
