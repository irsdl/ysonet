#!/usr/bin/env python3
# Copyright (c) 2026 Soroush Dalili
# SPDX-License-Identifier: MIT
"""codegraph - memory- and token-efficient query tool for a large code-graph JSON.

Indexes a multi-GB graph JSON (UTF-16 or UTF-8) once into a compact SQLite
database, then answers queries instantly with tiny memory and terse output
designed for AI agents (short #id handles instead of 150-char node ids).

Requires: python 3.9+, ijson (only for the one-time `index` step).
"""

import argparse
import codecs
import contextlib
import io
import json
import os
import sqlite3
import sys
import time

INDEX_VERSION = 2  # v2: added nodes.mods / nodes.synthetic columns
CHUNK = 1 << 20

# ---------------------------------------------------------------------------
# helpers


def unescape(s: str) -> str:
    """Graph ids escape literal dots as '\\.'; undo that for display/search."""
    return s.replace("\\.", ".")


def make_label(s: str) -> str:
    """Short display name: after last ':', else last segment split on
    unescaped '.', then unescaped."""
    i = s.rfind(":")
    if i >= 0:
        return unescape(s[i + 1:])
    j = len(s) - 1
    while j > 0:
        if s[j] == "." and s[j - 1] != "\\":
            return unescape(s[j + 1:])
        j -= 1
    return unescape(s)


KIND_ABBREV = {
    "function": "fn", "method": "fn", "class": "cls", "module": "mod",
    "external": "ext", "namespace": "ns", "interface": "ifc", "struct": "str",
    "enum": "enum", "property": "prop", "field": "fld", "file": "file",
    "unknown": "?",
    # extra kinds from the Roslyn / Cecil C# makers
    "constructor": "ctor", "finalizer": "dtor", "operator": "op",
    "event": "evt", "delegate": "del", "enum_member": "enumv",
}


def kind_abbrev(name: str) -> str:
    return KIND_ABBREV.get(name, name[:4])


class U16ToU8(io.RawIOBase):
    """Streams a UTF-16-LE file as UTF-8 bytes (for ijson) without loading it."""

    def __init__(self, f):
        self.f = f
        self.dec = codecs.getincrementaldecoder("utf-16-le")()
        self.buf = bytearray()
        self.eof = False

    def readable(self):
        return True

    def read(self, n=-1):
        if n is None or n < 0:
            n = 1 << 62
        while len(self.buf) < n and not self.eof:
            c = self.f.read(CHUNK)
            if not c:
                self.eof = True
                self.buf += self.dec.decode(b"", True).encode("utf-8")
                break
            self.buf += self.dec.decode(c).encode("utf-8")
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def readinto(self, b):
        data = self.read(len(b))
        n = len(data)
        b[:n] = data
        return n


def open_json_bytes(path):
    """Returns (utf8_stream_for_ijson, raw_file_for_tell)."""
    f = open(path, "rb", buffering=CHUNK)
    head = f.read(3)
    if head[:2] == b"\xff\xfe":
        f.seek(2)
        return U16ToU8(f), f
    if head == b"\xef\xbb\xbf":
        return f, f
    if len(head) >= 2 and head[1] == 0 and head[0] != 0:
        f.seek(0)
        return U16ToU8(f), f
    f.seek(0)
    return f, f


def err(msg):
    print(msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# index build

SCHEMA = """
CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE kinds(id INTEGER PRIMARY KEY, name TEXT UNIQUE);
CREATE TABLE ekinds(id INTEGER PRIMARY KEY, name TEXT UNIQUE);
CREATE TABLE confs(id INTEGER PRIMARY KEY, name TEXT UNIQUE);
CREATE TABLE files(id INTEGER PRIMARY KEY, path TEXT UNIQUE);
CREATE TABLE nodes(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  label TEXT NOT NULL,
  lname TEXT NOT NULL,
  kind INTEGER NOT NULL,
  file INTEGER,
  line1 INTEGER,
  line2 INTEGER,
  cc INTEGER,
  nbranch INTEGER,
  params TEXT,
  ret TEXT,
  throws TEXT,
  doc TEXT,
  mods TEXT,        -- space-joined modifiers/accessibility (e.g. "public get set");
                    -- NULL for graphs that don't emit them (e.g. trailmark)
  synthetic INTEGER -- 1 for compiler-generated members (e.g. implicit ctors)
);
CREATE TABLE edges(src INTEGER, dst INTEGER, kind INTEGER, conf INTEGER, n INTEGER);
"""


class Interner:
    def __init__(self):
        self.map = {}
        self.items = []

    def get(self, name):
        i = self.map.get(name)
        if i is None:
            i = len(self.items)
            self.map[name] = i
            self.items.append(name)
        return i


def fmt_param(p):
    if isinstance(p, dict):
        n, t = p.get("name"), p.get("type")
        if t and n:
            return f"{t} {n}"
        return str(n or t or "?")
    return str(p)


def as_text(v):
    """Coerce arbitrarily-shaped JSON values to a short string (or None)."""
    if v is None or isinstance(v, str):
        return v
    if isinstance(v, dict):
        for k in ("name", "type", "value"):
            if isinstance(v.get(k), str):
                return v[k]
    try:
        return json.dumps(v, default=str)
    except (TypeError, ValueError):
        return str(v)


def build_index(graph_path, db_path, quiet=False):
    try:
        import ijson
    except ImportError:
        err("error: indexing requires the 'ijson' package: pip install ijson")
        sys.exit(1)

    t0 = time.time()
    total_bytes = os.path.getsize(graph_path)
    if os.path.exists(db_path):
        os.remove(db_path)
    db = sqlite3.connect(db_path)
    db.execute("PRAGMA journal_mode=OFF")
    db.execute("PRAGMA synchronous=OFF")
    db.execute("PRAGMA temp_store=1")
    db.execute("PRAGMA cache_size=-65536")
    db.executescript(SCHEMA)

    kinds, ekinds, confs, files = Interner(), Interner(), Interner(), Interner()
    name2id = {}
    next_id = 0
    nodes_batch = []
    n_external = 0

    def flush_nodes():
        nonlocal nodes_batch
        if nodes_batch:
            db.executemany(
                "INSERT INTO nodes VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", nodes_batch)
            nodes_batch = []

    def progress(stage, raw):
        if not quiet:
            pct = min(99, int(100 * raw.tell() / total_bytes))
            sys.stderr.write(
                f"\r{stage} {pct}%  nodes={next_id:,}  {time.time()-t0:.0f}s   ")
            sys.stderr.flush()

    # --- pass 0: header (language / root_path / summary) -- reads file head only
    head_meta = {"language": "", "root_path": "", "summary": {}}
    deps = []
    src, raw = open_json_bytes(graph_path)
    for prefix, event, value in ijson.parse(src):
        if event == "string" and prefix in ("language", "root_path"):
            head_meta[prefix] = value
        elif prefix.startswith("summary."):
            key = prefix[len("summary."):]
            if key == "dependencies.item":
                deps.append(value)
            elif event in ("number", "string"):
                head_meta["summary"][key] = int(value) if event == "number" else value
        elif prefix == "nodes" and event == "start_map":
            break
    raw.close()
    head_meta["summary"]["dependencies"] = deps

    # --- pass 1: nodes
    src, raw = open_json_bytes(graph_path)
    count = 0
    for key, nd in ijson.kvitems(src, "nodes"):
        if key in name2id:
            continue
        loc = nd.get("location")
        if not isinstance(loc, dict):
            loc = {}
        params = nd.get("parameters")
        if not isinstance(params, list):
            params = []
        exc = nd.get("exception_types")
        if not isinstance(exc, list):
            exc = []
        br = nd.get("branches")
        cc = nd.get("cyclomatic_complexity")
        fp = loc.get("file_path")
        if not isinstance(fp, str):
            fp = None
        base = nd.get("name")
        if not isinstance(base, str) or not base:
            base = key
        try:
            l1 = int(loc.get("start_line") or 0) or None
            l2 = int(loc.get("end_line") or 0) or None
        except (TypeError, ValueError):
            l1 = l2 = None
        try:
            cc = int(cc) if cc is not None else None
        except (TypeError, ValueError):
            cc = None
        mods = nd.get("modifiers")
        mods = " ".join(str(m) for m in mods) if isinstance(mods, list) and mods else None
        nodes_batch.append((
            next_id,
            key,
            make_label(base),
            unescape(key).lower(),
            kinds.get(as_text(nd.get("kind")) or "unknown"),
            files.get(fp) if fp else None,
            l1,
            l2,
            cc,
            len(br) if isinstance(br, list) else 0,
            "; ".join(fmt_param(p) for p in params) or None,
            as_text(nd.get("return_type")),
            ", ".join(str(as_text(x)) for x in exc) or None,
            as_text(nd.get("docstring")),
            mods,
            1 if nd.get("synthetic") else None,
        ))
        name2id[key] = next_id
        next_id += 1
        count += 1
        if len(nodes_batch) >= 2000:
            flush_nodes()
            if count % 20000 == 0:
                progress("indexing nodes", raw)
    flush_nodes()
    raw.close()
    n_nodes = next_id

    # --- pass 2: edges (raw -> dedup with counts)
    ext_kind = kinds.get("external")
    db.execute("CREATE TABLE eraw(src INTEGER, dst INTEGER, kind INTEGER, conf INTEGER)")
    eraw_batch = []
    n_raw_edges = 0

    def node_ref(name):
        nonlocal next_id, n_external
        i = name2id.get(name, -1)
        if i < 0:
            i = next_id
            name2id[name] = i
            next_id += 1
            n_external += 1
            un = unescape(name)
            nodes_batch.append((i, name, un, un.lower(), ext_kind, None, None,
                                None, None, 0, None, None, None, None, None, None))
        return i

    src, raw = open_json_bytes(graph_path)
    for e in ijson.items(src, "edges.item"):
        s, t = e.get("source"), e.get("target")
        if not isinstance(s, str) or not isinstance(t, str) or not s or not t:
            continue
        eraw_batch.append((
            node_ref(s),
            node_ref(t),
            ekinds.get(as_text(e.get("kind")) or "unknown"),
            confs.get(as_text(e.get("confidence")) or "unknown"),
        ))
        n_raw_edges += 1
        if len(eraw_batch) >= 5000:
            db.executemany("INSERT INTO eraw VALUES(?,?,?,?)", eraw_batch)
            eraw_batch = []
            flush_nodes()
            if n_raw_edges % 100000 == 0 and not quiet:
                sys.stderr.write(
                    f"\rindexing edges {min(99, int(100 * raw.tell() / total_bytes))}%  "
                    f"edges={n_raw_edges:,}  {time.time()-t0:.0f}s   ")
                sys.stderr.flush()
    if eraw_batch:
        db.executemany("INSERT INTO eraw VALUES(?,?,?,?)", eraw_batch)
    flush_nodes()
    raw.close()
    name2id.clear()  # free

    if not quiet:
        sys.stderr.write("\rfinalizing (dedup + indexes)...                              ")
        sys.stderr.flush()
    db.execute("INSERT INTO edges SELECT src,dst,kind,conf,COUNT(*) FROM eraw "
               "GROUP BY src,dst,kind,conf")
    n_unique = db.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
    db.execute("DROP TABLE eraw")
    db.executemany("INSERT INTO kinds VALUES(?,?)", list(enumerate(kinds.items)))
    db.executemany("INSERT INTO ekinds VALUES(?,?)", list(enumerate(ekinds.items)))
    db.executemany("INSERT INTO confs VALUES(?,?)", list(enumerate(confs.items)))
    db.executemany("INSERT INTO files VALUES(?,?)", list(enumerate(files.items)))
    db.execute("CREATE UNIQUE INDEX idx_nodes_name ON nodes(name)")
    db.execute("CREATE INDEX idx_edges_src ON edges(src)")
    db.execute("CREATE INDEX idx_edges_dst ON edges(dst)")

    st = os.stat(graph_path)
    meta = {
        "version": INDEX_VERSION,
        "source_size": st.st_size,
        "source_mtime": int(st.st_mtime),
        "language": head_meta["language"],
        "root_path": head_meta["root_path"],
        "summary": head_meta["summary"],
        "nodes": n_nodes,
        "externals": n_external,
        "raw_edges": n_raw_edges,
        "unique_edges": n_unique,
    }
    db.executemany("INSERT INTO meta VALUES(?,?)",
                   [(k, json.dumps(v)) for k, v in meta.items()])
    db.execute("ANALYZE")
    db.commit()
    db.close()
    if not quiet:
        sys.stderr.write(
            f"\rindexed {n_nodes:,} nodes (+{n_external:,} external), "
            f"{n_raw_edges:,} edges ({n_unique:,} unique) in {time.time()-t0:.0f}s "
            f"-> {os.path.basename(db_path)} "
            f"({os.path.getsize(db_path)/1e6:.0f} MB)\n")


# ---------------------------------------------------------------------------
# query layer


class G:
    """Read-only handle over the index."""

    def __init__(self, db_path):
        self.db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        self.db.execute("PRAGMA query_only=1")
        self.db.execute("PRAGMA mmap_size=268435456")
        self._tails = None
        self.meta = {k: json.loads(v)
                     for k, v in self.db.execute("SELECT k,v FROM meta")}
        self.kinds = [r[1] for r in
                      self.db.execute("SELECT id,name FROM kinds ORDER BY id")]
        self.ekinds = [r[1] for r in
                       self.db.execute("SELECT id,name FROM ekinds ORDER BY id")]
        self.confs = [r[1] for r in
                      self.db.execute("SELECT id,name FROM confs ORDER BY id")]
        self.n = self.meta["nodes"] + self.meta["externals"]

        # Does this graph record calls as unresolved name strings (trailmark /
        # mygraph) or as resolved edges (the Roslyn/Cecil makers)? It decides
        # whether `callers` folds in alias targets: that heuristic recovers
        # hidden callers on an unresolved graph, but injects FALSE callers on a
        # resolved one (a bare-name match to an unrelated method). Prefer an
        # explicit summary flag from the maker; otherwise infer from how many
        # nodes are unresolved external targets (heuristic graphs are ~40-60%
        # external; resolved graphs are a few percent).
        rc = (self.meta.get("summary") or {}).get("resolved_calls")
        if rc is not None:
            self.heuristic_calls = not rc
        else:
            self.heuristic_calls = self.meta["externals"] / max(1, self.n) > 0.25

    def kind_id(self, text):
        """Match a node-kind by exact name, abbrev, or unique prefix."""
        t = text.lower()
        for i, k in enumerate(self.kinds):
            if k == t or kind_abbrev(k) == t:
                return i
        pref = [i for i, k in enumerate(self.kinds) if k.startswith(t)]
        if len(pref) == 1:
            return pref[0]
        raise SystemExit(f"error: unknown kind '{text}' (kinds: {', '.join(self.kinds)})")

    def ekind_id(self, text):
        if text is None or text == "any":
            return None
        t = text.lower()
        for i, k in enumerate(self.ekinds):
            if k == t:
                return i
        pref = [i for i, k in enumerate(self.ekinds) if k.startswith(t)]
        if len(pref) == 1:
            return pref[0]
        raise SystemExit(
            f"error: unknown edge kind '{text}' (kinds: {', '.join(self.ekinds)}, any)")

    def node(self, i):
        return self.db.execute(
            "SELECT n.id,n.name,n.label,n.kind,f.path,n.line1,n.line2,n.cc,"
            "n.nbranch,n.params,n.ret,n.throws,n.doc,n.mods,n.synthetic "
            "FROM nodes n LEFT JOIN files f ON f.id=n.file WHERE n.id=?",
            (i,)).fetchone()

    def line(self, i, extra=""):
        r = self.db.execute(
            "SELECT n.id,n.label,n.kind,f.path,n.line1 "
            "FROM nodes n LEFT JOIN files f ON f.id=n.file WHERE n.id=?",
            (i,)).fetchone()
        if not r:
            return f"#{i} ?"
        _, label, kind, path, line1 = r
        loc = ""
        if path:
            loc = f"  {os.path.basename(path)}" + (f":{line1}" if line1 else "")
        return f"#{i} {kind_abbrev(self.kinds[kind])} {label}{loc}{extra}"

    def row_json(self, i):
        r = self.db.execute(
            "SELECT n.id,n.label,n.kind,f.path,n.line1 "
            "FROM nodes n LEFT JOIN files f ON f.id=n.file WHERE n.id=?",
            (i,)).fetchone()
        _, label, kind, path, line1 = r
        d = {"id": i, "kind": self.kinds[kind], "label": label}
        if path:
            d["file"] = path
            if line1:
                d["line"] = line1
        return d

    def edge_suffix(self, n, conf):
        s = f" x{n}" if n > 1 else ""
        if self.confs[conf] != "certain":
            s += " ~"
        return s

    def _tail_index(self):
        """last-name-segment -> [(ext id, lname)] for all external nodes."""
        if self._tails is None:
            self._tails = {}
            for i, ln in self.db.execute(
                    "SELECT id,lname FROM nodes WHERE id>=?",
                    (self.meta["nodes"],)):
                self._tails.setdefault(ln.rsplit(".", 1)[-1], []).append((i, ln))
        return self._tails

    def aliases(self, i):
        """External nodes that plausibly stand for node i as an unresolved
        call target (the source graph records most calls as 'this.Method' /
        'Class.Method' strings rather than resolved node ids). Suffix-matched
        on the method name; when that is too common (>8 hits) only this- and
        class-qualified forms are kept."""
        if i >= self.meta["nodes"]:
            return []
        row = self.db.execute("SELECT label FROM nodes WHERE id=?", (i,)).fetchone()
        if not row:
            return []
        label = row[0].lower()
        tail = label.rsplit(".", 1)[-1]
        if len(tail) < 2:
            return []
        cands = self._tail_index().get(tail, [])
        if len(cands) > 8:
            parts = label.split(".")
            cls = parts[-2] if len(parts) > 1 else None
            cands = [(j, ln) for j, ln in cands
                     if ln == "this." + tail or ln == tail
                     or (cls and ln.endswith(cls + "." + tail))]
        return [j for j, _ in cands if j != i]

    def resolve(self, ref):
        """#123 | 123 | exact id | exact label | unique substring.
        Returns id or exits with candidate list."""
        r = ref[1:] if ref.startswith("#") else ref
        if r.isdigit():
            i = int(r)
            if 0 <= i < self.n:
                return i
            raise SystemExit(f"error: node #{i} out of range (0..{self.n - 1})")
        row = self.db.execute("SELECT id FROM nodes WHERE name=?", (ref,)).fetchone()
        if row:
            return row[0]
        rows = self.db.execute(
            "SELECT id FROM nodes WHERE label=? COLLATE NOCASE LIMIT 11",
            (ref,)).fetchall()
        if len(rows) == 1:
            return rows[0][0]
        pat = unescape(ref).lower()
        cands = self.db.execute(
            "SELECT id FROM nodes WHERE instr(lname,?)>0 LIMIT 11", (pat,)).fetchall()
        if len(cands) == 1:
            return cands[0][0]
        if not cands and not rows:
            err(f"error: no node matches '{ref}'")
            sys.exit(2)
        show = rows if len(rows) > 1 else cands
        err(f"ambiguous ref '{ref}'; candidates:")
        for (i,) in show[:10]:
            err("  " + self.line(i))
        if len(show) > 10:
            err("  ... (refine the text, or use search)")
        sys.exit(2)


def out_edges(g, i, ekind):
    q = "SELECT dst,kind,conf,n FROM edges WHERE src=?"
    args = [i]
    if ekind is not None:
        q += " AND kind=?"
        args.append(ekind)
    return g.db.execute(q, args).fetchall()


def in_edges(g, i, ekind):
    q = "SELECT src,kind,conf,n FROM edges WHERE dst=?"
    args = [i]
    if ekind is not None:
        q += " AND kind=?"
        args.append(ekind)
    return g.db.execute(q, args).fetchall()


# ---------------------------------------------------------------------------
# commands


def cmd_stats(g, a):
    m = g.meta
    if a.json:
        kc = {g.kinds[k]: c for k, c in
              g.db.execute("SELECT kind,COUNT(*) FROM nodes GROUP BY kind")}
        ec = {g.ekinds[k]: {"unique": u, "raw": r} for k, u, r in
              g.db.execute("SELECT kind,COUNT(*),SUM(n) FROM edges GROUP BY kind")}
        print(json.dumps({**m, "node_kinds": kc, "edge_kinds": ec},
                         separators=(",", ":")))
        return
    print(f"graph: {m['language']}  root: {m['root_path']}")
    print(f"nodes: {m['nodes']:,} (+{m['externals']:,} external targets) "
          f"-> refs #0..#{g.n - 1}")
    for k, c in g.db.execute(
            "SELECT kind,COUNT(*) FROM nodes GROUP BY kind ORDER BY 2 DESC"):
        print(f"  {g.kinds[k]}: {c:,}")
    print(f"edges: {m['raw_edges']:,} raw -> {m['unique_edges']:,} unique")
    for k, u, r in g.db.execute(
            "SELECT kind,COUNT(*),SUM(n) FROM edges GROUP BY kind ORDER BY 3 DESC"):
        print(f"  {g.ekinds[k]}: {r:,} ({u:,} unique)")
    nf = g.db.execute("SELECT COUNT(*) FROM files").fetchone()[0]
    print(f"files: {nf:,}")
    deps = m["summary"].get("dependencies", [])
    shown = ", ".join(deps[:15])
    more = f" (+{len(deps) - 15} more)" if len(deps) > 15 else ""
    print(f"deps ({len(deps)}): {shown}{more}")
    ep = m["summary"].get("entrypoints")
    if ep is not None:
        print(f"entrypoints: {ep}")


def cmd_search(g, a):
    pat = unescape(a.text).lower()
    cond, args = ["instr(n.lname,?)>0"], [pat]
    if a.kind:
        cond.append("n.kind=?")
        args.append(g.kind_id(a.kind))
    if a.file:
        cond.append("n.file IN (SELECT id FROM files WHERE instr(lower(path),?)>0)")
        args.append(a.file.lower())
    q = (f"SELECT n.id, COUNT(*) OVER () FROM nodes n WHERE {' AND '.join(cond)} "
         f"ORDER BY n.id LIMIT ? OFFSET ?")
    rows = g.db.execute(q, args + [a.limit, a.offset]).fetchall()
    total = rows[0][1] if rows else 0
    if a.json:
        print(json.dumps({"total": total,
                          "offset": a.offset,
                          "items": [g.row_json(i) for i, _ in rows]},
                         separators=(",", ":")))
        return
    for i, _ in rows:
        print(g.line(i))
    if total > a.offset + len(rows):
        print(f"[{a.offset + len(rows)}/{total} shown; next: --offset {a.offset + len(rows)}]")
    elif total == 0:
        print("no matches")


def _token_match(col):
    """SQL fragment matching a whole space-delimited token inside `col`
    (modifiers are stored space-joined, e.g. 'public get set')."""
    return f"instr(' '||COALESCE({col},'')||' ', ?)>0"


def member_clause(g, spec):
    """Compiles one --member spec into an EXISTS subclause + its params.

    spec = "<kind>[:tok,tok,...]" where toks are modifiers the member must
    have (whole-token match, e.g. public/get/set/static) plus the specials
    `params=0` (parameterless), `params=+` (takes >=1 parameter),
    `calls=<substr>` (the member calls a target matching substr) and
    `uses=<substr>` (the member's signature references a type matching substr).
    The clause is true when the node contains (via a `contains` edge) at least
    one member matching all of them. Examples:
        constructor:public,params=0     a public parameterless ctor
        property:public,get,set         a public read/write property
        method:calls=invoke             a method that calls something *invoke*
                                        (e.g. the ObjectDataProvider gadget shape)

    Also accepts `type=<substr>`: the member's own type (field/property type or
    method return type) contains substr - works for primitives too, unlike
    `uses=` which is a type_uses edge and skips language primitives.

    Also accepts `reaches=<substr>`: the member can *transitively* reach a
    target matching substr via calls (multi-hop). Because that is a bounded BFS
    (not a single SQL join), it is returned separately for Python post-filtering
    rather than baked into the SQL clause. Returns
    (sql_clause, sql_args, member_kind, reaches_substrs).
    """
    kind_part, _, tok_part = spec.partition(":")
    kind_name = g.kinds[g.kind_id(kind_part.strip())] if kind_part.strip() else None
    clause = ("EXISTS(SELECT 1 FROM edges ce JOIN nodes m ON m.id=ce.dst "
              "JOIN kinds mk ON mk.id=m.kind JOIN ekinds ek ON ek.id=ce.kind "
              "WHERE ce.src=n.id AND ek.name='contains'")
    cargs = []
    reaches = []
    if kind_name is not None:
        clause += " AND mk.name=?"
        cargs.append(kind_name)

    def member_edge(ekind, substr):
        nonlocal clause
        clause += (" AND EXISTS(SELECT 1 FROM edges me JOIN nodes mt ON mt.id=me.dst "
                   "JOIN ekinds mek ON mek.id=me.kind WHERE me.src=m.id "
                   "AND mek.name=? AND instr(mt.lname,?)>0)")
        cargs.extend([ekind, unescape(substr).lower()])

    for tok in tok_part.split(","):
        tok = tok.strip()
        if not tok:
            continue
        low = tok.lower()
        if low in ("params=0", "params=none", "parameterless"):
            clause += " AND m.params IS NULL"
        elif low in ("params=+", "params=any", "hasparams"):
            clause += " AND m.params IS NOT NULL"
        elif low.startswith("calls="):
            member_edge("calls", tok[len("calls="):])
        elif low.startswith("uses="):
            member_edge("type_uses", tok[len("uses="):])
        elif low.startswith("type="):
            # the member's own type (field/property type, or method return);
            # works for primitives too, unlike uses= (type_uses skips them)
            clause += " AND instr(lower(COALESCE(m.ret,'')),?)>0"
            cargs.append(tok[len("type="):].lower())
        elif low.startswith("reaches="):
            reaches.append(tok[len("reaches="):])
        else:
            clause += " AND " + _token_match("m.mods")
            cargs.append(f" {low} ")
    clause += ")"
    return clause, cargs, kind_name, reaches


def member_reaches_ok(g, cls_id, kind_name, substrs, depth):
    """True if `cls_id` contains a member (of kind_name, if given) that reaches
    every substr in `substrs` via calls within `depth` hops. This is the
    multi-hop bridge-gadget check, e.g. 'a class with a constructor that reaches
    BinaryFormatter.Deserialize'."""
    if "contains" not in g.ekinds:
        return False
    q = ("SELECT m.id FROM edges ce JOIN nodes m ON m.id=ce.dst "
         "JOIN kinds mk ON mk.id=m.kind JOIN ekinds ek ON ek.id=ce.kind "
         "WHERE ce.src=? AND ek.name='contains'")
    qargs = [cls_id]
    if kind_name is not None:
        q += " AND mk.name=?"
        qargs.append(kind_name)
    for (mid,) in g.db.execute(q, qargs):
        if all(reaches_target(g, mid, s, depth, False) for s in substrs):
            return True
    return False


def reaches_target(g, start, substr, max_depth, incoming, cap=20000):
    """True if `start` can reach a node whose lname contains `substr` by
    following `calls` edges (outgoing if not incoming, else reverse) within
    `max_depth` hops. Bounded BFS with an early exit on first match; `cap`
    limits visited nodes so call-graph hubs can't blow up. Used by find's
    --reaches / --reached-by for source->sink and gadget reachability."""
    if "calls" not in g.ekinds:
        return False
    ek = g.ekinds.index("calls")
    sub = unescape(substr).lower()
    col, other = ("dst", "src") if incoming else ("src", "dst")
    nbr_sql = (f"SELECT e.{other}, t.lname FROM edges e "
               f"JOIN nodes t ON t.id=e.{other} "
               f"WHERE e.{col}=? AND e.kind=?")
    seen = {start}
    frontier = [start]
    visited = 0
    for _ in range(max_depth):
        nxt = []
        for cur in frontier:
            for oid, lname in g.db.execute(nbr_sql, (cur, ek)):
                if oid in seen:
                    continue
                if lname and sub in lname:
                    return True
                seen.add(oid)
                visited += 1
                if visited > cap:
                    return False
                nxt.append(oid)
        if not nxt:
            break
        frontier = nxt
    return False


def cmd_find(g, a):
    """Find nodes matching a conjunction of structural predicates. All given
    conditions must hold (AND)."""
    cond, args = [], []
    if a.kind:
        cond.append("n.kind=?")
        args.append(g.kind_id(a.kind))
    if a.name:
        cond.append("instr(n.lname,?)>0")
        args.append(unescape(a.name).lower())
    if a.file:
        cond.append("n.file IN (SELECT id FROM files WHERE instr(lower(path),?)>0)")
        args.append(a.file.lower())
    for m in (a.mods.split(",") if a.mods else []):
        m = m.strip().lower()
        if m:
            cond.append(_token_match("n.mods"))
            args.append(f" {m} ")

    def edge_pred(ekind, substr):
        cond.append(
            "EXISTS(SELECT 1 FROM edges e JOIN nodes t ON t.id=e.dst "
            "JOIN ekinds k ON k.id=e.kind "
            "WHERE e.src=n.id AND k.name=? AND instr(t.lname,?)>0)")
        args.extend([ekind, unescape(substr).lower()])

    for s in a.attr:
        edge_pred("has_attribute", s)
    for s in a.implements:
        edge_pred("implements", s)
    for s in a.inherits:
        edge_pred("inherits", s)
    for s in a.uses:
        edge_pred("type_uses", s)
    for s in a.overrides:
        edge_pred("overrides", s)
    for s in a.calls:
        edge_pred("calls", s)
    member_reaches = []  # [(kind_name, [substrs])] for Python post-filter
    for spec in a.member:
        clause, cargs, mkind, mreach = member_clause(g, spec)
        cond.append(clause)
        args.extend(cargs)
        if mreach:
            member_reaches.append((mkind, mreach))

    reaches = getattr(a, "reaches", []) or []
    reached_by = getattr(a, "reached_by", []) or []
    if not cond and not (reaches or reached_by):
        raise SystemExit("error: find needs at least one predicate "
                         "(--kind/--attr/--member/--implements/--inherits/"
                         "--uses/--overrides/--calls/--reaches/--reached-by/"
                         "--mods/--name/--file)")

    if reaches or reached_by or member_reaches:
        # Reachability is a bounded call-graph BFS done in Python, so we can't
        # paginate in SQL: fetch all structural candidates, filter by reach,
        # then page. A structural predicate should narrow the candidates first
        # (BFS over every node would be wasteful); cap how many we BFS.
        # Node-level reach only makes sense for nodes that actually have call
        # edges; pruning the rest (e.g. auto-properties, data fields) both
        # speeds the BFS and stops dead nodes from eating the candidate cap.
        # (Not applied for member-level reaches: there the candidate is the
        # container class, which has no calls of its own.)
        extra = []
        if reaches:
            extra.append("EXISTS(SELECT 1 FROM edges e JOIN ekinds k ON k.id=e.kind "
                         "WHERE e.src=n.id AND k.name='calls')")
        if reached_by:
            extra.append("EXISTS(SELECT 1 FROM edges e JOIN ekinds k ON k.id=e.kind "
                         "WHERE e.dst=n.id AND k.name='calls')")
        all_cond = cond + extra
        where = " AND ".join(all_cond) if all_cond else "1"
        cand = [r[0] for r in g.db.execute(
            f"SELECT n.id FROM nodes n WHERE {where} ORDER BY n.id", args).fetchall()]
        cap = getattr(a, "reach_cap", 6000)
        capped = len(cand) > cap
        depth = getattr(a, "reach_depth", 4)
        kept = []
        for i in cand[:cap]:
            if (all(reaches_target(g, i, s, depth, False) for s in reaches)
                    and all(reaches_target(g, i, s, depth, True) for s in reached_by)
                    and all(member_reaches_ok(g, i, kn, subs, depth)
                            for kn, subs in member_reaches)):
                kept.append(i)
        total = len(kept)
        page = kept[a.offset:a.offset + a.limit]
        if a.json:
            print(json.dumps({"total": total, "offset": a.offset,
                              "truncated_candidates": capped,
                              "items": [g.row_json(i) for i in page]},
                             separators=(",", ":")))
            return
        for i in page:
            print(g.line(i))
        if capped:
            print(f"[only the first {cap} structural candidates were checked for "
                  f"reachability; add predicates to narrow]")
        if total > a.offset + len(page):
            print(f"[{a.offset + len(page)}/{total} shown; next: --offset {a.offset + len(page)}]")
        elif total == 0:
            print("no matches")
        return

    q = (f"SELECT n.id, COUNT(*) OVER () FROM nodes n WHERE {' AND '.join(cond)} "
         f"ORDER BY n.id LIMIT ? OFFSET ?")
    rows = g.db.execute(q, args + [a.limit, a.offset]).fetchall()
    total = rows[0][1] if rows else 0
    if a.json:
        print(json.dumps({"total": total, "offset": a.offset,
                          "items": [g.row_json(i) for i, _ in rows]},
                         separators=(",", ":")))
        return
    for i, _ in rows:
        print(g.line(i))
    if total > a.offset + len(rows):
        print(f"[{a.offset + len(rows)}/{total} shown; next: --offset {a.offset + len(rows)}]")
    elif total == 0:
        print("no matches")


def container_chain(g, i, max_up=5):
    """Walk 'contains' edges upwards: [class, module, ...] containing node i."""
    if "contains" not in g.ekinds:
        return []
    ek = g.ekinds.index("contains")
    chain = []
    cur = i
    for _ in range(max_up):
        up = in_edges(g, cur, ek)
        if not up:
            break
        cur = up[0][0]
        chain.append(cur)
    return chain


def cmd_node(g, a):
    i = g.resolve(a.ref)
    (nid, name, label, kind, path, l1, l2, cc, nbranch,
     params, ret, throws, doc, mods, synthetic) = g.node(i)
    deg = {}
    for d, tbl in (("out", "src"), ("in", "dst")):
        deg[d] = {g.ekinds[k]: int(s) for k, s in g.db.execute(
            f"SELECT kind,SUM(n) FROM edges WHERE {tbl}=? GROUP BY kind", (i,))}
    chain = container_chain(g, i)
    if a.json:
        print(json.dumps({
            "id": nid, "name": name, "label": label, "kind": g.kinds[kind],
            "file": path, "lines": [l1, l2], "cc": cc, "branches": nbranch,
            "params": params, "returns": ret, "throws": throws, "doc": doc,
            "modifiers": mods.split() if mods else [],
            "synthetic": bool(synthetic),
            "container": [g.row_json(c) for c in chain],
            "edges": deg}, separators=(",", ":")))
        return
    head = f"#{nid} {g.kinds[kind]} {label}"
    if mods:
        head += f"  [{mods}]"
    if synthetic:
        head += "  (synthetic)"
    print(head)
    if name != label:
        print(f"id: {name}")
    if path:
        loc = f"{path}:{l1}-{l2}" if l1 else path
        print(f"file: {loc}")
    if chain:
        parts = []
        for c in chain:
            rj = g.row_json(c)
            parts.append(f"#{c} {kind_abbrev(rj['kind'])} {rj['label']}")
        print("container: " + " < ".join(parts))
    extras = []
    if cc is not None:
        extras.append(f"cc={cc}")
    if nbranch:
        extras.append(f"branches={nbranch}")
    if extras:
        print("  ".join(extras))
    if params:
        print(f"params: {params}")
    if ret:
        print(f"returns: {ret}")
    if throws:
        print(f"throws: {throws}")
    if doc:
        d = doc if a.full or len(doc) <= 400 else doc[:400] + f"... (+{len(doc)-400} chars, use --full)"
        print(f"doc: {d}")
    fmt = lambda dd: " ".join(f"{k}={v}" for k, v in dd.items()) or "-"
    print(f"out: {fmt(deg['out'])}   in: {fmt(deg['in'])}")


def traverse(g, a, incoming):
    """Depth-first tree of incoming (callers) or outgoing (callees) edges:
    each node is printed under the node it was reached from, so a chain reads
    top-to-bottom as an actual call path. Already-shown nodes get '^' and are
    not expanded again.

    For callers over call edges, each node's unresolved aliases (ext nodes
    like 'this.Method' / 'Class.Method') are folded in transparently --
    in this graph most call edges point at those, not at the method node."""
    root = g.resolve(a.ref)
    ek = g.ekind_id(a.kind)
    calls_ek = g.ekinds.index("calls") if "calls" in g.ekinds else None
    # Alias folding only makes sense on graphs whose calls are unresolved name
    # strings; on a resolved graph it would fabricate callers (see G.__init__).
    use_alias = (incoming and (ek is None or ek == calls_ek)
                 and g.heuristic_calls)
    fetch = in_edges if incoming else out_edges

    def fetch_rows(cur):
        rows = list(fetch(g, cur, ek))
        if not use_alias:
            return rows
        for al in g.aliases(cur):
            rows += in_edges(g, al, ek)
        merged = {}  # same caller via several aliases -> one row, summed n
        for other, k, conf, n in rows:
            if other in merged:
                o, k0, c0, n0 = merged[other]
                merged[other] = (o, k0, c0, n0 + n)
            else:
                merged[other] = (other, k, conf, n)
        return list(merged.values())

    visited = {root}
    rows = []  # (depth, id, n, conf, again)
    truncated = False

    def walk(cur, depth):
        nonlocal truncated
        if depth >= a.depth or truncated:
            return
        for other, _k, conf, n in sorted(fetch_rows(cur),
                                         key=lambda r: (-r[3], r[0])):
            if len(rows) >= a.limit:
                truncated = True
                return
            again = other in visited
            rows.append((depth + 1, other, n, conf, again))
            if not again:
                visited.add(other)
                walk(other, depth + 1)

    walk(root, 0)
    root_aliases = g.aliases(root) if use_alias else []
    word = "callers" if incoming else "callees"
    if a.json:
        print(json.dumps({
            "root": root, "direction": "in" if incoming else "out",
            "kind": a.kind, "truncated": truncated,
            **({"aliases": root_aliases} if root_aliases else {}),
            "items": [{**g.row_json(i), "depth": d, "n": n,
                       "conf": g.confs[conf],
                       **({"again": True} if again else {})}
                      for d, i, n, conf, again in rows]},
            separators=(",", ":")))
        return
    suffix = f" [kind={a.kind}]" if a.kind != "calls" else ""
    if root_aliases:
        suffix += f" [+{len(root_aliases)} alias targets]"
    print(f"{word} of {g.line(root)}{suffix}")
    for d, i, n, conf, again in rows:
        print("  " * d + g.line(i, g.edge_suffix(n, conf) + (" ^" if again else "")))
    if truncated:
        print(f"[truncated at {a.limit}; use --limit]")
    elif not rows:
        print("(none)")


def cmd_path(g, a):
    src, dst = g.resolve(a.src), g.resolve(a.dst)
    ek = g.ekind_id(a.kind)
    # external nodes (unresolved targets) are hubs that make most paths
    # meaningless; skip them as intermediates unless --via-ext
    ext_base = g.meta["nodes"] if not a.via_ext else g.n
    parent = {src: None}
    frontier = [src]
    found = src == dst
    depth = 0
    while frontier and not found and depth < a.max_depth:
        depth += 1
        nxt = []
        for cur in frontier:
            neigh = [r[0] for r in out_edges(g, cur, ek)]
            if a.undirected:
                neigh += [r[0] for r in in_edges(g, cur, ek)]
            for o in neigh:
                if o in parent:
                    continue
                if o >= ext_base and o != dst:
                    continue
                parent[o] = cur
                if o == dst:
                    found = True
                    break
                nxt.append(o)
            if found:
                break
        frontier = nxt
    if not found:
        hint = ("; try --undirected" if not a.undirected
                else "; try --via-ext" if not a.via_ext else "")
        msg = (f"no path {g.line(src)} -> {g.line(dst)} within depth {a.max_depth} "
               f"(kind={a.kind}{hint})")
        if a.json:
            print(json.dumps({"found": False, "items": []}, separators=(",", ":")))
        else:
            print(msg)
        sys.exit(2)
    chain = []
    cur = dst
    while cur is not None:
        chain.append(cur)
        cur = parent[cur]
    chain.reverse()
    if a.json:
        print(json.dumps({"found": True,
                          "items": [g.row_json(i) for i in chain]},
                         separators=(",", ":")))
        return
    print(g.line(chain[0]))
    for i in chain[1:]:
        print("-> " + g.line(i))
    print(f"({len(chain) - 1} hops)")


def cmd_sql(g, a):
    q = a.query.strip().rstrip(";")
    if not q.lower().startswith(("select", "with", "explain")):
        raise SystemExit("error: only read-only SELECT/WITH/EXPLAIN queries are allowed")
    try:
        cur = g.db.execute(q)
    except sqlite3.Error as e:
        raise SystemExit(f"sql error: {e}")
    cols = [d[0] for d in (cur.description or [])]
    rows = cur.fetchmany(a.limit)
    truncated = len(rows) == a.limit and cur.fetchone() is not None
    if a.json:
        print(json.dumps({"columns": cols, "rows": rows, "truncated": truncated},
                         default=str, separators=(",", ":")))
        return
    if cols:
        print("\t".join(cols))
    for r in rows:
        print("\t".join("" if v is None else str(v) for v in r))
    if truncated:
        print(f"[truncated at {a.limit}; refine the query or raise --limit]")


# ---------------------------------------------------------------------------
# wiring


def find_graph(opt):
    cands = []
    if opt:
        cands.append(opt)
    envp = os.environ.get("CODEGRAPH_GRAPH")
    if envp:
        cands.append(envp)
    here = os.path.dirname(os.path.abspath(__file__))
    cands += [os.path.join(here, "mygraph.json"), "mygraph.json"]
    for c in cands:
        if os.path.isfile(c):
            return os.path.abspath(c)
    raise SystemExit("error: graph JSON not found (use --graph <path> or CODEGRAPH_GRAPH)")


def ensure_index(graph, db_path, force=False):
    if not force and os.path.exists(db_path):
        try:
            db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            meta = {k: json.loads(v) for k, v in db.execute("SELECT k,v FROM meta")}
            db.close()
            st = os.stat(graph)
            if (meta.get("version") == INDEX_VERSION
                    and meta.get("source_size") == st.st_size
                    and meta.get("source_mtime") == int(st.st_mtime)):
                return
            err("index is stale (graph changed); rebuilding...")
        except sqlite3.Error:
            err("index unreadable; rebuilding...")
    else:
        if not force:
            err("no index yet; building one-time index (this can take a few minutes)...")
    build_index(graph, db_path)


EPILOG = """\
refs:    #123 / 123 (node number, shown in all output) | full id | unique substring
output:  "#id kind label  file:line"; x3 = edge seen 3 times;
         ~ = inferred (not certain); ^ = already shown above (cycle/repeat)
kinds:   fn=method/function cls=class mod=module ns=namespace ext=external;
         C# graphs also: ctor=constructor prop=property fld=field evt=event
         op=operator del=delegate ifc=interface str=struct enum enumv=enum-member
exit:    0 ok, 2 not-found/ambiguous (candidates on stderr)
recipes:
  find a node:               search <name> --kind fn        -> pick its #id
  where is it called from:   callers <id> --depth 3         (tree toward origins)
  what does it call:         callees <id> --depth 2         (tree toward targets)
  what contains it:          node <id>                      (container: line)
  members of class/module:   callees <id> --kind contains
  call chain between two:    path <a> <b>
  find a pattern:            find --kind class --attr serializable \\
                                  --member "constructor:public,params=0" \\
                                  --member "property:public,get,set"
  anything else:             sql "select ..."               (schema in README)
agent integration: run `codegraph mcp` as an MCP stdio server, or shell out per query
"""

# ---------------------------------------------------------------------------
# MCP stdio server (JSON-RPC 2.0, newline-delimited; no dependencies)

SQL_SCHEMA_DOC = (
    "Tables: nodes(id,name,label,lname,kind,file,line1,line2,cc,nbranch,params,"
    "ret,throws,doc,mods,synthetic), edges(src,dst,kind,conf,n), files(id,path), "
    "kinds(id,name), ekinds(id,name), confs(id,name), meta(k,v). Joins: "
    "nodes.kind->kinds.id, nodes.file->files.id, edges.src/dst->nodes.id, "
    "edges.kind->ekinds.id, edges.conf->confs.id. lname = lowercased unescaped "
    "node id (for matching); n = how many times the edge appeared in the source "
    "graph; mods = space-joined modifiers e.g. 'public get set' (NULL if the "
    "graph has none - match with mods LIKE '%set%'); synthetic = 1 for "
    "compiler-generated members.")

MCP_INSTRUCTIONS = (
    "Query tool for a large code graph (call/containment/inheritance edges). "
    "Nodes are referenced by short #id handles returned in every result - "
    "always prefer them over full node ids. To trace where something is "
    "called from use graph_callers with depth 2-3 (tree toward origins); to "
    "trace what it calls use graph_callees (tree toward targets); "
    "graph_path finds the chain between two nodes. graph_node shows details "
    "plus its containing class/module; kind=contains on callers/callees "
    "navigates structure (members / containers). 'n' or x-counts mean the "
    "edge appeared multiple times; conf 'inferred' means uncertain; 'again' "
    "or ^ marks a node already shown (cycle). graph_sql accepts read-only "
    "SELECT for anything the other tools don't cover.")

_REF_DESC = "node reference: #id (preferred), full node id, or unique substring"

# (tool name, cli command, description, [(positional, desc)], [(option, type, desc)])
MCP_TOOLS = [
    ("graph_stats", "stats",
     "Overview of the code graph: node/edge counts by kind, files, dependencies.",
     [], []),
    ("graph_search", "search",
     "Find nodes by case-insensitive substring of their id/name. Returns short "
     "#id handles used by every other tool.",
     [("text", "substring to search for")],
     [("kind", str, "node kind filter, e.g. method/class/module/external"),
      ("file", str, "only nodes whose file path contains this"),
      ("limit", int, "max results (default 20)"),
      ("offset", int, "pagination offset")]),
    ("graph_find", "find",
     "Find nodes matching a CONJUNCTION of structural patterns (all conditions "
     "must hold). Use for code-review / security questions like 'classes that "
     "are [Serializable] with a public parameterless constructor and public "
     "read/write properties'. member spec = 'kind[:mod,mod,params=0|+]', e.g. "
     "'constructor:public,params=0' or 'property:public,get,set'. Best on a "
     "resolved graph (csgraph / cecil).",
     [],
     [("kind", str, "node kind (class/method/property/...)"),
      ("name", str, "node id/name contains this substring"),
      ("file", str, "defined in a file whose path contains this"),
      ("mods", str, "comma-separated modifiers the node must have"),
      ("attr", list, "has an attribute whose name contains this (array)"),
      ("implements", list, "implements an interface matching this (array)"),
      ("inherits", list, "inherits a base matching this (array)"),
      ("uses", list, "references a type matching this in its signature "
                     "(type_uses; array)"),
      ("overrides", list, "overrides a member matching this (array)"),
      ("calls", list, "has an outgoing call to a target matching this (array)"),
      ("member", list, "contains a matching member; spec 'kind[:mod,mod,"
                       "params=0|+,type=substr,calls=substr,uses=substr,"
                       "reaches=substr]' (array). e.g. 'method:calls=invoke' "
                       "(ObjectDataProvider shape), 'field:type=DataSet', "
                       "'constructor:reaches=binaryformatter.deserialize' "
                       "(bridge gadget)"),
      ("reaches", list, "can reach a target matching this via calls within "
                        "reach_depth hops - transitive; for source->sink and "
                        "multi-hop bridge gadgets, e.g. a ctor that reaches "
                        "binaryformatter.deserialize (array)"),
      ("reached_by", list, "is reachable FROM a source matching this via calls "
                           "(reverse reachability; array)"),
      ("reach_depth", int, "max hops for reaches/reached_by (default 4)"),
      ("limit", int, "max results (default 30)"),
      ("offset", int, "pagination offset")]),
    ("graph_node", "node",
     "Full details for one node: full id, file:lines, containing class/module "
     "chain, complexity, params, return type, throws, docstring, edge counts "
     "by kind.",
     [("ref", _REF_DESC)],
     [("full", bool, "do not truncate the docstring")]),
    ("graph_callers", "callers",
     "Trace incoming edges toward origins (tree). With kind=calls: who calls "
     "it. kind=inherits: subclasses (who extends it). kind=implements: "
     "implementers. kind=type_uses: who references the type in a signature "
     "(field/property/param) - i.e. who USES it. kind=overrides: who overrides "
     "it. kind=contains: its container. Key for gadget/sink analysis.",
     [("ref", _REF_DESC)],
     [("depth", int, "tree depth (default 1; use 2-5 to trace transitively)"),
      ("kind", str, "edge kind: calls (default), inherits, implements, "
                    "type_uses, overrides, contains, any"),
      ("limit", int, "max rows (default 30)")]),
    ("graph_callees", "callees",
     "Trace outgoing edges toward targets (tree). With kind=calls: what it "
     "calls (toward sinks). kind=contains: its members (methods/props of a "
     "class). kind=inherits/implements: its base types/interfaces.",
     [("ref", _REF_DESC)],
     [("depth", int, "tree depth (default 1)"),
      ("kind", str, "edge kind: calls (default), contains, inherits, "
                    "implements, type_uses, overrides, any"),
      ("limit", int, "max rows (default 30)")]),
    ("graph_path", "path", "Shortest path between two nodes over graph edges.",
     [("src", _REF_DESC), ("dst", _REF_DESC)],
     [("kind", str, "edge kind to traverse (default calls)"),
      ("undirected", bool, "also traverse edges backwards"),
      ("via_ext", bool, "allow paths through external (unresolved) hub nodes"),
      ("max_depth", int, "BFS depth limit (default 15)")]),
    ("graph_sql", "sql",
     "Run a read-only SQL SELECT against the index for anything the other "
     "tools don't cover. " + SQL_SCHEMA_DOC,
     [("query", "a single SELECT/WITH statement")],
     [("limit", int, "max rows (default 50)")]),
]


def _mcp_tool_defs():
    defs = []
    for name, _cmd, desc, pos, opts in MCP_TOOLS:
        props = {p: {"type": "string", "description": d} for p, d in pos}
        for o, typ, d in opts:
            if typ is list:  # array-of-string option (repeatable CLI flag)
                props[o] = {"type": "array", "items": {"type": "string"},
                            "description": d}
            else:
                t = "integer" if typ is int else "boolean" if typ is bool else "string"
                props[o] = {"type": t, "description": d}
        defs.append({"name": name, "description": desc,
                     "inputSchema": {"type": "object", "properties": props,
                                     "required": [p for p, _ in pos]}})
    return defs


def _mcp_call_tool(name, arguments, graph):
    """Run one tool by reusing the CLI entry point with --json. Returns
    (result text, isError)."""
    spec = next((t for t in MCP_TOOLS if t[0] == name), None)
    if spec is None:
        return f"unknown tool: {name}", True
    _, cmd, _, pos, opts = spec
    argv = [cmd]
    for p, _ in pos:
        if p not in arguments:
            return f"missing required argument: {p}", True
        argv.append(str(arguments[p]))
    for o, typ, _ in opts:
        v = arguments.get(o)
        if v is None:
            continue
        flag = "--" + o.replace("_", "-")
        if typ is bool:
            if v:
                argv.append(flag)
        elif typ is list:  # emit the flag once per item
            for item in (v if isinstance(v, list) else [v]):
                argv += [flag, str(item)]
        else:
            argv += [flag, str(v)]
    argv += ["--graph", graph, "--json"]
    out, errbuf = io.StringIO(), io.StringIO()
    code = 0
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(errbuf):
            main(argv)
    except SystemExit as e:
        if isinstance(e.code, int):
            code = e.code or 0
        else:
            code = 1
            if e.code:
                errbuf.write(str(e.code))
    except Exception as e:  # surface tool failures to the client, don't die
        return f"error: {e}", True
    text = out.getvalue().strip()
    if code:
        emsg = errbuf.getvalue().strip()
        text = (text + ("\n" if text and emsg else "") + emsg) or f"exit code {code}"
    # exit 2 = not-found/ambiguous: useful feedback for the model, not a failure
    return text, code not in (0, 2)


def run_mcp(graph):
    def send(obj):
        sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
        sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        mid = msg.get("id")
        method = msg.get("method")
        if method == "initialize":
            pv = (msg.get("params") or {}).get("protocolVersion") or "2024-11-05"
            send({"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": pv,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "codegraph", "version": "1.0.0"},
                "instructions": MCP_INSTRUCTIONS}})
        elif method == "ping":
            send({"jsonrpc": "2.0", "id": mid, "result": {}})
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": mid,
                  "result": {"tools": _mcp_tool_defs()}})
        elif method == "tools/call":
            p = msg.get("params") or {}
            text, is_err = _mcp_call_tool(p.get("name"), p.get("arguments") or {},
                                          graph)
            send({"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": text}],
                "isError": is_err}})
        elif mid is not None:  # unknown request (notifications are just ignored)
            send({"jsonrpc": "2.0", "id": mid, "error": {
                "code": -32601, "message": f"method not found: {method}"}})
    return 0


def main(argv=None):
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        with contextlib.suppress(Exception):
            reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(
        prog="codegraph",
        description="query a large code-graph JSON via a compact SQLite index "
                    "(token-efficient output for AI agents)",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--graph", help="path to graph JSON (default: mygraph.json "
                                        "next to this script, or $CODEGRAPH_GRAPH)")
    common.add_argument("--json", action="store_true", help="machine-readable output")
    sub = p.add_subparsers(dest="cmd", metavar="command")

    sp = sub.add_parser("index", parents=[common], help="(re)build the index")
    sp.add_argument("--force", action="store_true")

    sub.add_parser("stats", parents=[common], help="graph overview")

    sp = sub.add_parser("search", parents=[common],
                        help="find nodes by substring (case-insensitive)")
    sp.add_argument("text")
    sp.add_argument("--kind")
    sp.add_argument("--file", help="only nodes in files whose path contains this")
    sp.add_argument("--limit", "-n", type=int, default=20)
    sp.add_argument("--offset", type=int, default=0)

    sp = sub.add_parser("node", parents=[common], help="full details for one node")
    sp.add_argument("ref")
    sp.add_argument("--full", action="store_true", help="don't truncate docstring")

    sp = sub.add_parser(
        "find", parents=[common],
        help="find nodes matching a conjunction of patterns",
        description="Find nodes where ALL given predicates hold. Repeatable "
                    "flags add more conditions.",
        epilog="example: find --kind class --attr serializable "
               "--member \"constructor:public,params=0\" "
               "--member \"property:public,get,set\"",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sp.add_argument("--kind", help="node kind (class/method/property/...)")
    sp.add_argument("--name", help="node id/name contains this substring")
    sp.add_argument("--file", help="defined in a file whose path contains this")
    sp.add_argument("--mods", help="comma-separated modifiers the node must have "
                                   "(e.g. public,abstract)")
    sp.add_argument("--attr", action="append", default=[], metavar="SUBSTR",
                    help="has an attribute whose name contains SUBSTR (repeatable)")
    sp.add_argument("--implements", action="append", default=[], metavar="SUBSTR",
                    help="implements an interface matching SUBSTR (repeatable)")
    sp.add_argument("--inherits", action="append", default=[], metavar="SUBSTR",
                    help="inherits a base matching SUBSTR (repeatable)")
    sp.add_argument("--uses", action="append", default=[], metavar="SUBSTR",
                    help="references a type matching SUBSTR in its signature "
                         "(type_uses; repeatable)")
    sp.add_argument("--overrides", action="append", default=[], metavar="SUBSTR",
                    help="overrides a member matching SUBSTR (repeatable)")
    sp.add_argument("--calls", action="append", default=[], metavar="SUBSTR",
                    help="has an outgoing call to a target matching SUBSTR (repeatable)")
    sp.add_argument("--member", action="append", default=[], metavar="SPEC",
                    help="contains a member: 'kind[:mod,mod,params=0|+,"
                         "type=substr,calls=substr,uses=substr,reaches=substr]' "
                         "(repeatable), e.g. 'property:public,get,set', "
                         "'field:type=DataSet', 'method:calls=invoke', "
                         "'constructor:reaches=binaryformatter.deserialize'")
    sp.add_argument("--reaches", action="append", default=[], metavar="SUBSTR",
                    help="can reach a target matching SUBSTR via calls within "
                         "--reach-depth hops (transitive; for source->sink & "
                         "multi-hop gadgets). Repeatable.")
    sp.add_argument("--reached-by", action="append", default=[], metavar="SUBSTR",
                    help="is reachable FROM a source matching SUBSTR via calls "
                         "(reverse reachability). Repeatable.")
    sp.add_argument("--reach-depth", type=int, default=4,
                    help="max hops for --reaches/--reached-by (default 4)")
    sp.add_argument("--limit", "-n", type=int, default=30)
    sp.add_argument("--offset", type=int, default=0)

    for name, hlp in (("callers", "tree of who calls it (toward origins)"),
                      ("callees", "tree of what it calls (toward targets)")):
        sp = sub.add_parser(name, parents=[common], help=hlp)
        sp.add_argument("ref")
        sp.add_argument("--depth", type=int, default=1)
        sp.add_argument("--kind", default="calls",
                        help="edge kind (default calls; contains/inherits/"
                             "implements/any)")
        sp.add_argument("--limit", "-n", type=int, default=30)

    sp = sub.add_parser("path", parents=[common], help="shortest path between nodes")
    sp.add_argument("src")
    sp.add_argument("dst")
    sp.add_argument("--kind", default="calls")
    sp.add_argument("--undirected", action="store_true")
    sp.add_argument("--via-ext", action="store_true",
                    help="allow paths through external (unresolved) hub nodes")
    sp.add_argument("--max-depth", type=int, default=15)

    sp = sub.add_parser("sql", parents=[common],
                        help="read-only SQL SELECT against the index")
    sp.add_argument("query")
    sp.add_argument("--limit", "-n", type=int, default=50)

    sub.add_parser("mcp", parents=[common],
                   help="run as an MCP stdio server for AI agents")

    a = p.parse_args(argv)
    if not a.cmd:
        p.print_help()
        return 0

    graph = find_graph(a.graph)
    db_path = graph + ".idx.sqlite"
    if a.cmd == "index":
        build_index(graph, db_path)
        return 0
    ensure_index(graph, db_path)
    if a.cmd == "mcp":
        return run_mcp(graph)
    g = G(db_path)
    try:
        {
            "stats": cmd_stats,
            "search": cmd_search,
            "find": cmd_find,
            "node": cmd_node,
            "callers": lambda g, a: traverse(g, a, True),
            "callees": lambda g, a: traverse(g, a, False),
            "path": cmd_path,
            "sql": cmd_sql,
        }[a.cmd](g, a)
    finally:
        g.db.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(0)
