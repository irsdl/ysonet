# Copyright (c) 2026 Soroush Dalili
# SPDX-License-Identifier: MIT

"""End-to-end tests for every CLI command against the tiny fixture graph.

Fixture topology (see conftest):
  #0 Mod (module) -contains-> #1 Cls (class) -contains-> #2 Run, #3 Helper, #4 Lonely
  #2 Run -calls(x2,inferred)-> #3 Helper, -calls(inferred)-> #5 this.Ext.Call (ext)
  #3 Helper -calls(certain)-> #4 Lonely -calls(certain)-> #2 Run   (cycle)
  #3 Helper -calls(inferred)-> #7 this.Run (ext alias of #2)
  #1 Cls -inherits-> #6 System.Object (ext)
"""

import json
import os
import time

import conftest
import codegraph
from conftest import ID, RUN, run_cli, write_graph


def j(out):
    return json.loads(out)


# --- stats -------------------------------------------------------------------

def test_stats_text(cli):
    out, _, code = cli("stats")
    assert code == 0
    assert "nodes: 5 (+3 external targets)" in out
    assert "edges: 11 raw -> 10 unique" in out
    assert "calls: 6 (5 unique)" in out
    assert "contains: 4 (4 unique)" in out
    assert "inherits: 1 (1 unique)" in out


def test_stats_json(cli):
    out, _, _ = cli("stats", "--json")
    m = j(out)
    assert m["nodes"] == 5 and m["externals"] == 3
    assert m["raw_edges"] == 11 and m["unique_edges"] == 10
    assert m["language"] == "polyglot"
    assert m["node_kinds"]["method"] == 3
    assert m["edge_kinds"]["calls"] == {"unique": 5, "raw": 6}


# --- search ------------------------------------------------------------------

def test_search_basic(cli):
    out, _, _ = cli("search", "cls.run", "--json")
    r = j(out)
    assert r["total"] == 1
    assert r["items"][0] == {"id": ID[RUN], "kind": "method", "label": "Cls.Run",
                             "file": "./src/mod.cs", "line": 10}


def test_search_unescaped_dots(cli):
    # user types real dots; ids store escaped '\.' -- search must still match
    out, _, _ = cli("search", "app.dll", "--json")
    assert j(out)["total"] == 5


def test_search_kind_filter(cli):
    out, _, _ = cli("search", "app", "--kind", "cls", "--json")
    assert [i["id"] for i in j(out)["items"]] == [1]
    out, _, _ = cli("search", "app", "--kind", "method", "--json")
    assert j(out)["total"] == 3


def test_search_file_filter(cli):
    out, _, _ = cli("search", "app", "--file", "other.cs", "--json")
    assert [i["id"] for i in j(out)["items"]] == [4]


def test_search_pagination(cli):
    out, _, _ = cli("search", "app", "-n", "2")
    assert "[2/5 shown; next: --offset 2]" in out
    out, _, _ = cli("search", "app", "-n", "2", "--offset", "4", "--json")
    r = j(out)
    assert r["total"] == 5 and len(r["items"]) == 1


def test_search_no_match(cli):
    out, _, _ = cli("search", "zzznope")
    assert "no matches" in out


# --- node + ref resolution ---------------------------------------------------

def test_node_details_json(cli):
    out, _, _ = cli("node", "#2", "--json")
    n = j(out)
    assert n["name"] == RUN and n["label"] == "Cls.Run"
    assert n["params"] == "int x; y"          # dict + str params
    assert n["returns"] == "void"             # dict-shaped return_type
    assert n["throws"] == "E1, E2"
    assert n["cc"] == 5 and n["branches"] == 3
    assert n["lines"] == [10, 40]
    assert [c["id"] for c in n["container"]] == [1, 0]
    assert n["edges"] == {"out": {"calls": 3},
                          "in": {"contains": 1, "calls": 1}}


def test_node_container_chain_text(cli):
    out, _, _ = cli("node", "2")
    assert "container: #1 cls Cls < #0 mod Mod" in out
    # the top-level module has no container line
    out, _, _ = cli("node", "0")
    assert "container:" not in out


def test_node_doc_truncation(cli):
    out, _, _ = cli("node", "2")
    assert "(+50 chars, use --full)" in out
    out, _, _ = cli("node", "2", "--full")
    assert "D" * 450 in out


def test_resolve_by_full_id_and_label(cli):
    out, _, _ = cli("node", RUN, "--json")
    assert j(out)["id"] == 2
    # exact label match wins even when the substring would be ambiguous
    out, _, _ = cli("node", "cls", "--json")
    assert j(out)["id"] == 1


def test_resolve_ambiguous(cli):
    out, err, code = cli("node", "app")
    assert code == 2
    assert "ambiguous" in err and "#0" in err


def test_resolve_no_match(cli):
    _, err, code = cli("node", "zzznope")
    assert code == 2 and "no node matches" in err


def test_resolve_out_of_range(cli):
    _, err, code = cli("node", "#999")
    assert code != 0


# --- callers / callees (tracing) -------------------------------------------

def test_callers_single_level(cli):
    out, _, _ = cli("callers", "3", "--json")
    r = j(out)
    assert [i["id"] for i in r["items"]] == [2]
    assert r["items"][0]["n"] == 2 and r["items"][0]["conf"] == "inferred"


def test_callers_includes_unresolved_aliases(cli):
    # Helper calls 'this.Run' (ext #7), not node #2 directly -- callers of
    # Run must still surface Helper, with the alias noted
    out, _, _ = cli("callers", "2", "--json")
    r = j(out)
    assert r["aliases"] == [7]
    assert {i["id"] for i in r["items"]} == {3, 4}
    out, _, _ = cli("callers", "2")
    assert "[+1 alias targets]" in out and "#3 " in out


def test_resolved_graph_disables_alias_folding(tmp_path):
    # A graph whose maker marks calls as resolved (summary.resolved_calls=1)
    # must NOT fold name-based aliases - doing so on the unresolved fixture is
    # correct, but on a resolved graph it would fabricate callers. Here Helper
    # calls the alias 'this.Run' (#7), not node #2; with folding off, the only
    # caller of #2 is the real Lonely->Run edge (#4).
    data = conftest.tiny_graph()
    data["summary"]["resolved_calls"] = 1
    p = tmp_path / "resolved.json"
    conftest.write_graph(p, data)
    codegraph.build_index(str(p), str(p) + ".idx.sqlite", quiet=True)
    out, _, _ = run_cli(str(p), "callers", "2", "--json")
    r = j(out)
    assert "aliases" not in r
    assert {i["id"] for i in r["items"]} == {4}
    out, _, _ = run_cli(str(p), "callers", "2")
    assert "alias targets" not in out


def test_callers_trace_to_origin(cli):
    # full upstream trace of Run: Helper (via this.Run alias) and Lonely,
    # each expanded under its own chain; revisits marked, not expanded
    out, _, _ = cli("callers", "2", "--depth", "3", "--json")
    items = j(out)["items"]
    assert [(i["id"], i["depth"], i.get("again", False)) for i in items] == [
        (3, 1, False), (2, 2, True), (4, 1, False), (3, 2, True)]


def test_callees_tree_structure(cli):
    out, _, _ = cli("callees", "2", "--depth", "3", "--json")
    items = j(out)["items"]
    # DFS: Helper subtree (Lonely -> Run cycle, then its this.Run target)
    # fully expanded before the ext sibling
    assert [(i["id"], i["depth"], i.get("again", False)) for i in items] == [
        (3, 1, False), (4, 2, False), (2, 3, True), (7, 2, False),
        (5, 1, False)]


def test_callees_text_tree(cli):
    out, _, _ = cli("callees", "2", "--depth", "3")
    lines = out.splitlines()
    assert lines[0].startswith("callees of #2 fn Cls.Run")
    assert lines[1].startswith("  #3 ") and " x2 ~" in lines[1]
    assert lines[2].startswith("    #4 ")        # nested under its caller
    assert lines[3].startswith("      #2 ") and lines[3].endswith("^")  # cycle
    assert lines[4].startswith("    #7 ")        # Helper's unresolved target
    assert lines[5].startswith("  #5 ")


def test_traverse_limit(cli):
    out, _, _ = cli("callees", "2", "-n", "1")
    assert "[truncated at 1" in out


def test_members_via_contains(cli):
    # members of a class = callees --kind contains
    out, _, _ = cli("callees", "1", "--kind", "contains", "--json")
    assert [i["id"] for i in j(out)["items"]] == [2, 3, 4]


def test_container_via_contains(cli):
    out, _, _ = cli("callers", "2", "--kind", "contains", "--json")
    assert [i["id"] for i in j(out)["items"]] == [1]


def test_traverse_none(cli):
    out, _, _ = cli("callees", "4", "--kind", "inherits")
    assert "(none)" in out


# --- path ----------------------------------------------------------------

def test_path_directed(cli):
    out, _, _ = cli("path", "2", "4", "--json")
    r = j(out)
    assert r["found"] and [i["id"] for i in r["items"]] == [2, 3, 4]


def test_path_uses_cycle_edge(cli):
    out, _, _ = cli("path", "4", "3", "--json")
    assert [i["id"] for i in j(out)["items"]] == [4, 2, 3]


def test_path_not_found_and_hint(cli):
    out, _, code = cli("path", "0", "4")
    assert code == 2 and "try --undirected" in out


def test_path_undirected(cli):
    out, _, _ = cli("path", "4", "0", "--kind", "contains", "--undirected",
                    "--json")
    assert [i["id"] for i in j(out)["items"]] == [4, 1, 0]


def test_path_ext_destination_allowed(cli):
    out, _, _ = cli("path", "2", "5", "--json")
    assert [i["id"] for i in j(out)["items"]] == [2, 5]


def test_path_other_edge_kinds(cli):
    out, _, _ = cli("path", "0", "2", "--kind", "contains", "--json")
    assert [i["id"] for i in j(out)["items"]] == [0, 1, 2]
    out, _, _ = cli("path", "1", "6", "--kind", "inherits", "--json")
    assert [i["id"] for i in j(out)["items"]] == [1, 6]


# --- sql -----------------------------------------------------------------

def test_sql_select(cli):
    out, _, _ = cli("sql", "select count(*) as c from nodes", "--json")
    r = j(out)
    assert r["columns"] == ["c"] and r["rows"][0][0] == 8


def test_sql_join(cli):
    out, _, _ = cli("sql",
                    "select k.name, count(*) c from nodes n "
                    "join kinds k on k.id=n.kind group by 1 order by 2 desc")
    assert "method\t3" in out


def test_sql_rejects_writes(cli):
    _, err, code = cli("sql", "delete from nodes")
    assert code == 1 and "read-only" in err
    _, err, code = cli("sql", "update nodes set cc=0")
    assert code == 1


def test_sql_truncation(cli):
    out, _, _ = cli("sql", "select id from nodes", "-n", "3")
    assert "[truncated at 3" in out


# --- index lifecycle -------------------------------------------------------

def test_auto_build_and_stale_rebuild(tmp_path):
    p = tmp_path / "g.json"
    write_graph(p)
    out, err, code = run_cli(str(p), "stats")
    assert code == 0 and "building one-time index" in err
    # unchanged -> no rebuild
    _, err, _ = run_cli(str(p), "stats")
    assert "building" not in err and "stale" not in err
    # touched -> rebuild
    later = time.time() + 30
    os.utime(p, (later, later))
    out, err, code = run_cli(str(p), "stats")
    assert code == 0 and "stale" in err
    assert "nodes: 5" in out


def test_dedup_counts_in_index(graph_file):
    g = codegraph.G(graph_file + ".idx.sqlite")
    try:
        rows = g.db.execute(
            "SELECT n FROM edges WHERE src=? AND dst=?",
            (ID[RUN], ID[conftest.HELPER])).fetchall()
        assert rows == [(2,)]  # two raw edges -> one row with n=2
    finally:
        g.db.close()
