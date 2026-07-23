# Copyright (c) 2026 Soroush Dalili
# SPDX-License-Identifier: MIT

"""Shared fixtures: a tiny synthetic graph that mirrors the real file's quirks
(UTF-16 BOM, escaped dots in ids, dict-shaped fields, duplicate edges,
unresolved external targets)."""

import contextlib
import io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import codegraph  # noqa: E402

# actual ids contain backslash-escaped dots, like the real graph
MOD = "app\\.dll.App.Mod"
CLS = MOD + ":Cls"
RUN = MOD + ":Cls.Run"
HELPER = MOD + ":Cls.Helper"
LONELY = MOD + ":Cls.Lonely"
EXT_CALL = "this.Ext.Call"
EXT_BASE = "System.Object"
THIS_RUN = "this.Run"  # unresolved alias for RUN, as the real graph records calls

# expected node numbering: nodes in insertion order, externals appended
# during the edge pass in edge order
ID = {MOD: 0, CLS: 1, RUN: 2, HELPER: 3, LONELY: 4, EXT_CALL: 5, EXT_BASE: 6,
      THIS_RUN: 7}


def _node(nid, kind, file, l1, l2, params=None, ret=None, exc=None, cc=None,
          branches=None, doc=None):
    return {
        "id": nid, "name": nid, "kind": kind,
        "location": {"file_path": file, "start_line": l1, "end_line": l2,
                     "start_col": 0, "end_col": 0},
        "parameters": params or [],
        "return_type": ret,
        "exception_types": exc or [],
        "cyclomatic_complexity": cc,
        "branches": branches or [],
        "docstring": doc,
    }


def _edge(s, t, k, c):
    return {"source": s, "target": t, "kind": k, "confidence": c}


def tiny_graph():
    nodes = {
        MOD: _node(MOD, "module", "./src/mod.cs", 1, 100),
        CLS: _node(CLS, "class", "./src/mod.cs", 5, 90),
        # dict-shaped return_type and mixed params, like the real polyglot graph
        RUN: _node(RUN, "method", "./src/mod.cs", 10, 40,
                   params=[{"name": "x", "type": "int"}, "y"],
                   ret={"name": "void"}, exc=["E1", "E2"], cc=5,
                   branches=[1, 2, 3], doc="D" * 450),
        HELPER: _node(HELPER, "method", "./src/mod.cs", 45, 60, cc=2),
        LONELY: _node(LONELY, "method", "./src/other.cs", 1, 5),
    }
    edges = [
        _edge(MOD, CLS, "contains", "certain"),
        _edge(CLS, RUN, "contains", "certain"),
        _edge(CLS, HELPER, "contains", "certain"),
        _edge(CLS, LONELY, "contains", "certain"),
        _edge(RUN, HELPER, "calls", "inferred"),
        _edge(RUN, HELPER, "calls", "inferred"),  # duplicate -> x2
        _edge(RUN, EXT_CALL, "calls", "inferred"),  # unresolved -> ext node
        _edge(HELPER, LONELY, "calls", "certain"),
        _edge(LONELY, RUN, "calls", "certain"),  # cycle Run->Helper->Lonely->Run
        _edge(CLS, EXT_BASE, "inherits", "certain"),
        # call recorded against the unresolved 'this.Run' string, not the node
        _edge(HELPER, THIS_RUN, "calls", "inferred"),
    ]
    return {
        "language": "polyglot",
        "root_path": "C:\\src",
        "summary": {"total_nodes": 5, "functions": 3, "classes": 1,
                    "call_edges": 6, "dependencies": ["System", "App"],
                    "entrypoints": 1},
        "nodes": nodes,
        "edges": edges,
        "subgraphs": {},
    }


def write_graph(path, data=None):
    text = json.dumps(data if data is not None else tiny_graph())
    path.write_bytes(b"\xff\xfe" + text.encode("utf-16-le"))


@pytest.fixture(scope="session")
def graph_file(tmp_path_factory):
    p = tmp_path_factory.mktemp("graph") / "tiny.json"
    write_graph(p)
    codegraph.build_index(str(p), str(p) + ".idx.sqlite", quiet=True)
    return str(p)


def run_cli(graph, *args):
    """Run a codegraph command in-process; returns (stdout, stderr, exit_code)."""
    out, errbuf = io.StringIO(), io.StringIO()
    code = 0
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(errbuf):
            codegraph.main(list(args) + ["--graph", graph])
    except SystemExit as e:
        if isinstance(e.code, int):
            code = e.code or 0
        else:
            code = 1
            errbuf.write(str(e.code) + "\n")
    return out.getvalue(), errbuf.getvalue(), code


@pytest.fixture
def cli(graph_file):
    def run(*args):
        return run_cli(graph_file, *args)
    return run
