# Copyright (c) 2026 Soroush Dalili
# SPDX-License-Identifier: MIT

"""MCP stdio server round-trip: speaks real JSON-RPC to a subprocess."""

import json
import os
import subprocess
import sys

CODEGRAPH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "codegraph.py")


def rpc(id_, method, **params):
    m = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params:
        m["params"] = params
    return m


def test_mcp_roundtrip(graph_file):
    msgs = [
        rpc(1, "initialize", protocolVersion="2024-11-05", capabilities={},
            clientInfo={"name": "test", "version": "0"}),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        rpc(2, "tools/list"),
        rpc(3, "tools/call", name="graph_stats", arguments={}),
        rpc(4, "tools/call", name="graph_search", arguments={"text": "cls.run"}),
        rpc(5, "tools/call", name="graph_callees",
            arguments={"ref": "#2", "depth": 2}),
        rpc(6, "tools/call", name="graph_sql",
            arguments={"query": "select count(*) as c from nodes"}),
        rpc(7, "tools/call", name="graph_node", arguments={"ref": "zzz_nope"}),
        rpc(8, "tools/call", name="graph_node", arguments={}),  # missing arg
        rpc(9, "tools/call", name="no_such_tool", arguments={}),
        rpc(10, "nonexistent/method"),
        # array argument (calls) must round-trip into repeated CLI flags
        rpc(11, "tools/call", name="graph_find",
            arguments={"kind": "method", "calls": ["helper"]}),
    ]
    inp = "".join(json.dumps(m) + "\n" for m in msgs)
    r = subprocess.run(
        [sys.executable, CODEGRAPH, "mcp", "--graph", graph_file],
        input=inp, capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert r.returncode == 0, r.stderr
    resp = {}
    for line in r.stdout.splitlines():
        if line.strip():
            m = json.loads(line)
            if "id" in m:
                resp[m["id"]] = m

    init = resp[1]["result"]
    assert init["serverInfo"]["name"] == "codegraph"
    assert init["protocolVersion"] == "2024-11-05"
    assert init["capabilities"] == {"tools": {}}

    tools = {t["name"]: t for t in resp[2]["result"]["tools"]}
    # exactly the focused tool set -- tool schemas cost agent-context tokens
    assert set(tools) == {"graph_stats", "graph_search", "graph_find",
                          "graph_node", "graph_callers", "graph_callees",
                          "graph_path", "graph_sql"}
    assert tools["graph_search"]["inputSchema"]["required"] == ["text"]
    assert tools["graph_path"]["inputSchema"]["properties"]["undirected"][
        "type"] == "boolean"
    # graph_find's repeatable predicates are typed as string arrays
    assert tools["graph_find"]["inputSchema"]["properties"]["member"][
        "type"] == "array"

    def content(i):
        return resp[i]["result"]["content"][0]["text"]

    stats = json.loads(content(3))
    assert stats["nodes"] == 5

    search = json.loads(content(4))
    assert search["total"] == 1 and search["items"][0]["label"] == "Cls.Run"

    callees = json.loads(content(5))
    assert {i["id"] for i in callees["items"]} == {3, 4, 5, 7}

    sqlres = json.loads(content(6))
    assert sqlres["rows"][0][0] == 8

    # not-found is useful feedback, not a tool error
    nf = resp[7]["result"]
    assert nf["isError"] is False and "no node matches" in nf["content"][0]["text"]

    missing = resp[8]["result"]
    assert missing["isError"] is True and "missing required" in missing["content"][0]["text"]

    unknown = resp[9]["result"]
    assert unknown["isError"] is True and "unknown tool" in unknown["content"][0]["text"]

    assert resp[10]["error"]["code"] == -32601

    # graph_find with an array predicate: methods calling something matching
    # "helper" -> Cls.Run (#2) calls Helper
    find = resp[11]["result"]
    assert find["isError"] is False
    assert 2 in {i["id"] for i in json.loads(find["content"][0]["text"])["items"]}
