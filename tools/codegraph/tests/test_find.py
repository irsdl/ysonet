# Copyright (c) 2026 Soroush Dalili
# SPDX-License-Identifier: MIT

"""Tests for the `find` pattern command, against a small resolved-style graph
(attributes, modifiers, members) like the csharp_roslyn / csharp_cecil output.

Topology:
  Dto (class, public)  [Serializable], implements ISerializable
    - ctor Dto()                 constructor public, parameterless
    - prop Name                  property public get set
    - prop Id                    property public get      (read-only)
  Plain (class, public)          no [Serializable]
    - ctor Plain(int x)          constructor public, HAS params
    - prop Val                   property public get set
  Helper (class, internal)
    - method Load()              calls Foo.Deserialize (ext)
"""

import json

import pytest

import codegraph
from conftest import run_cli


def _n(nid, kind, mods=None, params=None, ret=None):
    d = {"id": nid, "name": nid, "kind": kind}
    if mods is not None:
        d["modifiers"] = mods
    if params is not None:
        d["parameters"] = params
    if ret is not None:
        d["return_type"] = ret
    return d


def build(path):
    nodes = {
        "T:App.Dto": _n("T:App.Dto", "class", ["public"]),
        "M:App.Dto.#ctor": _n("App.Dto:Dto.#ctor", "constructor", ["public"]),
        "P:App.Dto.Name": _n("App.Dto:Dto.Name", "property", ["public", "get", "set"]),
        "P:App.Dto.Id": _n("App.Dto:Dto.Id", "property", ["public", "get"]),
        "T:App.Plain": _n("T:App.Plain", "class", ["public"]),
        "M:App.Plain.#ctor": _n("App.Plain:Plain.#ctor", "constructor", ["public"],
                                params=[{"name": "x", "type": "int"}]),
        "P:App.Plain.Val": _n("App.Plain:Plain.Val", "property", ["public", "get", "set"]),
        "T:App.Helper": _n("T:App.Helper", "class", ["internal"]),
        "M:App.Helper.Load": _n("App.Helper:Helper.Load", "method", ["public"]),
        # gadget scenario: SubDto extends the Dto gadget; Consumer has a field
        # of type Dto (uses it) and overrides Dto.Name.
        "T:App.SubDto": _n("T:App.SubDto", "class", ["public"]),
        "T:App.Consumer": _n("T:App.Consumer", "class", ["public"]),
        "F:App.Consumer.gadget": _n("App.Consumer:Consumer.gadget", "field",
                                    ["private"], ret="Dto"),
        "P:App.Consumer.Name": _n("App.Consumer:Consumer.Name", "property",
                                  ["public", "get", "set", "override"]),
        # ObjectDataProvider-shaped: a class with a method that calls *invoke*,
        # a public settable property, and a public parameterless ctor.
        "T:App.Provider": _n("T:App.Provider", "class", ["public"]),
        "M:App.Provider.#ctor": _n("App.Provider:Provider.#ctor", "constructor", ["public"]),
        "M:App.Provider.Run": _n("App.Provider:Provider.Run", "method", ["public"]),
        "P:App.Provider.MethodName": _n("App.Provider:Provider.MethodName", "property",
                                       ["public", "get", "set"]),
    }
    edges = [
        {"source": "T:App.Dto", "target": "T:System.SerializableAttribute",
         "kind": "has_attribute", "confidence": "certain"},
        {"source": "T:App.Dto",
         "target": "T:System.Runtime.Serialization.ISerializable",
         "kind": "implements", "confidence": "certain"},
        {"source": "T:App.Dto", "target": "M:App.Dto.#ctor", "kind": "contains",
         "confidence": "certain"},
        {"source": "T:App.Dto", "target": "P:App.Dto.Name", "kind": "contains",
         "confidence": "certain"},
        {"source": "T:App.Dto", "target": "P:App.Dto.Id", "kind": "contains",
         "confidence": "certain"},
        {"source": "T:App.Plain", "target": "M:App.Plain.#ctor", "kind": "contains",
         "confidence": "certain"},
        {"source": "T:App.Plain", "target": "P:App.Plain.Val", "kind": "contains",
         "confidence": "certain"},
        {"source": "T:App.Helper", "target": "M:App.Helper.Load", "kind": "contains",
         "confidence": "certain"},
        {"source": "M:App.Helper.Load", "target": "Foo.Deserialize",
         "kind": "calls", "confidence": "certain"},
        # SubDto inherits Dto
        {"source": "T:App.SubDto", "target": "T:App.Dto", "kind": "inherits",
         "confidence": "certain"},
        {"source": "T:App.Consumer", "target": "F:App.Consumer.gadget",
         "kind": "contains", "confidence": "certain"},
        {"source": "T:App.Consumer", "target": "P:App.Consumer.Name",
         "kind": "contains", "confidence": "certain"},
        # Consumer.gadget field is of type Dto (uses the gadget)
        {"source": "F:App.Consumer.gadget", "target": "T:App.Dto",
         "kind": "type_uses", "confidence": "certain"},
        # Consumer.Name overrides Dto.Name
        {"source": "P:App.Consumer.Name", "target": "P:App.Dto.Name",
         "kind": "overrides", "confidence": "certain"},
        # Provider: ctor + invoking method + settable property
        {"source": "T:App.Provider", "target": "M:App.Provider.#ctor",
         "kind": "contains", "confidence": "certain"},
        {"source": "T:App.Provider", "target": "M:App.Provider.Run",
         "kind": "contains", "confidence": "certain"},
        {"source": "T:App.Provider", "target": "P:App.Provider.MethodName",
         "kind": "contains", "confidence": "certain"},
        {"source": "M:App.Provider.Run", "target": "System.Reflection.MethodBase.Invoke",
         "kind": "calls", "confidence": "certain"},
        # ctor -> Run -> Invoke : a 2-hop chain for reachability tests
        {"source": "M:App.Provider.#ctor", "target": "M:App.Provider.Run",
         "kind": "calls", "confidence": "certain"},
    ]
    data = {
        "language": "csharp", "root_path": "C:\\app",
        "summary": {"total_nodes": len(nodes), "functions": 2, "classes": 3,
                    "call_edges": 1, "dependencies": ["App", "System"],
                    "entrypoints": 0, "resolved_calls": 1},
        "nodes": nodes, "edges": edges, "subgraphs": {},
    }
    path.write_bytes(b"\xff\xfe" + json.dumps(data).encode("utf-16-le"))
    codegraph.build_index(str(path), str(path) + ".idx.sqlite", quiet=True)
    return str(path)


@pytest.fixture(scope="module")
def fg(tmp_path_factory):
    return build(tmp_path_factory.mktemp("find") / "g.json")


def ids(out):
    return {i["id"] for i in json.loads(out)["items"]}


def cli(fg, *args):
    return run_cli(fg, *args)


# --- single predicates -------------------------------------------------------

def test_kind_only(fg):
    out, _, _ = cli(fg, "find", "--kind", "class", "--json")
    # Dto, Plain, Helper, SubDto, Consumer, Provider (ids by insertion order)
    assert ids(out) == {0, 4, 7, 9, 10, 13}


def test_attr(fg):
    out, _, _ = cli(fg, "find", "--kind", "class", "--attr", "serializable", "--json")
    assert ids(out) == {0}  # only Dto


def test_implements(fg):
    out, _, _ = cli(fg, "find", "--implements", "iserializable", "--json")
    assert ids(out) == {0}


def test_node_mods(fg):
    out, _, _ = cli(fg, "find", "--kind", "class", "--mods", "internal", "--json")
    assert ids(out) == {7}  # Helper


def test_calls(fg):
    out, _, _ = cli(fg, "find", "--kind", "method", "--calls", "deserialize", "--json")
    assert ids(out) == {8}  # Helper.Load


# --- member predicates -------------------------------------------------------

def test_member_parameterless_ctor(fg):
    out, _, _ = cli(fg, "find", "--kind", "class",
                    "--member", "constructor:public,params=0", "--json")
    # Dto and Provider (Plain's ctor has params, Helper/SubDto/Consumer have none)
    assert ids(out) == {0, 13}


def test_member_ctor_with_params(fg):
    out, _, _ = cli(fg, "find", "--kind", "class",
                    "--member", "constructor:params=+", "--json")
    assert ids(out) == {4}  # Plain


def test_member_readwrite_property(fg):
    out, _, _ = cli(fg, "find", "--kind", "class",
                    "--member", "property:public,get,set", "--json")
    # Dto, Plain, Consumer, Provider all have a public get/set property
    assert ids(out) == {0, 4, 10, 13}


def test_member_calls_condition(fg):
    # class with a method that calls something *invoke* (gadget behavior)
    out, _, _ = cli(fg, "find", "--kind", "class",
                    "--member", "method:calls=invoke", "--json")
    assert ids(out) == {13}  # Provider


def test_member_uses_condition(fg):
    # class with a field whose type references the Dto gadget
    out, _, _ = cli(fg, "find", "--kind", "class",
                    "--member", "field:uses=app.dto", "--json")
    assert ids(out) == {10}  # Consumer


def test_member_type_condition(fg):
    # field whose declared TYPE is Dto (matches the ret column; works for
    # primitives too, unlike uses=)
    out, _, _ = cli(fg, "find", "--kind", "class",
                    "--member", "field:type=dto", "--json")
    assert ids(out) == {10}  # Consumer.gadget : Dto


def test_reaches_multihop(fg):
    # Provider.#ctor (#14) -> Run -> Invoke : reaches "invoke" in 2 hops
    out, _, _ = cli(fg, "find", "--kind", "constructor", "--reaches", "invoke", "--json")
    assert ids(out) == {14}


def test_reaches_depth_bound(fg):
    # with only 1 hop allowed, the ctor cannot reach Invoke (it's 2 hops)
    out, _, _ = cli(fg, "find", "--kind", "constructor", "--reaches", "invoke",
                    "--reach-depth", "1", "--json")
    assert ids(out) == set()


def test_reaches_direct_method(fg):
    # Provider.Run (#15) calls Invoke directly
    out, _, _ = cli(fg, "find", "--kind", "method", "--reaches", "invoke", "--json")
    assert ids(out) == {15}


def test_reached_by_reverse(fg):
    # the Invoke ext node is reachable FROM Provider.Run (externals are numbered
    # after the 17 real nodes, in edge order: SerializableAttribute=17,
    # ISerializable=18, Foo.Deserialize=19, MethodBase.Invoke=20)
    out, _, _ = cli(fg, "find", "--reached-by", "provider.run", "--json")
    assert 20 in ids(out)


def test_member_reaches_bridge_gadget(fg):
    # the headline bridge-gadget rule: a class with a constructor that
    # transitively REACHES a target (here Provider.#ctor -> Run -> Invoke).
    out, _, _ = cli(fg, "find", "--kind", "class",
                    "--member", "constructor:reaches=invoke", "--json")
    assert ids(out) == {13}  # Provider only


def test_member_reaches_depth_bound(fg):
    # at depth 1 the ctor reaches Run but not Invoke (2 hops) -> no match
    out, _, _ = cli(fg, "find", "--kind", "class",
                    "--member", "constructor:reaches=invoke",
                    "--reach-depth", "1", "--json")
    assert ids(out) == set()


def test_objectdataprovider_shape(fg):
    # the behavioral gadget rule: invoking method + settable prop + parameterless ctor
    out, _, _ = cli(fg, "find", "--kind", "class",
                    "--member", "method:calls=invoke",
                    "--member", "property:public,set",
                    "--member", "constructor:public,params=0", "--json")
    assert ids(out) == {13}  # Provider


# --- gadget / relationship predicates ---------------------------------------

def test_find_inherits(fg):
    # classes that extend the Dto gadget
    out, _, _ = cli(fg, "find", "--kind", "class", "--inherits", "app.dto", "--json")
    assert ids(out) == {9}  # SubDto


def test_find_uses(fg):
    # members whose signature references the Dto gadget type
    out, _, _ = cli(fg, "find", "--uses", "app.dto", "--json")
    assert ids(out) == {11}  # Consumer.gadget field


def test_find_overrides(fg):
    out, _, _ = cli(fg, "find", "--overrides", "dto.name", "--json")
    assert ids(out) == {12}  # Consumer.Name overrides Dto.Name


def test_callers_subclasses_of_gadget(fg):
    # the recommended "who extends gadget #0" query
    out, _, _ = cli(fg, "callers", "0", "--kind", "inherits", "--json")
    assert {i["id"] for i in json.loads(out)["items"]} == {9}


def test_callers_users_of_gadget(fg):
    # the recommended "who references gadget #0 in a signature" query
    out, _, _ = cli(fg, "callers", "0", "--kind", "type_uses", "--json")
    assert {i["id"] for i in json.loads(out)["items"]} == {11}


# --- the motivating conjunction ---------------------------------------------

def test_serializable_roundtrippable_pattern(fg):
    # [Serializable] (BinaryFormatter) + public parameterless ctor + public
    # read/write property (Json.NET round-trip) => Dto only.
    out, _, _ = cli(fg, "find", "--kind", "class",
                    "--attr", "serializable",
                    "--member", "constructor:public,params=0",
                    "--member", "property:public,get,set", "--json")
    assert ids(out) == {0}


def test_conjunction_excludes_non_serializable(fg):
    # Plain has the ctor+property shape but no [Serializable] -> excluded.
    out, _, _ = cli(fg, "find", "--kind", "class", "--attr", "serializable",
                    "--member", "property:public,get,set", "--json")
    assert ids(out) == {0}


def test_no_predicates_errors(fg):
    _, err, code = cli(fg, "find")
    assert code != 0 and "at least one predicate" in err


def test_text_output_and_no_match(fg):
    out, _, _ = cli(fg, "find", "--kind", "class", "--attr", "nosuchattr")
    assert "no matches" in out
    out, _, _ = cli(fg, "find", "--kind", "class", "--attr", "serializable")
    assert "#0" in out and "cls" in out
