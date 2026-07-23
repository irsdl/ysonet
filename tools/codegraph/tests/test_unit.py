# Copyright (c) 2026 Soroush Dalili
# SPDX-License-Identifier: MIT

"""Unit tests for the pure helpers: label derivation, escaping, value
coercion, and the UTF-16 -> UTF-8 streaming transcoder."""

import io
import json

import codegraph


# --- unescape / make_label --------------------------------------------------

def test_unescape():
    assert codegraph.unescape("a\\.b") == "a.b"
    assert codegraph.unescape("plain") == "plain"
    # lone backslashes (windows paths) are preserved
    assert codegraph.unescape("all\\System.x") == "all\\System.x"


def test_make_label_member():
    # part after the last ':' wins
    assert codegraph.make_label("a\\.b.C:D.E") == "D.E"
    assert codegraph.make_label("x.dll.Ns.Cls:Cls.Method") == "Cls.Method"


def test_make_label_module():
    # last segment split on unescaped '.', then unescaped
    assert codegraph.make_label("app\\.dll.App.Mod") == "Mod"
    assert codegraph.make_label("a.b.Date\\.Hijri\\.debug") == "Date.Hijri.debug"


def test_make_label_no_separator():
    assert codegraph.make_label("noseparator") == "noseparator"
    # all dots escaped -> whole id, unescaped
    assert codegraph.make_label("Date\\.Hijri\\.debug") == "Date.Hijri.debug"


# --- value coercion ----------------------------------------------------------

def test_fmt_param():
    assert codegraph.fmt_param({"name": "x", "type": "int"}) == "int x"
    assert codegraph.fmt_param({"name": "x"}) == "x"
    assert codegraph.fmt_param({"type": "int"}) == "int"
    assert codegraph.fmt_param("y") == "y"
    assert codegraph.fmt_param({}) == "?"


def test_as_text():
    assert codegraph.as_text(None) is None
    assert codegraph.as_text("s") == "s"
    assert codegraph.as_text({"name": "void"}) == "void"
    assert codegraph.as_text({"type": "int"}) == "int"
    assert "z" in str(codegraph.as_text({"z": 1}))  # falls back to JSON
    assert codegraph.as_text([1, 2]) == "[1, 2]"


def test_kind_abbrev():
    assert codegraph.kind_abbrev("method") == "fn"
    assert codegraph.kind_abbrev("class") == "cls"
    assert codegraph.kind_abbrev("external") == "ext"
    assert codegraph.kind_abbrev("weirdkind") == "weir"


# --- UTF-16 -> UTF-8 transcoder ----------------------------------------------

def test_u16_transcode_chunked():
    # odd-sized reads must not split UTF-16 code units incorrectly;
    # includes a surrogate pair (4 UTF-16 bytes)
    text = '{"a": "héllo \U0001f30d", "b": [1, 2]}'
    w = codegraph.U16ToU8(io.BytesIO(text.encode("utf-16-le")))
    out = bytearray()
    while True:
        b = w.read(7)
        if not b:
            break
        out += b
    assert bytes(out).decode("utf-8") == text


def test_u16_read_all():
    text = '{"k": "v"}'
    w = codegraph.U16ToU8(io.BytesIO(text.encode("utf-16-le")))
    assert w.read().decode("utf-8") == text


def test_u16_readinto():
    text = '{"k": 1}'
    w = codegraph.U16ToU8(io.BytesIO(text.encode("utf-16-le")))
    out = bytearray()
    buf = bytearray(5)
    while True:
        n = w.readinto(buf)
        if not n:
            break
        out += buf[:n]
    assert bytes(out).decode("utf-8") == text


# --- encoding detection ------------------------------------------------------

def _roundtrip(tmp_path, name, raw):
    p = tmp_path / name
    p.write_bytes(raw)
    src, f = codegraph.open_json_bytes(str(p))
    try:
        return json.loads(src.read().decode("utf-8"))
    finally:
        f.close()


def test_open_json_bytes_encodings(tmp_path):
    doc = {"a": 1}
    text = json.dumps(doc)
    assert _roundtrip(tmp_path, "u16bom.json",
                      b"\xff\xfe" + text.encode("utf-16-le")) == doc
    assert _roundtrip(tmp_path, "u8bom.json",
                      b"\xef\xbb\xbf" + text.encode("utf-8")) == doc
    assert _roundtrip(tmp_path, "u8.json", text.encode("utf-8")) == doc
    # BOM-less UTF-16 LE is sniffed via the zero byte
    assert _roundtrip(tmp_path, "u16.json", text.encode("utf-16-le")) == doc
