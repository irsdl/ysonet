"""Offline diagram parsing and output validation for the isolated worker."""
import html
import json
import re
import xml.etree.ElementTree as ET


def find_mermaid(documents):
    found = []
    for data in documents:
        if not isinstance(data, bytes) or len(data) > 4 * 1024 * 1024:
            raise ValueError("invalid diagram input")
        fence, language, block = "", "", []
        for line in data.decode("utf-8", "replace").splitlines():
            opening = re.match(r"^\s*(`{3,}|~{3,})(.*)$", line)
            if fence:
                if re.fullmatch(re.escape(fence[0]) + r"{%d,}\s*" % len(fence), line.strip()):
                    if language == "mermaid":
                        found.append("\n".join(block).strip())
                    fence, language, block = "", "", []
                elif language == "mermaid":
                    block.append(line)
            elif opening:
                fence, language = opening.group(1), opening.group(2).strip()
    return found


def parse_rendered(data, expected):
    match = re.search(r'<textarea id="result">(.*?)</textarea>', data.decode("utf-8", "replace"), re.S)
    if not match or len(data) > 16 * 1024 * 1024:
        raise ValueError("invalid diagram output envelope")
    rows = json.loads(html.unescape(match[1]))
    seen = set()
    if not isinstance(rows, list):
        raise ValueError("diagram output must be a list")
    for row in rows:
        if not isinstance(row, list) or len(row) not in (2, 3) or not isinstance(row[0], str):
            raise ValueError("invalid diagram record")
        identity = row[0]
        if identity not in expected or identity in seen or not re.fullmatch(r"[a-f0-9]{64}", identity):
            raise ValueError("unexpected or duplicate diagram identity")
        seen.add(identity)
        if row[1] is not None:
            if not isinstance(row[1], str) or len(row[1]) > 4 * 1024 * 1024:
                raise ValueError("invalid diagram SVG")
            row[1] = checked_svg(row[1])
    if seen != set(expected):
        raise ValueError("diagram output is incomplete")
    return rows

def checked_svg(value):
    # Chromium expands local marker URLs to its temporary document URL.
    # Restore fragment-only references before validating the standalone SVG.
    value = value.replace("file:///out/index.html#", "#")
    if re.search(r"<\?|<!DOCTYPE|<!ENTITY", value, re.I):
        raise ValueError("SVG processing instructions and declarations are not admitted")
    root = ET.fromstring(value)
    if root.tag != "{http://www.w3.org/2000/svg}svg":
        raise ValueError("renderer did not produce SVG")
    styles = []
    allowed = {"svg", "g", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon",
               "text", "tspan", "defs", "marker", "style", "title", "desc", "clippath", "mask",
               "pattern", "lineargradient", "radialgradient", "stop", "symbol", "a",
               "filter", "fedropshadow"}
    for node in root.iter():
        if not node.tag.startswith("{http://www.w3.org/2000/svg}") or node.tag.split("}")[-1].lower() not in allowed:
            raise ValueError("active or unsupported SVG element")
        if node.tag.split("}")[-1].lower() == "style":
            styles.append(node.text or "")
        if node.tag.split("}")[-1].lower() in {"script", "foreignobject", "iframe", "image", "use"}:
            raise ValueError("active or externally referenced SVG element")
        for key, val in node.attrib.items():
            styles.append(val)
            name = key.split("}")[-1].lower()
            if name.startswith("on") or (name in {"href", "src"} and not val.startswith("#")):
                raise ValueError("active or external SVG attribute")
    style_text = "\n".join(styles)
    if "\\" in style_text or re.search(r"@import|@font-face|expression\s*\(", style_text, re.I) or any(
        not target.strip().strip("\"'").startswith("#")
        for target in re.findall(r"url\((.*?)\)", style_text, re.I)
    ):
        raise ValueError("external SVG stylesheet reference")
    return value
