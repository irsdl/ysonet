"""Inert source interpretation, executed in the offline source worker."""
import hashlib
import json
import re

from . import grade, render, translate

ATTRIBUTION_FIELDS = ("title", "authors", "publisher", "published", "licence", "original_url",
                      "canonical_url", "retrieved_kind", "retrieved_from", "retrieved_utc",
                      "snapshot", "commit", "title_english", "publisher_english", "language")


def metadata(text):
    """Read the archive's simple frontmatter as data, with no YAML execution."""
    if not text.startswith("---\n"):
        return {}
    header = text.split("\n---", 1)[0][4:]
    found = {}
    for name in ATTRIBUTION_FIELDS:
        match = re.search(r"^" + name + r":([^\n]*)(\n(?:  - [^\n]*\n?)*)?", header, re.M)
        if not match:
            continue
        value = match.group(1).strip()
        if name == "authors":
            value = [line[4:].strip().strip('"') for line in (match.group(2) or "").splitlines()
                     if line.startswith("  - ")]
        elif value.startswith('"'):
            try:
                value = json.loads(value)
            except ValueError:
                value = value.strip('"')
        if isinstance(value, (str, list)):
            found[name] = value
    return found


def sections(text):
    """Recover source and English bodies from the earlier archive format.

    Only archive-owned section boundaries are interpreted. This never executes
    Markdown or follows a source URL. The controller retains the published hash.
    """
    english = ""
    if "\n## Content (translated into English)\n" in text:
        prefix, original = text.split("\n## Content (original)\n", 1)
        translated = prefix.split("\n## Content (translated into English)\n", 1)[1]
        english = re.sub(r"\A\s*_Machine translation\..*?_\s*", "", translated,
                         count=1, flags=re.S).strip()
        body = original
    elif "\n## Content (English translation)\n" in text:
        body = text.split("\n## Content (English translation)\n", 1)[1]
        return "", _after_banner(body)
    elif "\n## Content\n" in text:
        body = text.split("\n## Content\n", 1)[1]
    else:
        return "", ""
    body = body.split("\n## Recovery notes\n", 1)[0]
    return _after_banner(body), english


def _after_banner(body):
    marker = render.BANNER.strip()
    if marker in body:
        return body.split(marker, 1)[1].strip()
    return ""


def inspect_batch(rows):
    """Bounded data-only result, including recoverable content and language gaps."""
    if len(rows) > 600:
        raise ValueError("too many documents in one reading batch")
    output = []
    for row in rows:
        text, entry = row["text"], row["entry"]
        source, english = sections(text)
        reading = english or source
        foreign = translate.has_foreign_prose(reading, "" if english else entry.get("language", ""))
        output.append({"key": row["key"], "source": source, "english": english,
                       "published_sha256": hashlib.sha256(text.encode()).hexdigest(),
                       "characters": len(reading), "foreign": foreign,
                       "capture_fault": grade.looks_broken(metadata(text).get("title", ""), reading)})
    return output


def english_render(record, content, depth="full"):
    """Publish an English reading copy; retain originals by hash and source PDF."""
    from . import repo
    record = dict(record)
    content = reading_content(record, content)
    if record.get("translation"):
        record["translation"] = reading_content(record, record["translation"])
    url = record.get("original_url") or ""
    if record.get("kind") == "repo":
        content = repo.clean_legacy_markdown(content, url, record.get("commit") or "")
        if record.get("translation"):
            record["translation"] = repo.clean_legacy_markdown(record["translation"], url, record.get("commit") or "")
    if not record.get("translation"):
        return render.render(record, content, depth)
    text = render.render(record, content, depth)
    start = text.index("\n## Content (translated into English)\n")
    prefix = text[:start]
    return (prefix + "\n## Content (English translation)\n\n"
            "_English translation. Original text is retained in the content store; "
            "the source PDF, when available, retains its original language._\n\n" +
            render.BANNER + "\n" + record["translation"].strip() + "\n")


def reading_content(record, content):
    """Expose Markdown document prose and restore linked slide figures."""
    from urllib.parse import unquote, urlsplit
    from . import github, images, repo
    url = record.get("original_url") or ""
    parts = urlsplit(url)
    match = github.BLOB.match(unquote(parts.path)) if (parts.hostname or "").lower() in ("github.com", "www.github.com") else None
    if match and match.group(4).lower().endswith((".md", ".markdown")):
        owner, name, ref, path = match.groups()
        prefix = "# %s\n\n`%s/%s` at `%s`, path `%s`." % (path.rsplit("/", 1)[-1], owner, name, ref[:12], path)
        if content.startswith(prefix):
            rest = content[len(prefix):]
            citation = re.match(r"\n\nThe citation points at line \d+\.", rest)
            if citation:
                prefix += citation.group(0)
                rest = rest[citation.end():]
            opening = re.match(r"\n\n(`{3,})(?:markdown|md)\n", rest)
            if opening and rest.rstrip().endswith("\n" + opening.group(1)):
                body = rest[opening.end():].rstrip()[:-(len(opening.group(1)) + 1)]
                content = prefix + "\n\n" + repo.document_links(body, owner + "/" + name, ref, path) + "\n"
    if record.get("kind") == "slides":
        primary = slide_image_urls(content)
        held = record.get("slide_images") or []
        if len(held) > len(primary):
            primary = list(dict.fromkeys(held))
        if primary:
            existing = set(images.urls_in(content))
            missing = [target for target in primary if target not in existing]
            if missing and len(primary) >= 3:
                content += "\n\n## Slide images preserved from the transcript links\n\n"
                for target in missing:
                    number = re.search(r"slide_(\d+)\.", target)
                    slide = str(int(number.group(1)) + 1) if number else ""
                    if not slide:
                        number = re.search(r"-(\d+)-\d+\.(?:jpg|jpeg|png)$", target)
                        slide = number.group(1) if number else ""
                    content += "![Slide %s](%s)\n\n" % (slide, target)
    return content


def slide_image_urls(content):
    """The largest same-deck group of public slide images in source order."""
    from urllib.parse import urlsplit
    targets = re.findall(
        r'https://(?:files\.speakerdeck\.com/presentations/|image\.slidesharecdn\.com/)'
        r'[^\s<>"\)]+?\.(?:jpg|jpeg|png)', content or "")
    groups = {}
    for target in dict.fromkeys(targets):
        path = urlsplit(target).path.strip("/").split("/")
        identity = path[1] if path[0] == "presentations" and len(path) > 1 else path[0]
        groups.setdefault(identity, []).append(target)
    return max(groups.values(), key=len) if groups else []


def render_batch(rows):
    if len(rows) > 20:
        raise ValueError("render batch limit")
    results = []
    for row in rows:
        record = dict(row["record"])
        held = metadata(row.get("published") or "")
        for field in ATTRIBUTION_FIELDS:
            if not record.get(field) and held.get(field):
                record[field] = held[field]
        if not record.get("title"):
            record["title"] = record.get("cited_title") or record["original_url"]
        results.append({"key": row["key"], "text": english_render(record, row["content"], row["depth"]),
                        "attribution": {field: record[field] for field in ATTRIBUTION_FIELDS if record.get(field)}})
    return results


def refresh_gap(previous, candidate):
    """Detect material loss before an existing source copy is replaced."""
    if len(previous.strip()) >= 1500 and len(candidate.strip()) < len(previous.strip()) * 0.7:
        return "Refresh lost more than 30% of the held body; retained the existing copy for source comparison."
    old_code = re.findall(r"^```[^\n]*\n", previous, re.M)
    new_code = re.findall(r"^```[^\n]*\n", candidate, re.M)
    if old_code and len(new_code) < len(old_code):
        return "Refresh lost fenced source listings; retained the existing copy for source comparison."
    return ""


def paper_candidates(rows):
    from . import htmltext, linked_documents
    from urllib.parse import urlsplit
    if len(rows) > 20:
        raise ValueError("paper discovery batch limit")
    results = []
    for row in rows:
        key = row["key"]
        try:
            url = key if urlsplit(key).path.lower().endswith(".pdf") else linked_documents.paper_link(row["text"], key)
            raw = row.get("raw") or b""
            if not url and raw.lstrip().startswith(b"<"):
                url = linked_documents.discover(htmltext.decode(raw, "text/html"), key).primary
            results.append({"key": key, "url": url})
        except (ValueError, TypeError) as error:
            results.append({"key": key, "url": "", "error": type(error).__name__ + ": " + str(error)[:160]})
    return results


def validate_batch(rows):
    from . import verify
    if len(rows) > 20:
        raise ValueError("validation batch limit")
    results = []
    for row in rows:
        text = row["text"]
        source, english = sections(text)
        results.append({"key": row["key"], "attribution": render.check_attribution(text),
                        "malformed": verify.malformed(text),
                        "capture_fault": capture_fault(metadata(text), english or source),
                        "foreign": translate.has_foreign_prose(english or source)})
    return results


def capture_fault(record, body):
    fault = grade.looks_broken(record.get("title") or "", body)
    if fault:
        return fault
    expected = re.findall(r"CVE-\d{4}-\d{4,}", record.get("original_url") or "", re.I)
    identity_text = (record.get("title") or "") + "\n" + body
    # Publishers commonly let typography engines replace the second ASCII
    # hyphen in a CVE identifier with an en dash or another Unicode dash.
    # That is still the same identifier, not evidence of a wrong document.
    identity_text = re.sub(r"[\u2010-\u2015\u2212\ufe58\ufe63\uff0d]", "-", identity_text)
    from urllib.parse import unquote, urlsplit
    title_key = re.sub(r"[^a-z0-9]+", "-", (record.get("title") or "").lower()).strip("-")
    path_key = re.sub(r"[^a-z0-9]+", "-", unquote(urlsplit(
        record.get("original_url") or "").path).lower()).strip("-")
    title_matches_path = len(title_key) >= 20 and title_key in path_key
    if expected and not title_matches_path and not any(
            cve.lower() in identity_text.lower() for cve in expected):
        return "The cited CVE identifier is absent from the captured title and body; check for a redirect or wrong document."
    if "anquanke.com/subject/id/" in (record.get("original_url") or "") and "/post/id/" not in body:
        return "The captured series index contains navigation but no article entries."
    return ""


def catalog_body(body, url):
    """Keep all entries in the Anquanke subject index, excluding site chrome."""
    if "anquanke.com/subject/id/" not in url:
        return body
    heading = re.search(r"(?m)^# [^\n]+", body)
    if not heading:
        return body
    body = body[heading.start():]
    footer = "\n****[](https://weibo.com/360adlab)"
    if footer in body:
        body = body.split(footer, 1)[0]
        body = re.sub(r"\n!\[\]\(https://p0\.qhimg\.com/t11098f6bcd5614af4bf21ef9b5\.png\)\s*$", "", body)
    return body.strip()


def cve_record(raw, identifier):
    """A complete, identity-checked CVE Program record for a declared fallback."""
    data = json.loads(raw.decode("utf-8"))
    meta = data.get("cveMetadata") or {}
    if data.get("dataType") != "CVE_RECORD" or meta.get("cveId") != identifier:
        raise ValueError("CVE record identity mismatch")
    cna = (data.get("containers") or {}).get("cna") or {}
    descriptions = [item["value"] for item in cna.get("descriptions", [])
                    if item.get("lang", "").lower().startswith("en") and isinstance(item.get("value"), str)]
    if not descriptions:
        raise ValueError("CVE record has no English description")
    source = json.dumps(data, ensure_ascii=False, indent=2)
    fence = "`" * max(3, 1 + max((len(m.group(0)) for m in re.finditer(r"`+", source)), default=0))
    body = ("# " + identifier + " — authoritative CVE record\n\n"
            "The original AttackerKB page could not be recovered. The complete CVE Program "
            "record is preserved below as a separately attributed fallback; it does not "
            "establish what community assessments the original page contained.\n\n"
            + "\n\n".join(descriptions) + "\n\n## Complete source record\n\n"
            + fence + "json\n" + source + "\n" + fence + "\n")
    return {"body": body, "title": identifier + " — CVE Program record (AttackerKB fallback)",
            "publisher": "CVE Program", "authors": [(cna.get("providerMetadata") or {}).get("shortName") or "CVE Program"],
            "published": (meta.get("datePublished") or "")[:10]}


def language_findings(text):
    source, english = sections(text)
    prepared = translate.prepare(english or source or text)
    return prepared.chunks
