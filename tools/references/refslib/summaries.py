"""Preserve reviewed source metadata and original summaries, without fetching.

These are explicitly incomplete source archives. A summary must never replace
an existing full document, claim raw source bytes, or clear a full-text gap.
"""

from pathlib import Path

from . import layout, manifest as manifest_module, paths, render, slugs, urls

GAP = "Only metadata and an original summary are preserved; full source text is not mirrored."


def record_summaries(records, references, manifest, store, root, config):
    """Validate the entire batch, then render only new or existing summary records."""
    if not isinstance(records, list) or not records:
        raise ValueError("expected a non-empty JSON array of reviewed source summaries")
    prepared = []
    seen = set()
    for item in records:
        if not isinstance(item, dict):
            raise ValueError("each summary must be a JSON object")
        for field in ("url", "title", "summary", "why", "publisher", "reviewed_on"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                raise ValueError("missing non-empty string: " + field)
        from datetime import date
        date.fromisoformat(item["reviewed_on"])
        if item.get("published"):
            date.fromisoformat(item["published"])
        authors = item.get("authors", [])
        if not isinstance(authors, list) or any(not isinstance(a, str) for a in authors):
            raise ValueError("authors must be an array of strings")
        for field in ("published", "licence"):
            if field in item and not isinstance(item[field], str):
                raise ValueError(field + " must be a string")
        # These fields become public prose. Do not accept local provenance paths.
        for value in list(item.values()):
            values = value if isinstance(value, list) else [value]
            if any(isinstance(v, str) and paths.redact_text(v) != v for v in values):
                raise ValueError("summary metadata contains a local path")
        key = urls.normalize(item["url"], config.get("host_aliases"),
                             config.get("locale_stripped_hosts") or ())
        if key not in references or key in seen:
            raise ValueError("URL must be a unique, current research citation: " + item["url"])
        seen.add(key)
        old = manifest.data["urls"].get(key) or {}
        if (old.get("decision") or {}).get("outcome") == "skip":
            raise ValueError("reference has an existing exclusion: " + item["url"])
        if (old.get("content_sha256") or old.get("slug")) and old.get("depth_reason") != "original-summary":
            raise ValueError("refusing to replace an existing source artifact: " + item["url"])
        prepared.append((key, item, references[key]))

    outputs = []
    taken = {e.get("slug") for e in manifest.data["urls"].values() if e.get("slug")}
    for key, item, reference in prepared:
        entry = manifest.entry(key)
        stamp = manifest_module.utc_now()
        summary = "Original research summary; not a copy of the source.\n\n" + item["summary"].strip()
        digest = store.put_text(summary)
        slug = entry.get("slug") or slugs.build(item["title"], item["publisher"],
                                                slugs.year_of(item.get("published", "")), taken=taken)
        taken.add(slug)
        record = dict(
            slug=slug, title=item["title"], publisher=item["publisher"],
            authors=item.get("authors", []), published=item.get("published", ""),
            licence=item.get("licence") or "unknown", kind="article", language="en",
            original_url=reference.spellings[0], retrieved_from=reference.spellings[0],
            retrieved_kind="original-summary", retrieved_utc=stamp,
            reviewed_on=item["reviewed_on"], content_sha256=digest, raw_sha256="",
            cited_by=[o.cited_by() for o in reference.occurrences],
            depth="metadata", depth_reason="original-summary", grade="records",
            summary=summary, why=item["why"], content_gap=GAP,
        )
        destination = (layout.path(root, config, record) if config.get("layout_version") == 2
                       else Path(root) / config["archive_dir"] / "records" / (slug + ".md"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() and entry.get("slug") != slug:
            raise ValueError("refusing to overwrite an unclaimed archive file")
        destination.write_text(render.render(record, depth="metadata"), encoding="utf-8", newline="\n")
        entry.update(record)
        entry["spellings"] = reference.spellings
        entry["decision"] = {"outcome": "archive", "class": "records",
                             "by": "original-summary", "reason": GAP, "at": stamp[:10]}
        manifest.record(key, "summary", result="stored", content_sha256=digest,
                        reviewed_on=item["reviewed_on"], reason=GAP)
        manifest.record(key, "render", result="ok", depth="metadata",
                        file=paths.rel(destination, root))
        outputs.append(paths.rel(destination, root))
    manifest.save()
    return outputs
