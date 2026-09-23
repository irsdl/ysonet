"""Archive migration, original-PDF preference and explicit completeness reports.

Controllers move bounded bytes and own publication. Source interpretation and
rendering use the same isolated workers as acquisition. No source can nominate
a local output path or turn an archive gap into a successful capture.
"""
import hashlib
import json
from pathlib import Path

from . import check, isolation, layout, manifest as state, paths
from .store import Store


def context():
    root, config = paths.repo_root(), paths.config()
    return root, config, check.open_manifest(root, config), Store(paths.store_root())


def selected(manifest, only="", limit=None):
    rows = [(key, entry) for key, entry in manifest.data["urls"].items()
            if entry.get("slug") and entry.get("grade") in ("research", "records")
            and (not only or only.lower() in key.lower())]
    return rows if limit is None else rows[:limit]


def write_bytes(path, body):
    """Atomic replacement; interrupted runs keep the previous complete file."""
    import os
    import tempfile
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def migrate(args):
    """Move the existing archive without discarding user edits or source bytes."""
    root, config, manifest, store = context()
    old = root / "docs/references-md"
    target = root / config["archive_dir"]
    if not old.exists():
        print("Archive layout already migrated.")
        return 0
    if (target / "manifest.json").exists():
        raise ValueError("both archive manifests exist; refusing an ambiguous migration")
    # Build and validate the complete move map before changing any file.
    old_manifest = state.Manifest.load(old / "manifest.json")
    moves = []
    claimed = set()
    for key, entry in selected(old_manifest):
        source = old / entry["grade"] / (entry["slug"] + ".md")
        if source.exists():
            moves.append((source, layout.path(root, config, entry)))
            claimed.add(source)
    for source in old.iterdir():
        if source.is_file():
            moves.append((source, target / source.name))
            claimed.add(source)
    extra = [p for p in old.rglob("*") if p.is_file() and p not in claimed]
    if extra or any(b.exists() for a, b in moves):
        raise ValueError("unclaimed files or destination collisions; migration made no changes")
    for source, destination in moves:
        destination.parent.mkdir(parents=True, exist_ok=True)
        source.rename(destination)
    for directory in sorted(old.rglob("*"), reverse=True):
        if directory.is_dir():
            directory.rmdir()
    old.rmdir()
    manifest = state.Manifest.load(target / "manifest.json")
    for key, entry in selected(manifest):
        # History stays byte-for-byte intact; current step paths follow the move.
        for step in entry.get("steps", {}).values():
            if isinstance(step.get("file"), str) and step["file"].startswith("docs/references-md/"):
                step["file"] = paths.rel(layout.path(root, config, entry), root)
    manifest.save()
    print("Moved %d files into %s; history and reference bodies preserved." % (len(moves), config["archive_dir"]))
    return 0


def recover(args):
    """Recover missing extracted text from published copies before any refresh."""
    root, config, manifest, store = context()
    rows = []
    for key, entry in manifest.data["urls"].items():
        if args.only and args.only.lower() not in key.lower():
            continue
        prior = entry.get("steps", {}).get("import", {})
        if (not entry.get("grade") and entry.get("slug") and prior.get("result") == "stored"
                and prior.get("grade") in ("research", "records")
                and store.has(entry.get("content_sha256"))
                and (entry.get("decision") or {}).get("outcome") != "skip"):
            entry["grade"] = prior["grade"]
            entry["depth"] = "full"
            entry["content_gap"] = ""
            manifest.record(key, "recover-import", result="restored",
                            reason="Restored classification from a recorded import whose extracted source object is intact; render and review remain required.")
    manifest.save()
    for key, entry in selected(manifest, args.only, args.limit):
        path = layout.path(root, config, entry)
        if path.is_file():
            rows.append({"key": key, "entry": entry, "text": path.read_text(encoding="utf-8")})
    recovered = 0
    for offset in range(0, len(rows), 20):
        batch = rows[offset:offset + 20]
        results = isolation.call("reading.inspect_batch", batch)
        expected = {row["key"]: row for row in batch}
        if not isinstance(results, list) or len(results) != len(expected):
            raise ValueError("incomplete source reading response")
        seen = set()
        for item in results:
            key = item.get("key")
            if key not in expected or key in seen:
                raise ValueError("unexpected source reading identity")
            seen.add(key)
            row, entry = expected[key], manifest.entry(key)
            digest = hashlib.sha256(row["text"].encode()).hexdigest()
            if item.get("published_sha256") != digest:
                raise ValueError("source reading hash mismatch")
            for field, body_key in (("content_sha256", "source"), ("translation_sha256", "english")):
                body = item.get(body_key)
                if not isinstance(body, str):
                    raise ValueError("invalid recovered body")
                if body and not store.has(entry.get(field)):
                    previous = entry.get(field)
                    entry[field] = store.put_text(body)
                    manifest.record(key, "recover-" + body_key, result="stored",
                                    sha256=entry[field], previous_sha256=previous or "",
                                    published_sha256=digest,
                                    reason="Recovered extracted text from the published Markdown; not raw source bytes.")
                    recovered += 1
            entry["reading_audit"] = {"characters": item["characters"],
                                      "foreign": item["foreign"], "published_sha256": digest,
                                      "capture_fault": item.get("capture_fault") or ""}
        manifest.save()
        print("Inspected %d/%d published copies." % (min(offset + 20, len(rows)), len(rows)), flush=True)
    print("Recovered %d missing text objects; raw-source gaps remain separate." % recovered)
    return 0


def republish(args):
    """Offline English rendering, including manual imports and recovered copies."""
    root, config, manifest, store = context()
    made = failed = 0
    jobs = []
    for key, entry in selected(manifest, args.only, args.limit):
        sha = entry.get("content_sha256")
        if not store.has(sha):
            failed += 1
            continue
        record = dict(entry)
        # Earlier state sometimes said metadata even though a full body had
        # already been published by a manual import. Never discard that body.
        if (record.get("depth") in (None, "metadata") and record.get("depth_reason") != "original-summary"
                and (record.get("reading_audit") or {}).get("characters", 0) > 0):
            record["depth"] = entry["depth"] = "full"
            record["depth_reason"] = entry["depth_reason"] = "preserved-source-body"
            manifest.record(key, "depth-repair", result="full",
                            reason="Reconciled legacy metadata depth with the existing complete-body publication; semantic review remains separate.")
        step = entry.get("steps", {}).get("acquire", {})
        record.setdefault("original_url", (entry.get("spellings") or [key])[0])
        record.setdefault("retrieved_kind", step.get("retrieved_kind") or "preserved-copy")
        record.setdefault("retrieved_utc", step.get("utc") or entry.get("first_seen_utc") or state.utc_now())
        translation = entry.get("translation_sha256")
        if store.has(translation):
            record["translation"] = store.get_text(translation)
        published = layout.path(root, config, entry)
        jobs.append({"key": key, "record": record, "content": store.get_text(sha),
                     "published": published.read_text(encoding="utf-8") if published.exists() else "",
                     "depth": entry.get("depth") or "full"})
    for offset in range(0, len(jobs), 20):
        batch = jobs[offset:offset + 20]
        results = isolation.call("reading.render_batch", batch)
        expected = {row["key"] for row in batch}
        if len(results) != len(expected) or {row["key"] for row in results} != expected:
            raise ValueError("render response identity mismatch")
        for result in results:
            key, text = result["key"], result["text"]
            entry = manifest.entry(key)
            from .reading import ATTRIBUTION_FIELDS
            for field, value in result.get("attribution", {}).items():
                if field not in ATTRIBUTION_FIELDS:
                    raise ValueError("unexpected attribution field")
                if not entry.get(field):
                    entry[field] = value
            path = layout.path(root, config, entry)
            write_bytes(path, text.encode())
            manifest.record(key, "render", result="ok", file=paths.rel(path, root),
                            depth=entry.get("depth") or "full", sha256=hashlib.sha256(text.encode()).hexdigest())
            made += 1
        manifest.save()
        print("Published %d reading copies." % made, flush=True)
    manifest.save()
    print("%d rendered; %d missing content objects." % (made, failed))
    return 1 if failed else 0


def pdf_inputs(entry, markdown):
    """All inputs which can change a PDF, including captured figures."""
    from . import makepdf
    values = {"markdown": hashlib.sha256(markdown).hexdigest(), "raw": entry.get("raw_sha256"),
              "paper": (entry.get("paper") or {}).get("sha256"),
              "images": {url: item.get("sha256") for url, item in (entry.get("images") or {}).items()},
              "renderer": makepdf.RENDERER}
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def choose_pdf(entry, store):
    """The original PDF outranks a discovered publisher copy, then Markdown."""
    from .makepdf import is_pdf_bytes
    for source, sha in (("original-pdf", entry.get("raw_sha256")),
                        ("linked-paper", (entry.get("paper") or {}).get("sha256"))):
        if store.has(sha):
            body = store.get(sha)
            if is_pdf_bytes(body):
                return source, body
    return "markdown", b""


def pdf(args):
    from concurrent.futures import ThreadPoolExecutor
    from . import images
    root, config, manifest, store = context()
    made = failed = skipped = 0
    def produce(row):
        key, entry = row
        md, out = layout.path(root, config, entry), layout.path(root, config, entry, "pdf")
        if not md.exists():
            return key, {"error": "Markdown is missing"}
        markdown = md.read_bytes()
        fingerprint = pdf_inputs(entry, markdown)
        previous = entry.get("steps", {}).get("pdf", {})
        if out.exists() and previous.get("inputs_sha256") == fingerprint and not args.force:
            if hashlib.sha256(out.read_bytes()).hexdigest() == previous.get("sha256"):
                return key, {"unchanged": True}
        try:
            source, body = choose_pdf(entry, store)
            if body:
                # Validate page structure in Docker; never publish a truncated header.
                pages = isolation.call("pdf_info", body, text=False)
                if not 1 <= pages <= 500:
                    raise ValueError("PDF page count is outside the archive limit")
            else:
                image_map = {url: images.data_uri(store.get(item["sha256"]))
                             for url, item in entry.get("images", {}).items() if store.has(item.get("sha256"))}
                body, pages = isolation.call("render_pdf", markdown.decode("utf-8"),
                    entry.get("title_english") or entry.get("title") or entry["slug"], key, image_map=image_map)
            write_bytes(out, body)
            return key, {"result": "copied" if source != "markdown" else "rendered",
                "source": source, "file": paths.rel(out, root), "sha256": hashlib.sha256(body).hexdigest(),
                "inputs_sha256": fingerprint, "bytes": len(body), "pages": pages}
        except Exception as error:
            return key, {"error": str(error)[:240]}
    # Workers write distinct artifact paths. Only this controller mutates the manifest.
    with ThreadPoolExecutor(max_workers=getattr(args, "jobs", 4)) as pool:
        for key, result in pool.map(produce, selected(manifest, args.only, args.limit)):
            entry = manifest.data["urls"][key]
            if result.get("unchanged"):
                skipped += 1
                continue
            if "error" in result:
                failed += 1
                manifest.record(key, "pdf-attempt", result="failed", reason=result["error"])
                print("PDF failed: %s: %s" % (entry["slug"], result["error"][:160]), flush=True)
            else:
                made += 1
                manifest.record(key, "pdf", **result)
                print("PDF %-13s %s" % (result["source"], entry["slug"]), flush=True)
            manifest.save()
    print("PDFs: %d published, %d unchanged, %d failed." % (made, skipped, failed))
    return 1 if failed else 0


def reports(root, config, manifest, store):
    """Distinct document, semantic-review and reproducibility queues."""
    groups = {"document-gaps": [], "review-gaps": [], "store-gaps": []}
    for key, entry in selected(manifest):
        reasons = []
        if not layout.path(root, config, entry).is_file():
            reasons.append("Markdown missing")
        if not layout.path(root, config, entry, "pdf").is_file():
            reasons.append("PDF missing")
        if entry.get("depth") != "full":
            reasons.append("Only %s depth is preserved" % (entry.get("depth") or "unknown"))
        if entry.get("content_gap"):
            reasons.append(entry["content_gap"])
        audit = entry.get("reading_audit") or {}
        if audit.get("foreign"):
            reasons.append("English translation incomplete or absent")
        if audit.get("capture_fault"):
            reasons.append(audit["capture_fault"])
        if entry.get("figure_gap"):
            reasons.append(entry["figure_gap"])
        unavailable = [url for url, item in (entry.get("images") or {}).items() if not store.has(item.get("sha256"))]
        if unavailable:
            reasons.append("%d referenced figures unavailable" % len(unavailable))
        if reasons:
            groups["document-gaps"].append((key, "; ".join(reasons)))
        review = entry.get("review") or {}
        path = layout.path(root, config, entry)
        reviewed = path.is_file() and review.get("markdown_sha256") == hashlib.sha256(path.read_bytes()).hexdigest()
        if not reviewed:
            groups["review-gaps"].append((key, "Check full source coverage, identity, prose, code, tables, figures and English; conversion alone is not review."))
        missing = [field for field in ("raw_sha256", "content_sha256", "translation_sha256")
                   if entry.get(field) and not store.has(entry[field])]
        if not entry.get("raw_sha256"):
            missing.append("raw source was not preserved")
        if missing:
            groups["store-gaps"].append((key, ", ".join(missing)))
    for key, entry in manifest.data["urls"].items():
        if entry.get("slug") and entry.get("grade") in ("research", "records"):
            continue
        decision = entry.get("decision") or {}
        if decision.get("outcome") == "skip" and decision.get("class") != "broken-capture":
            continue
        groups["document-gaps"].append((key, entry.get("content_gap") or decision.get("reason") or "No published document"))
    return groups


def verify_pairs(root, config, manifest, store):
    """Published pairs and their bytes are checked independently of store health."""
    from .verify import Finding
    groups = reports(root, config, manifest, store)
    findings = []
    if groups["document-gaps"]:
        findings.append(Finding("fail", "incomplete archived references",
                                "%d reference(s); see document-gaps.md" % len(groups["document-gaps"])))
    if groups["review-gaps"]:
        findings.append(Finding("warn", "semantic review pending",
                                "%d reference(s); see review-gaps.md" % len(groups["review-gaps"])))
    expected = set()
    for key, entry in selected(manifest):
        path = layout.path(root, config, entry, "pdf")
        expected.add(path.resolve())
        if not path.is_file():
            continue
        pdf = entry.get("steps", {}).get("pdf", {})
        body = path.read_bytes()
        if not body.startswith(b"%PDF-") or hashlib.sha256(body).hexdigest() != pdf.get("sha256"):
            findings.append(Finding("fail", "PDF integrity mismatch", entry["slug"]))
        md = layout.path(root, config, entry)
        if md.is_file() and pdf.get("inputs_sha256") != pdf_inputs(entry, md.read_bytes()):
            findings.append(Finding("fail", "PDF is stale", entry["slug"]))
    for path in (Path(root) / config["archive_dir"] / "pdf").rglob("*.pdf"):
        if path.resolve() not in expected:
            findings.append(Finding("fail", "orphan PDF", path.name))
    return findings


def write_reports(root, config, manifest, store):
    groups = reports(root, config, manifest, store)
    archive = root / config["archive_dir"]
    for name, rows in groups.items():
        text = ["<!-- GENERATED by tools/references/refs.py index. -->", "", "# " + name.replace("-", " ").capitalize(), "",
                "%d reference(s). A gap is unverified, never a pass." % len(rows), "", "| Reference | Required work |", "|---|---|"]
        for url, reason in rows:
            text.append("| <%s> | %s |" % (url, reason.replace("|", "\\|").replace("\n", " ")))
        write_bytes(archive / (name + ".md"), ("\n".join(text) + "\n").encode())
    return groups


def add_commands(subparsers):
    for name, handler, help_text in (
        ("migrate-layout", migrate, "Move the legacy Markdown archive into parallel md/pdf trees."),
        ("recover-published", recover, "Recover missing text-store objects from published copies in Docker."),
        ("render", republish, "Publish English reading copies offline, without reacquisition."),
        ("pdf", pdf, "Publish original PDFs, publisher PDFs, or offline rendered Markdown."),
    ):
        parser = subparsers.add_parser(name, help=help_text)
        parser.add_argument("--only", default="")
        parser.add_argument("--limit", type=int)
        parser.add_argument("--force", action="store_true")
        if name == "pdf":
            parser.add_argument("--jobs", type=int, choices=range(1, 5), default=4,
                                help="Bounded independent conversion workers (1-4).")
        parser.set_defaults(handler=handler)
