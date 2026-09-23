"""Acquire publisher PDF copies and inert figures before offline printing."""
from pathlib import Path
from urllib.parse import urlsplit

from . import fetcher, images, isolation, layout, linked_documents, manifest as state, preservation


def papers(args):
    root, config, manifest, store = preservation.context()
    client = fetcher.Fetcher(timeout=args.timeout, per_host_gap=args.gap)
    stored = failed = 0
    rows = preservation.selected(manifest, args.only, args.limit)
    if args.from_url and (not args.only or len(rows) != 1):
        raise ValueError("--from-url requires --only matching exactly one reference")
    discovered = {}
    discovery_errors = {}
    jobs = []
    for key, entry in rows:
        path = layout.path(root, config, entry)
        if not path.exists() or preservation.choose_pdf(entry, store)[0] != "markdown":
            continue
        raw = entry.get("raw_sha256")
        jobs.append({"key": key, "text": path.read_text(encoding="utf-8"),
                     "raw": store.get(raw) if store.has(raw) else b""})
    for offset in range(0, len(jobs), 20):
        batch = jobs[offset:offset + 20]
        candidates = isolation.call("reading.paper_candidates", batch)
        if len(candidates) != len(batch) or {item["key"] for item in candidates} != {item["key"] for item in batch}:
            raise ValueError("paper discovery identity mismatch")
        discovered.update({item["key"]: item["url"] for item in candidates})
        discovery_errors.update({item["key"]: item["error"] for item in candidates if item.get("error")})
        print("Checked publisher PDF links for %d/%d documents." % (min(offset + 20, len(jobs)), len(jobs)), flush=True)
    for key, entry in rows:
        path = layout.path(root, config, entry)
        if not path.exists():
            continue
        if preservation.choose_pdf(entry, store)[0] == "original-pdf":
            continue
        held = entry.get("paper") or {}
        if store.has(held.get("sha256")) and not args.force:
            continue
        original_pdf = urlsplit(key).path.lower().endswith(".pdf")
        url = args.from_url or discovered.get(key) or ""
        if not url:
            manifest.record(key, "paper-search", result="failed" if key in discovery_errors else "none-linked",
                            reason=discovery_errors.get(key) or "No unambiguous same-document PDF in the stored page; live publisher/author search may find one.")
            continue
        try:
            from . import github
            target = github.raw_url(url) or url
            response = client.get(target, max_bytes=64 * 1024 * 1024)
            if response.status != 200 or not response.body.startswith(b"%PDF-"):
                raise ValueError("publisher link did not return a PDF")
            pages = isolation.call("pdf_info", response.body, text=False)
            if not 1 <= pages <= 500:
                raise ValueError("invalid PDF page count")
            if original_pdf and not args.from_url:
                entry["raw_sha256"] = store.put(response.body)
            entry["paper"] = {"url": url, "final_url": response.url,
                              "sha256": store.put(response.body), "pages": pages,
                              "retrieved_utc": state.utc_now(),
                              "identity": "operator-selected" if args.from_url else "publisher-linked"}
            manifest.record(key, "paper", result="stored", url=url, sha256=entry["paper"]["sha256"])
            stored += 1
            print("Publisher PDF: " + entry["slug"], flush=True)
        except Exception as error:
            failed += 1
            manifest.record(key, "paper-attempt", result="failed", reason=str(error)[:240])
        manifest.save()
    manifest.save()
    print("Publisher PDFs: %d stored, %d failed." % (stored, failed))
    return 1 if failed else 0


def figures(args):
    from concurrent.futures import ThreadPoolExecutor
    root, config, manifest, store = preservation.context()
    client = fetcher.Fetcher(timeout=args.timeout, per_host_gap=args.gap)
    kept = failed = remaining = 0
    def capture(row):
        key, entry = row
        if preservation.choose_pdf(entry, store)[0] != "markdown":
            return key, None
        path = layout.path(root, config, entry)
        if not path.is_file():
            return key, None
        targets = images.urls_in(path.read_text(encoding="utf-8"))
        records = {url: item for url, item in (entry.get("images") or {}).items() if url in targets}
        captured = refused = 0
        total = sum(item.get("bytes", 0) for item in records.values() if store.has(item.get("sha256")))
        bound = 500 if entry.get("kind") == "slides" else images.MAX_IMAGES_PER_DOCUMENT
        for target in targets[:bound]:
            previous = records.get(target) or {}
            if store.has(previous.get("sha256")) and not args.force:
                continue
            if previous.get("reason") and not args.force and not getattr(args, "retry_missing", False):
                continue
            try:
                if total >= images.MAX_EMBEDDED_BYTES:
                    raise ValueError("embedded image budget reached")
                url = images.resolve(target, entry.get("canonical_url") or key, entry.get("commit") or "")
                if not url:
                    raise ValueError("image has no public source URL")
                response = client.get(url, max_bytes=images.MAX_SOURCE_BYTES)
                if response.status != 200:
                    raise ValueError("image HTTP status %d" % response.status)
                clean, width, height = images.sanitise(response.body)
                if total + len(clean) > images.MAX_EMBEDDED_BYTES:
                    raise ValueError("embedded image budget reached")
                records[target] = {"sha256": store.put(clean), "bytes": len(clean),
                                   "width": width, "height": height}
                total += len(clean)
                captured += 1
            except Exception as error:
                refused += 1
                if not store.has(previous.get("sha256")):
                    records[target] = {"reason": str(error)[:180]}
        return key, (records, len(targets), captured, refused)
    # Parsing and retrieval are isolated; only the controller records results.
    with ThreadPoolExecutor(max_workers=getattr(args, "jobs", 4)) as pool:
        for key, result in pool.map(capture, preservation.selected(manifest, args.only, args.limit)):
            if result is None:
                continue
            records, count, captured, refused = result
            entry = manifest.data["urls"][key]
            entry["images"] = records
            kept += captured
            failed += refused
            remaining += sum(not store.has(item.get("sha256")) for item in records.values())
            bound = 500 if entry.get("kind") == "slides" else images.MAX_IMAGES_PER_DOCUMENT
            if count > bound:
                entry["figure_gap"] = "%d figures exceed the per-document capture bound" % (count - bound)
            else:
                entry.pop("figure_gap", None)
            manifest.record(key, "images", result="checked", targets=count,
                            preserved=sum(store.has(item.get("sha256")) for item in records.values()))
            manifest.save()
            if count:
                print("Figures: %s (%d captured, %d unavailable)" % (entry["slug"], captured, refused), flush=True)
    print("Figures: %d newly preserved, %d unavailable (%d failed attempts this run)." % (kept, remaining, failed))
    return 1 if remaining else 0


def add_commands(subparsers):
    for name, handler in (("papers", papers), ("images", figures)):
        parser = subparsers.add_parser(name, help=handler.__doc__ or "Preserve publisher PDF copies or figures.")
        parser.add_argument("--only", default="")
        parser.add_argument("--limit", type=int)
        parser.add_argument("--force", action="store_true")
        parser.add_argument("--timeout", type=int, default=30)
        parser.add_argument("--gap", type=float, default=0.5)
        if name == "papers":
            parser.add_argument("--from-url", default="")
        else:
            parser.add_argument("--jobs", type=int, choices=range(1, 5), default=4)
            parser.add_argument("--retry-missing", action="store_true", help="Retry previously unavailable figures while keeping successful captures.")
        parser.set_defaults(handler=handler)
