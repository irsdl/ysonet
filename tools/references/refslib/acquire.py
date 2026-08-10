"""Acquire and convert one reference.

The pipeline for a text document: preserve the exact bytes, extract candidates
from those STORED bytes, choose one on measured evidence, sanitise it, and
record every hash. Extraction never touches the network, so it can be re-run
with a better extractor without re-crawling.

MEDIA POLICY (maintainer decision, 2026-08-03). Binary media - PDF, slide decks,
video - is NOT downloaded. An AI reading the archive can open those at their own
URL, and a local copy of a 30 MB deck earns little. Those references get a full
attribution record and a link, and render at `metadata` depth.

The cost is real and is recorded rather than glossed over: if such a source goes
offline, the archive has the citation and no content, which is the exact case
the archive exists for. `config.json` -> `media_policy` is the switch, so
changing this later is a config edit rather than a code change.

Video was already excluded on separate grounds: the useful part is metadata,
description and captions, none of which is the media file.
"""

from . import boilerplate, dates, extract_html, github, grade as grade_module
from . import htmltext, kinds, meta
from . import sanitise, slugs

# What a candidate has to keep to be believed. A page that survives extraction
# with almost nothing left is a failed extraction, not a short article.
MIN_CONTENT_CHARS = 400

# The loss guard. Below this much probed text the comparison is noise; below
# this share of it, extraction is suspected of eating the article.
LOSS_GUARD_FLOOR = 1000
# Measured across the corpus, the two populations separate cleanly: chrome-heavy
# pages (Veeam, Telerik, Tenable, Stack Overflow) land at 0.36 to 0.48, because
# half a documentation page really is navigation and footer, while genuinely
# broken extractions land at 0.03 to 0.25. A third is the gap between them.
LOSS_GUARD_RATIO = 0.33

# When a slides or whitepaper citation serves an HTML page, this much extracted
# text means the page carries the document rather than merely describing it.
# Measured: the three slide-host pages in this corpus extract to 28,762 to
# 31,482 characters, which is the deck's own text; a true landing page is an
# order of magnitude smaller.
PAGE_IS_THE_DOCUMENT_CHARS = 5000

# A DOCUMENT IS NOT A PROBE. The fetcher's default cap is sized for reading a
# page's head; applied to a whitepaper it silently returns the first 2 MiB of a
# PDF. Seven were stored that way - each exactly 2,097,152 bytes, each still
# starting with %PDF- and so passing every check - and the pages past the cut
# extracted as glyph soup. A 30 MB conference deck is ordinary.
MAX_DOCUMENT_BYTES = 64 * 1024 * 1024

# What lets an extraction past the loss guard on ratio alone. Two fenced blocks
# and this much text is a document with its listings intact, not a stray snippet
# left behind by a rule that ate the prose.
LOSS_GUARD_CODE_BLOCKS = 2
LOSS_GUARD_CODE_CHARS = 1500


class Acquired(object):
    def __init__(self, key, status, record=None, reason="", raw_sha256="", decision=None):
        self.key = key
        self.status = status        # "stored" | "link-only" | "review" | "skipped" | "failed"
        self.record = record or {}
        self.reason = reason
        # Set when a RULE decided the archive keeps no document for this page,
        # so the caller can record why. Without it a broken capture failed
        # silently and never reached the excluded list.
        self.decision = decision
        # Set even when the run FAILED. The bytes are already preserved by then,
        # so losing the hash means re-fetching a page we already hold, and it
        # left 32 objects in the store that nothing pointed at.
        self.raw_sha256 = raw_sha256

    @property
    def ok(self):
        return self.status in ("stored", "link-only")


def media_policy(config):
    policy = (config or {}).get("media_policy") or {}
    return {
        "store_binaries": bool(policy.get("store_binaries", False)),
        "binary_kinds": tuple(policy.get("binary_kinds")
                              or ("whitepaper", "slides", "video", "image")),
    }


def acquire(key, entry, store, fetcher, config, taken_slugs=(), refetch=False,
            replace_imports=False, ladder=None):
    """Acquire one reference from the manifest.

    Returns an `Acquired` carrying the fields `render` needs. Nothing is written
    to disk here except store objects; the manifest and the Markdown are the
    caller's business.
    """
    url = (entry.get("spellings") or [key])[0]
    kind = entry.get("kind") or kinds.from_url(url) or "article"
    health = entry.get("health") or {}
    policy = media_policy(config)

    # A MANUAL IMPORT IS STICKY. Somebody obtained this document by hand
    # precisely because no automated route could, so re-running acquisition can
    # only replace it with the failure that made the import necessary. It did:
    # one `acquire --force` silently overwrote all 18 imports with the same
    # failures they had been imported to fix. Re-importing is the way to change
    # one, and `--replace-imports` is the deliberate escape hatch.
    if ((entry.get("steps") or {}).get("import") or {}).get("result") == "stored" \
            and not replace_imports:
        return Acquired(key, "skipped",
                        reason="kept the hand-imported copy; pass --replace-imports "
                               "to overwrite it with a fetch")

    if kind in ("whitepaper", "slides", "video"):
        return _document(key, url, entry, kind, store, fetcher, taken_slugs, refetch,
                         ladder=ladder)

    if kind in policy["binary_kinds"] and not policy["store_binaries"]:
        return _link_only(key, url, entry, kind, taken_slugs,
                          "media policy: %s is read at its own URL, not mirrored" % kind)

    if kind == "repo":
        return _repository(key, url, entry, store, taken_slugs)

    # A GitHub advisory, file or issue page is a JavaScript shell: these were
    # reaching the extractor as 139 to 264 characters and failing the content
    # floor, which is correct behaviour on a document that is genuinely not
    # there. The content IS there, in a public API one request away.
    if github.route(url):
        return _github(key, url, entry, kind, store, fetcher, taken_slugs)

    if health.get("status") in ("blocked", "js-rendered") and not entry.get("browser_dom_sha256"):
        return Acquired(key, "skipped",
                        reason="unreadable over plain HTTP and no browser DOM stored")

    # A browser DOM already captured for this URL is the acquisition. Fetching
    # again would only reproduce the wall it got past.
    if entry.get("browser_dom_sha256"):
        raw = store.get(entry["browser_dom_sha256"])
        raw_sha = entry["browser_dom_sha256"]
        retrieved_kind = "browser"
        final_url = health.get("final_url") or url
    elif not refetch and entry.get("raw_sha256") and store.has(entry["raw_sha256"]):
        # Already preserved. Extraction reads STORED bytes, never a live page,
        # which is what makes it repeatable: fixing the extractor and
        # re-extracting 500 references is an offline pass in seconds rather than
        # a second crawl. It also guarantees the re-run describes exactly the
        # document that was preserved, not whatever the site serves today.
        raw = store.get(entry["raw_sha256"])
        raw_sha = entry["raw_sha256"]
        retrieved_kind = (entry.get("steps", {}).get("acquire", {}) or {}).get(
            "retrieved_kind") or "stored"
        final_url = health.get("final_url") or url
    else:
        response = fetcher.get(url)
        if not (200 <= response.status < 300) or not response.body:
            return Acquired(key, "failed",
                            reason="http %d on acquisition" % response.status)
        raw = response.body
        raw_sha = store.put(raw)
        retrieved_kind = "live"
        final_url = response.url

    markup = htmltext.decode(raw if isinstance(raw, bytes) else raw.encode("utf-8"),
                             _content_type(entry))
    cleaned = sanitise.sanitise_html(markup)
    candidates = extract_html.candidates(cleaned.text, base_url=final_url)
    chosen, why = choose(candidates)
    if chosen is None or chosen.metrics["chars"] < MIN_CONTENT_CHARS:
        # A JavaScript-built page that a plain fetch could not fill in is not a
        # failure of the document, it is a failure of the fetch. Say which, so
        # the browser pass can pick it up instead of a human wondering.
        needs_browser = not entry.get("browser_dom_sha256")
        return Acquired(key, "needs-browser" if needs_browser else "failed",
                        reason="extraction produced %d characters, below the floor"
                               % (chosen.metrics["chars"] if chosen else 0),
                        raw_sha256=raw_sha)

    # The loss guard. The health probe already measured how much visible text
    # this page has, so extraction losing half of it is a boilerplate rule
    # eating the article rather than a short document. Fail to REVIEW rather
    # than publishing a gutted page: a silent loss is precisely the failure this
    # archive exists to undo, and it is invisible unless something compares.
    # Measure the BEST candidate, not the chosen one. Precision keeping less
    # than the probe saw is precision doing its job: a Stack Overflow page is
    # mostly sidebar, and 3,140 characters of answer out of 20,032 of page is
    # correct. The failure worth catching is every candidate coming out small,
    # which means something upstream ate the article rather than the extractor
    # discriminating. Comparing the chosen candidate queued 28 good pages.
    probe_chars = int(health.get("text_length") or 0)
    widest = max(item.metrics["chars"] for item in candidates)
    # CODE IS EVIDENCE THE DOCUMENT WAS FOUND, and it outranks the ratio. A
    # Stack Overflow question page is 20% article by text and 80% sidebar,
    # related questions and footer: the extraction kept 4,045 characters
    # carrying all three code blocks out of 19,983, which is the extractor doing
    # its job and not a boilerplate rule eating the article. This is the same
    # "code beats length" rule the grading uses, applied one step earlier.
    kept_the_code = (chosen.metrics["code_blocks"] >= LOSS_GUARD_CODE_BLOCKS
                     and chosen.metrics["chars"] >= LOSS_GUARD_CODE_CHARS)
    if not kept_the_code \
            and probe_chars > LOSS_GUARD_FLOOR and widest < probe_chars * LOSS_GUARD_RATIO:
        # If a browser has not seen this page yet, that is the likelier cause
        # than a bad extractor: hackmd keeps its source in a hidden element, so
        # sanitisation correctly removes it and the readable article only exists
        # once JavaScript has run. Route it rather than parking it.
        outcome = "review" if entry.get("browser_dom_sha256") else "needs-browser"
        return Acquired(key, outcome,
                        reason="every candidate kept under a third of the %d characters "
                               "the probe saw (widest %d)" % (probe_chars, widest),
                        raw_sha256=raw_sha)

    # The publisher's furniture, trimmed inward from the edges. Container-level
    # chrome removal cannot see a call to action that sits in the article's own
    # flow with no class worth naming, and 111 files end with one.
    trimmed, furniture = boilerplate.trim(chosen.markdown)
    body = sanitise.sanitise_text(trimmed)
    facts = meta.read(markup, final_url)
    title = facts["title"] or _title_from(chosen.markdown) or url
    # A date the page did not DECLARE is often still in the article, the byline
    # or the URL. Only fills when metadata gave none, so a declared date wins.
    published = facts["published"] or dates.recover_published(body.text, url)

    # A challenge page can answer a health probe as a document and serve a wall
    # when the content is fetched. One was archived as though it were the paper.
    # The same check now also catches the BROWSER answering instead of the site,
    # and a page whose whole body is its consent gate.
    verdict = decide(body.text, url)
    if verdict.outcome == "skip":
        return Acquired(key, "failed", reason=verdict.reason, raw_sha256=raw_sha,
                        decision=verdict.as_dict())

    content_sha = store.put_text(body.text)

    record = {
        # A slug is pinned once it exists. It is the file name, the link target
        # and the archive identity at once, so a better title turning up on a
        # re-run must not rename the file. It also stops suffix creep: counting
        # an entry's OWN slug as taken made every --force run append the next
        # number, so five files became "...-2" and would have become "-3".
        "slug": slugs.pinned(entry.get("slug")) or slugs.build(
            title, facts["publisher"], dates.slug_year(published, title), taken=taken_slugs),
        "title": title,
        "authors": facts["authors"],
        "publisher": facts["publisher"],
        "published": published,
        "licence": facts["licence"],
        "language": (facts["language"] or "").split("_")[0][:5],
        "kind": kind,
        "original_url": url,
        "canonical_url": final_url if final_url != url else "",
        "also_at": entry.get("also_at") or [],
        "retrieved_kind": retrieved_kind,
        "retrieved_from": final_url,
        "snapshot": health.get("snapshot") or "",
        "raw_sha256": raw_sha,
        "content_sha256": content_sha,
        "cited_by": entry.get("cited_by") or [],
        "quality": chosen.metrics,
        "extraction": {"chosen": chosen.name, "why": why,
                       "candidates": [item.as_dict() for item in candidates]},
        "sanitised": sorted(set(cleaned.removed + body.removed)),
        "boilerplate": furniture,
        "injection_markers": sorted(set(cleaned.markers + body.markers)),
        "depth": "full",
        "depth_reason": "default",
        "grade": verdict.folder,
        "decision": verdict.as_dict(),
    }
    return Acquired(key, "stored", record)


def decide(markdown, url, content_gap="", complete=False):
    """What the archive does with this document, and why.

    One call point for every acquisition path, so the folder, the skip and the
    recorded reason can never disagree with each other. A MAINTAINER decision is
    not consulted here: it is honoured by the caller BEFORE anything is fetched,
    because "we keep no document for this URL" should not cost a request.
    """
    return grade_module.classify(markdown, url=url, content_gap=content_gap,
                                 complete=complete)


def choose(candidates):
    """Pick an extraction candidate on measured evidence.

    Precision wins when it is not obviously lossy, because it is the one that
    excludes site furniture. It loses when it dropped code blocks the wider
    candidates kept, which is the failure this archive exists to undo: a page
    whose payload listings vanished still reads fine as prose.
    """
    if not candidates:
        return None, "no candidate"
    best_code = max(item.metrics["code_blocks"] for item in candidates)
    best_chars = max(item.metrics["chars"] for item in candidates)

    for item in candidates:
        if item.name != "precision":
            continue
        if item.metrics["code_blocks"] < best_code:
            break                                  # lost code: fall through
        if item.metrics["chars"] < best_chars * 0.5:
            break                                  # lost half the text: fall through
        return item, "precision kept the code blocks and most of the text"

    ranked = sorted(candidates,
                    key=lambda item: (item.metrics["code_blocks"], item.metrics["chars"]),
                    reverse=True)
    return ranked[0], "%s kept the most code blocks and text" % ranked[0].name


def _github(key, url, entry, kind, store, fetcher, taken_slugs):
    """A GitHub page whose content lives in the API rather than the HTML.

    The raw API answer is preserved as the bytes, so a better renderer later is
    an offline re-run like every other route here.
    """
    try:
        body, facts = github.to_markdown(url, fetcher)
    except github.Unavailable as error:
        # A REFUSAL IS NOT A REASON TO LOSE THE DOCUMENT. The unauthenticated
        # API allows 60 requests an hour; hitting that limit made ten
        # references fail at once and the next index run swept every one of
        # their files. If the content is already in the store, re-render from
        # it and say why, which costs no request and keeps the archive whole.
        held = entry.get("content_sha256")
        if held and store.has(held):
            body, facts = store.get_text(held), {
                "title": entry.get("title") or "", "publisher": entry.get("publisher") or "",
                "published": entry.get("published") or "", "authors": entry.get("authors") or []}
        else:
            return Acquired(key, "failed", reason=str(error))

    cleaned = sanitise.sanitise_text(body)
    # The API returns the whole record or refuses, so a short answer here is a
    # short record rather than something still to be fetched.
    verdict = decide(cleaned.text, url, complete=True)
    if verdict.outcome == "skip":
        return Acquired(key, "failed", reason=verdict.reason,
                        decision=verdict.as_dict())
    raw_sha = store.put_text(body)
    content_sha = store.put_text(cleaned.text)
    title = facts["title"] or entry.get("cited_title") or url
    published = facts["published"] or dates.recover_published(cleaned.text, url)
    return Acquired(key, "stored", {
        "slug": slugs.pinned(entry.get("slug")) or slugs.build(
            title, facts["publisher"], dates.slug_year(published, title),
            taken=taken_slugs),
        "title": title,
        "authors": facts["authors"],
        "publisher": facts["publisher"],
        "published": published,
        "licence": meta.licence_for(url),
        "kind": kind,
        "original_url": url,
        "canonical_url": "",
        "also_at": entry.get("also_at") or [],
        "retrieved_kind": "github-api",
        "retrieved_from": url,
        "snapshot": "",
        "raw_sha256": raw_sha,
        "content_sha256": content_sha,
        "cited_by": entry.get("cited_by") or [],
        "quality": {"chars": len(cleaned.text)},
        "sanitised": cleaned.removed,
        "injection_markers": cleaned.markers,
        "depth": "full",
        "depth_reason": "default",
        "grade": verdict.folder,
        "decision": verdict.as_dict(),
    })


def _repository(key, url, entry, store, taken_slugs):
    """A repository is a package: pinned commit, documentation only, no execution."""
    from . import repo as repo_module

    try:
        package = repo_module.acquire(url, store.root)
    except Exception as error:
        return Acquired(key, "failed",
                        reason="repository: %s" % str(error)[:160])
    if not package.materials:
        return Acquired(key, "review",
                        reason="repository %s has no documentation to preserve at %s"
                               % (package.full_name, package.commit[:12]))

    body = repo_module.to_markdown(package, url)
    from . import sanitise as sanitise_module
    cleaned = sanitise_module.sanitise_text(body)
    # A clone reads the whole repository, so a short README is a short record
    # rather than something still to be fetched.
    verdict = decide(cleaned.text, url, complete=True)
    content_sha = store.put_text(cleaned.text)
    health = entry.get("health") or {}
    title = slugs.readable_title(
        entry.get("cited_title") or health.get("title") or package.full_name, url)
    return Acquired(key, "stored", {
        "slug": slugs.pinned(entry.get("slug")) or slugs.build(package.full_name, "github", "",
                                                 taken=taken_slugs),
        "title": title,
        "authors": [package.owner],
        "publisher": "GitHub",
        "published": "",
        "licence": "see the repository",
        "kind": "repo",
        "original_url": url,
        "canonical_url": "",
        "also_at": entry.get("also_at") or [],
        "retrieved_kind": "git",
        "retrieved_from": url,
        "snapshot": "",
        "commit": package.commit,
        "content_sha256": content_sha,
        "cited_by": entry.get("cited_by") or [],
        "quality": {"chars": len(cleaned.text), "documents": len(package.materials)},
        "sanitised": cleaned.removed,
        "injection_markers": cleaned.markers,
        "depth": "full",
        "depth_reason": "default",
        "grade": verdict.folder,
        "decision": verdict.as_dict(),
    })


def _document(key, url, entry, kind, store, fetcher, taken_slugs, refetch, ladder=None):
    """A PDF, a slide deck or a talk, converted to Markdown like everything else.

    The maintainer's decision on 2026-08-03: these must end up as Markdown, and
    anything that genuinely cannot be converted goes on the FAILURE list with a
    reason rather than being recorded as a link. The media file itself is still
    never stored: for a video that means the caption track, not the video.
    """
    from . import extract_doc, video as video_module

    health = entry.get("health") or {}
    final_url = health.get("final_url") or url

    if not refetch and entry.get("raw_sha256") and store.has(entry["raw_sha256"]):
        raw = store.get(entry["raw_sha256"])
        raw_sha = entry["raw_sha256"]
        retrieved_kind = "stored"
    else:
        response = fetcher.get(url, max_bytes=MAX_DOCUMENT_BYTES)
        if not (200 <= response.status < 300) or not response.body:
            return Acquired(key, "failed",
                            reason="http %d fetching the %s" % (response.status, kind))
        raw = response.body
        raw_sha = store.put(raw)
        retrieved_kind = "live"
        final_url = response.url

    # The KIND says what the citation is; the BYTES say what arrived. A
    # speakerdeck or slideshare URL is an HTML page ABOUT a deck, and a Wayback
    # replay of a PDF is an HTML wrapper. Both were failing as "not a PDF" when
    # the right answer was to read them as the web pages they are.
    if kind in ("whitepaper", "slides") and not _looks_like_pdf(raw) \
            and not _looks_like_pptx(raw):
        return _html_document(key, url, entry, kind, raw, raw_sha, retrieved_kind,
                              final_url, store, taken_slugs)

    # The reading list often links a paper as plain "[Whitepaper]", which is
    # the format and not the document. Read the URL when that happens.
    title = slugs.readable_title(entry.get("cited_title") or health.get("title"), url) or url
    gap = ""
    try:
        if kind == "video":
            markup = htmltext.decode(raw, "text/html")
            # A transcript obtained earlier by the container route is used
            # first: it is the only one YouTube still answers, and reading it
            # from the store makes a re-render offline.
            stored_transcript = ""
            if entry.get("transcript_sha256") and store.has(entry["transcript_sha256"]):
                stored_transcript = store.get_text(entry["transcript_sha256"])
            body, gap = video_module.to_markdown(markup, url, fetcher, ladder=ladder,
                                                 transcript=stored_transcript)
            facts = video_module.read_metadata(markup, url)
            title = facts["title"] or title
            authors = [facts["author"]] if facts["author"] else []
            published = facts["published"]
            publisher = "YouTube" if "youtu" in url else ""
        elif _looks_like_pptx(raw):
            body = extract_doc.pptx_to_markdown(raw, title)
            authors, published, publisher = [], "", ""
        else:
            # A cut-off PDF still starts with %PDF- and still yields text for
            # the pages before the cut, so it has to be refused here rather than
            # discovered later as glyph soup.
            cut = extract_doc.looks_truncated(raw)
            if cut:
                return Acquired(key, "failed", reason=cut, raw_sha256=raw_sha)
            body = extract_doc.pdf_to_markdown(raw, title)
            authors, published, publisher = [], "", ""
    except extract_doc.Unconvertible as error:
        # This is the failure list the maintainer asked for. It names the reason
        # so the next attempt can be a different route rather than a re-run.
        return Acquired(key, "failed",
                        reason="%s could not be converted: %s" % (kind, error),
                        raw_sha256=raw_sha)

    cleaned = sanitise.sanitise_text(body)
    if len(cleaned.text.strip()) < MIN_CONTENT_CHARS:
        return Acquired(key, "failed",
                        reason="%s converted to only %d characters, below the floor"
                               % (kind, len(cleaned.text.strip())),
                        raw_sha256=raw_sha)
    verdict = decide(cleaned.text, url, content_gap=gap)
    if verdict.outcome == "skip":
        return Acquired(key, "failed", reason=verdict.reason, raw_sha256=raw_sha,
                        decision=verdict.as_dict())
    content_sha = store.put_text(cleaned.text)
    published = published or dates.recover_published(cleaned.text, url)

    return Acquired(key, "stored", {
        "slug": slugs.pinned(entry.get("slug")) or slugs.build(title, publisher,
                                                 dates.slug_year(published, title), taken=taken_slugs),
        "title": title,
        "authors": authors,
        "publisher": publisher,
        "published": published,
        "licence": meta.licence_for(url),
        "kind": kind,
        "original_url": url,
        "canonical_url": final_url if final_url != url else "",
        "also_at": entry.get("also_at") or [],
        "retrieved_kind": retrieved_kind,
        "retrieved_from": final_url,
        "snapshot": health.get("snapshot") or "",
        "raw_sha256": raw_sha,
        "content_sha256": content_sha,
        "cited_by": entry.get("cited_by") or [],
        "quality": {"chars": len(cleaned.text)},
        "sanitised": cleaned.removed,
        "injection_markers": cleaned.markers,
        "depth": "full",
        "depth_reason": "default",
        "grade": verdict.folder,
        "decision": verdict.as_dict(),
        # What is MISSING from an otherwise good file. A talk whose transcript
        # could not be fetched is still worth its metadata and description, but
        # the reader has to be told what is not here.
        "content_gap": gap,
    })


def _looks_like_pdf(data):
    return bytes(data[:5]).startswith(b"%PDF")


def _html_document(key, url, entry, kind, raw, raw_sha, retrieved_kind, final_url,
                   store, taken_slugs):
    """A citation whose bytes turned out to be a web page, read as one."""
    markup = htmltext.decode(raw, "text/html")
    cleaned = sanitise.sanitise_html(markup)
    candidates = extract_html.candidates(cleaned.text, base_url=final_url)
    chosen, why = choose(candidates)
    if chosen is None or chosen.metrics["chars"] < MIN_CONTENT_CHARS:
        return Acquired(key, "failed", raw_sha256=raw_sha,
                        reason="the URL served a web page rather than a %s, and that "
                               "page extracted to only %d characters"
                               % (kind, chosen.metrics["chars"] if chosen else 0))
    trimmed, furniture = boilerplate.trim(chosen.markdown)
    body = sanitise.sanitise_text(trimmed)
    content_sha = store.put_text(body.text)
    facts = meta.read(markup, final_url)
    title = facts["title"] or slugs.readable_title(entry.get("cited_title"), url) or url
    published = facts["published"] or dates.recover_published(body.text, url)
    verdict = decide(body.text, url)
    if verdict.outcome == "skip":
        return Acquired(key, "failed", reason=verdict.reason, raw_sha256=raw_sha,
                        decision=verdict.as_dict())
    return Acquired(key, "stored", {
        "slug": slugs.pinned(entry.get("slug")) or slugs.build(title, facts["publisher"],
                                                 dates.slug_year(published, title),
                                                 taken=taken_slugs),
        "title": title,
        "authors": facts["authors"],
        "publisher": facts["publisher"],
        "published": published,
        "licence": facts["licence"],
        "language": (facts["language"] or "").split("_")[0][:5],
        "kind": kind,
        "original_url": url,
        "canonical_url": final_url if final_url != url else "",
        "also_at": entry.get("also_at") or [],
        "retrieved_kind": retrieved_kind,
        "retrieved_from": final_url,
        "snapshot": (entry.get("health") or {}).get("snapshot") or "",
        "raw_sha256": raw_sha,
        "content_sha256": content_sha,
        "cited_by": entry.get("cited_by") or [],
        "quality": chosen.metrics,
        "extraction": {"chosen": chosen.name, "why": why,
                       "candidates": [item.as_dict() for item in candidates]},
        "sanitised": sorted(set(cleaned.removed + body.removed)),
        "boilerplate": furniture,
        "injection_markers": sorted(set(cleaned.markers + body.markers)),
        "depth": "full",
        "depth_reason": "default",
        "grade": verdict.folder,
        "decision": verdict.as_dict(),
        # A GAP means something is MISSING, and on a slide host it usually is
        # not: SlideShare and SpeakerDeck publish the whole deck's text on the
        # page, and three decks here extracted to 28,762, 30,914 and 31,482
        # characters while being recorded as "we only have a page about it".
        # Above the floor the page IS the document; below it, it really is a
        # landing page and the gap is true.
        "content_gap": ("" if chosen.metrics["chars"] >= PAGE_IS_THE_DOCUMENT_CHARS else
                        "the citation points at a page about this %s rather than "
                        "the file itself" % kind),
    })


def _looks_like_pptx(data):
    """A .pptx is a zip whose first entry names the OpenXML content types."""
    return data[:2] == b"PK" and b"ppt/" in data[:4096]


def _link_only(key, url, entry, kind, taken_slugs, reason):
    """A reference the archive records but does not mirror."""
    health = entry.get("health") or {}
    title = slugs.readable_title(entry.get("cited_title") or health.get("title"), url) or url
    record = {
        "slug": slugs.pinned(entry.get("slug")) or slugs.build(title, "", "", taken=taken_slugs),
        "title": title,
        "authors": [],
        "publisher": "",
        "published": "",
        "licence": meta.licence_for(url),
        "kind": kind,
        "original_url": url,
        "canonical_url": health.get("final_url") or "",
        "also_at": entry.get("also_at") or [],
        "retrieved_kind": "link-only",
        "retrieved_from": url,
        "snapshot": health.get("snapshot") or "",
        "cited_by": entry.get("cited_by") or [],
        "depth": "metadata",
        "depth_reason": "media-policy",
        "grade": grade_module.RECORD,
        # A link-only reference is a record by construction: the document is
        # deliberately not mirrored, so there is nothing to classify.
        "decision": {"outcome": "archive", "class": grade_module.RECORD,
                     "reason": reason, "by": "rule:media-policy"},
        "media_note": reason,
    }
    return Acquired(key, "link-only", record, reason)


def _content_type(entry):
    return ((entry.get("health") or {}).get("content_type")) or "text/html"


def _title_from(markdown):
    for line in (markdown or "").splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return ""
