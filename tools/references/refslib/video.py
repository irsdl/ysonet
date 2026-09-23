"""Talks: metadata, description and captions. Never the media file.

A video reference is worth archiving for what was SAID, and that is the caption
track, not 400 MB of H.264. So this fetches the watch page, reads the declared
metadata, and follows the caption track the page itself points at.

It is best-effort by nature: the route depends on a page structure nobody
promised us. When it fails it says why, and the reference goes on the failure
list rather than being recorded as a link with a shrug.
"""

import json
import re
import urllib.parse

from . import extract_doc, htmltext

# The player configuration embedded in a watch page. Both spellings appear.
CAPTION_TRACKS = re.compile(r'"captionTracks"\s*:\s*(\[.*?\])', re.DOTALL)
PLAYER_TITLE = re.compile(r'"title"\s*:\s*\{\s*"simpleText"\s*:\s*"(.*?)"')
SHORT_DESCRIPTION = re.compile(r'"shortDescription"\s*:\s*"((?:[^"\\]|\\.)*)"')
UPLOAD_DATE = re.compile(r'"uploadDate"\s*:\s*"(\d{4}-\d{2}-\d{2})')
AUTHOR = re.compile(r'"author"\s*:\s*"((?:[^"\\]|\\.)*)"')

# The timed-text response is XML, not WebVTT, unless asked otherwise.
TIMED_TEXT = re.compile(r"<text[^>]*>(.*?)</text>", re.DOTALL)


def to_markdown(markup, url, fetcher, ladder=None, transcript="", fallback=None):
    """Convert one video page into Markdown: metadata, description, transcript.

    `fetcher` is injected so tests stay offline and so the caption fetch goes
    through the same paced, cookie-keeping client as everything else.

    `ladder` is the browser, used ONLY when the plain fetch cannot get the
    captions. YouTube stopped serving timed text to a client without a browser
    session - every format answers 200 with a zero-byte body, or 404 - so the
    track has to be requested from inside the page that already holds it.

    `transcript` is json3 timed text ALREADY obtained, by `refs.py transcripts`
    running yt-dlp in a container. It wins over every network route here,
    because it is the only one YouTube still answers and because re-rendering
    then costs no request at all.
    """
    facts = read_metadata(markup, url)
    # A container-retrieved transcript is a complete acquisition in its own
    # right.  The watch-page bytes may later be absent from a different object
    # store, so retain the citation metadata already recorded in the manifest
    # instead of forcing a fresh YouTube request merely to rebuild a heading.
    fallback = fallback or {}
    fallback_authors = fallback.get("authors") or []
    facts["title"] = facts["title"] or fallback.get("title") or ""
    facts["author"] = (facts["author"] or
                       (fallback_authors[0] if fallback_authors else ""))
    facts["published"] = facts["published"] or fallback.get("published") or ""
    facts["description"] = facts["description"] or fallback.get("description") or ""
    track = caption_track(markup)

    out = ["# " + (facts["title"] or url), ""]
    out.append("- Video: <%s>" % url)
    if facts["author"]:
        out.append("- Channel: %s" % facts["author"])
    if facts["published"]:
        out.append("- Published: %s" % facts["published"])
    out.append("- The media file itself is not archived; this is its metadata and transcript.")
    out.append("")

    if facts["description"]:
        out.append("## Description")
        out.append("")
        out.append(facts["description"])
        out.append("")

    # A missing transcript is a GAP, not a failure of the whole reference. The
    # title, channel, date and description are real content and worth keeping,
    # so the file is written and the gap is reported separately. Returning
    # nothing would throw away what was recovered.
    gap = ""
    stored = json3_to_prose(transcript) if transcript else ""
    if stored.strip():
        out.append("## Transcript")
        out.append("")
        out.append("_Retrieved with yt-dlp in a container, which is the only route "
                   "YouTube still answers. Expect transcription errors in type and "
                   "method names._")
        out.append("")
        out.append(stored)
        return "\n".join(out), ""

    if not track:
        gap = "the video page declares no caption track"
    else:
        response = fetcher.get(track["url"])
        body = response.body or b""
        if not (200 <= response.status < 300):
            gap = "the caption endpoint answered http %d" % response.status
        elif not body:
            # Measured 2026-08-03: YouTube answers 200 with a zero-byte body for
            # every format (default, json3, srv3, vtt) unless the request carries
            # a browser session. A plain client cannot get captions any more.
            gap = ("the caption endpoint returned an empty body: YouTube now "
                   "requires a browser session for timed text, so a plain "
                   "fetch cannot retrieve the transcript")
        else:
            transcript = timed_text_to_prose(
                htmltext.decode(body, response.content_type))
            if not transcript.strip():
                gap = "the caption track parsed to no text"
            else:
                out.append("## Transcript")
                out.append("")
                if track["auto"]:
                    out.append("_Auto-generated captions. Expect transcription "
                               "errors, especially in type and method names._")
                    out.append("")
                out.append(transcript)

    # Last resort, and the only one that works for YouTube now: let the page
    # fetch its own caption track.
    if gap and ladder is not None and getattr(ladder, "available", lambda: False)():
        body, _shape, error = ladder.timed_text(
            url, track_url=(track or {}).get("url") or "")
        transcript = json3_to_prose(body) if body else ""
        if transcript.strip():
            gap = ""
            out.append("## Transcript")
            out.append("")
            out.append("_Retrieved through a browser session, which is the only way "
                       "YouTube serves timed text. Expect transcription errors in "
                       "type and method names._")
            out.append("")
            out.append(transcript)
        elif error:
            # Measured 2026-08-04 on this corpus: YouTube refuses timed text to
            # an automation profile by all three routes. A plain fetch gets 404
            # or a zero-byte body; the same fetch made BY the page, with its
            # session and origin, gets a zero-byte body too; and clicking the
            # page's own "Show transcript" opens a panel that spins forever. The
            # caption URL now needs a token the real player generates, so this
            # is a wall rather than a bug to fix here. Say so exactly, because
            # the next person will otherwise spend the same afternoon on it.
            gap = (gap + "; the browser route also failed (" + error + "). "
                   "YouTube now requires a player-generated token on the caption "
                   "URL, so no plain fetch, in-page fetch or transcript panel "
                   "returns it. Only a manual transcript export will cover this")

    if gap:
        out.append("## Transcript")
        out.append("")
        out.append("_Not available: %s. The metadata and description above are "
                   "what could be recovered._" % gap)
    return "\n".join(out), gap


def read_metadata(markup, url):
    """Declared metadata from the watch page."""
    title = _first(PLAYER_TITLE, markup)
    if not title:
        title, _text, _ns = htmltext.read(markup)
        title = re.sub(r"\s*-\s*YouTube$", "", title or "")
    return {
        "title": _unescape(title),
        "author": _unescape(_first(AUTHOR, markup)),
        "published": _first(UPLOAD_DATE, markup),
        "description": _unescape(_first(SHORT_DESCRIPTION, markup)),
        "url": url,
    }


def caption_track(markup):
    """The caption track the page points at, preferring a human-made one."""
    match = CAPTION_TRACKS.search(markup or "")
    if not match:
        return None
    try:
        tracks = json.loads(match.group(1).replace("\\u0026", "&"))
    except ValueError:
        return None

    def rank(track):
        # A human track beats an automatic one; English beats anything else.
        auto = track.get("kind") == "asr"
        language = (track.get("languageCode") or "").lower()
        return (auto, not language.startswith("en"))

    usable = [track for track in tracks if isinstance(track, dict) and track.get("baseUrl")]
    if not usable:
        return None
    best = sorted(usable, key=rank)[0]
    return {"url": _unescape_url(best["baseUrl"]),
            "auto": best.get("kind") == "asr",
            "language": best.get("languageCode") or ""}


def json3_to_prose(body):
    """YouTube's `json3` timed text into readable prose.

    The browser route asks for this format because it is the one that survives a
    track URL with no query string of its own. Shape: events, each carrying
    segments, each carrying a `utf8` run.
    """
    try:
        payload = json.loads(body or "{}")
    except ValueError:
        return ""
    lines = []
    for event in payload.get("events") or []:
        piece = "".join((segment.get("utf8") or "")
                        for segment in (event.get("segs") or []))
        piece = piece.replace("\n", " ").strip()
        if piece and (not lines or lines[-1] != piece):
            lines.append(piece)
    return " ".join(lines)


def timed_text_to_prose(xml):
    """YouTube's timed-text XML into readable prose."""
    import html as html_module

    lines = []
    for piece in TIMED_TEXT.findall(xml or ""):
        text = html_module.unescape(html_module.unescape(piece))
        text = re.sub(r"<[^>]+>", "", text).replace("\n", " ").strip()
        if text and (not lines or lines[-1] != text):
            lines.append(text)
    return " ".join(lines)


def _first(pattern, text):
    match = pattern.search(text or "")
    return match.group(1) if match else ""


def _unescape(text):
    if not text:
        return ""
    try:
        return json.loads('"%s"' % text.replace('"', '\\"'))
    except ValueError:
        return text.replace("\\n", "\n").replace("\\/", "/")


def _unescape_url(url):
    return urllib.parse.unquote(_unescape(url).replace("\\u0026", "&"))
