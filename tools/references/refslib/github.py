"""Read GitHub through its API instead of its JavaScript shell.

Several GitHub pages carry real content and serve almost none of it to a plain
fetch, because the page is a React shell that fills itself in afterwards. They
were reaching the extractor as 139 to 264 characters and failing the content
floor, which is correct behaviour on a document that genuinely is not there.

The content IS available, in a documented public JSON API that needs no
credentials, so the fix is to ask the right endpoint rather than to drive a
browser at a page whose data is one request away. Three shapes are covered,
because they are the same defect:

* **A security advisory** - `/{owner}/{repo}/security/advisories/GHSA-...` and
  the global `/advisories/GHSA-...`. The API returns the summary, the whole
  description in Markdown, severity, the CVE, the affected packages and the
  reference list.
* **A file** - `/{owner}/{repo}/blob/{ref}/{path}`. The source is the document;
  `raw.githubusercontent.com` serves it exactly. A `#L123` fragment is kept as a
  note, because the citation points at a line for a reason.
* **An issue, pull request or discussion** - the body plus the comments, which
  is what a reader of the citation came for.

Rate limit: unauthenticated api.github.com allows 60 requests an hour per
address. That is ample for a corpus with a handful of these, and a refusal is
reported as a refusal - never as "this page has no content".

No token is read from the environment and none is sent. An archive run must
behave the same for every contributor, and a tool that quietly used one person's
credentials would produce results nobody else can reproduce.
"""

import json
import re
from urllib.parse import quote, unquote, urlsplit

API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"

# GitHub asks for this on every API request and changes behaviour without it.
API_HEADERS = {"Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}

ADVISORY = re.compile(r"^/(?:([\w.-]+)/([\w.-]+)/security/advisories|advisories)"
                      r"/(GHSA-[\w-]+)/?$", re.IGNORECASE)
BLOB = re.compile(r"^/([\w.-]+)/([\w.-]+)/blob/([^/]+)/(.+)$")
CONVERSATION = re.compile(r"^/([\w.-]+)/([\w.-]+)/(issues|pull|discussions)/(\d+)/?$")

# How many comments are worth keeping. A long thread is mostly "same here".
MAX_COMMENTS = 20


class NotGitHub(Exception):
    """This URL is not one of the shapes handled here."""


class Unavailable(Exception):
    """The API refused or answered with nothing usable. Reported, never guessed."""


# A blob whose bytes are NOT source text. `_file` wraps what it fetches in a
# fenced code block, which is right for a `.py` and catastrophic for a `.pdf`:
# three browser-security whitepapers were stored as several megabytes of
# `decode("utf-8", "replace")` - a code fence full of replacement characters -
# and every later stage faithfully preserved the damage. These are downloaded as
# bytes by the ordinary document route instead, which knows what a PDF is.
BINARY_BLOB_SUFFIXES = (
    ".pdf", ".ppt", ".pptx", ".doc", ".docx", ".xls", ".xlsx", ".odt", ".odp",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".tar", ".rar",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".svgz",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".woff", ".woff2", ".ttf", ".otf",
    ".exe", ".dll", ".so", ".dylib", ".jar", ".class", ".bin", ".img", ".iso",
)


def raw_url(url):
    """The `raw.githubusercontent.com` URL for a BINARY blob, or "".

    Only for the blobs `_file` must not read as text. A text blob keeps going
    through the API route, which adds the repository, the ref and the cited line
    number - context a raw download does not carry.
    """
    parts = urlsplit(str(url or ""))
    if (parts.hostname or "").lower() not in ("github.com", "www.github.com"):
        return ""
    path = unquote(parts.path or "")
    matched = BLOB.match(path)
    if not matched:
        return ""
    owner, repo, ref, blob_path = matched.groups()
    if not blob_path.lower().endswith(BINARY_BLOB_SUFFIXES):
        return ""
    return "%s/%s/%s/%s/%s" % (RAW, owner, repo, quote(ref, safe=""),
                               quote(blob_path, safe="/"))


def route(url):
    """Which API shape this URL is, or "" when it is an ordinary page."""
    parts = urlsplit(str(url or ""))
    host = (parts.hostname or "").lower()
    if host not in ("github.com", "www.github.com"):
        return ""
    path = unquote(parts.path or "")
    if ADVISORY.match(path):
        return "advisory"
    if BLOB.match(path):
        # A binary blob is not a file the API route can render, so it falls
        # through to the ordinary document route and is fetched as bytes.
        return "" if raw_url(url) else "file"
    if CONVERSATION.match(path):
        return "conversation"
    return ""


def to_markdown(url, fetcher):
    """(markdown, facts) for a GitHub URL the API can answer.

    Raises `NotGitHub` when the URL is not one of the shapes, and `Unavailable`
    when the API declined. Neither is ever turned into an empty document.
    """
    shape = route(url)
    if shape == "advisory":
        return _advisory(url, fetcher)
    if shape == "file":
        return _file(url, fetcher)
    if shape == "conversation":
        return _conversation(url, fetcher)
    raise NotGitHub(url)


def _advisory(url, fetcher):
    owner, repo, ghsa = ADVISORY.match(unquote(urlsplit(url).path)).groups()
    # The global database is tried first and answers for published repository
    # advisories too, so one endpoint covers both spellings of the same page.
    payload = _json("%s/advisories/%s" % (API, ghsa), fetcher, optional=True)
    if payload is None and owner:
        payload = _json("%s/repos/%s/%s/security-advisories/%s" % (API, owner, repo, ghsa),
                        fetcher)
    if payload is None:
        raise Unavailable("the advisory API has no published record for " + ghsa)

    summary = (payload.get("summary") or "").strip()
    description = (payload.get("description") or "").strip()
    if not summary and not description:
        raise Unavailable("the advisory record carries no summary or description")

    lines = ["# " + (summary or ghsa), ""]
    facts = {"title": summary or ghsa, "publisher": "GitHub Advisory Database",
             "published": (payload.get("published_at") or "")[:10], "authors": []}

    detail = [("Advisory", payload.get("ghsa_id") or ghsa),
              ("CVE", payload.get("cve_id") or ""),
              ("Severity", payload.get("severity") or ""),
              ("Published", (payload.get("published_at") or "")[:10]),
              ("Updated", (payload.get("updated_at") or "")[:10])]
    for name, value in detail:
        if value:
            lines.append("- %s: %s" % (name, value))

    affected = _affected(payload)
    if affected:
        lines += ["", "## Affected", ""] + affected
    if description:
        lines += ["", "## Description", "", description]

    references = [item for item in (payload.get("references") or []) if item]
    if references:
        lines += ["", "## References", ""] + ["- <%s>" % item for item in references]
    return "\n".join(lines) + "\n", facts


def _affected(payload):
    rows = []
    for item in payload.get("vulnerabilities") or []:
        package = (item.get("package") or {}).get("name") or ""
        ecosystem = (item.get("package") or {}).get("ecosystem") or ""
        affected = item.get("vulnerable_version_range") or ""
        fixed = item.get("first_patched_version") or ""
        if isinstance(fixed, dict):
            fixed = fixed.get("identifier") or ""
        if not package:
            continue
        row = "- `%s`" % package
        if ecosystem:
            row += " (%s)" % ecosystem
        if affected:
            row += ": %s" % affected
        if fixed:
            row += ", fixed in %s" % fixed
        rows.append(row)
    return rows


def _file(url, fetcher):
    parts = urlsplit(url)
    owner, repo, ref, path = BLOB.match(unquote(parts.path)).groups()
    # Re-encode before requesting. Matching on the decoded path keeps the rules
    # readable, but a repository really does contain files with spaces in their
    # names, and a literal space in the request line is not a request at all:
    # `.NET Remoting.md` failed with "http 0" until it was quoted back.
    response = fetcher.get("%s/%s/%s/%s/%s" % (RAW, owner, repo, quote(ref, safe=""),
                                               quote(path, safe="/")),
                           max_bytes=2 * 1024 * 1024)
    if not (200 <= response.status < 300) or not response.body:
        raise Unavailable("raw.githubusercontent.com answered http %d for %s"
                          % (response.status, path))
    text = response.body.decode("utf-8", "replace")
    name = path.rsplit("/", 1)[-1]
    lines = ["# %s" % name, "",
             "`%s/%s` at `%s`, path `%s`." % (owner, repo, ref[:12], path)]
    # The citation points at a line for a reason, so say which one it was even
    # though the whole file is preserved.
    line = re.match(r"^L(\d+)", parts.fragment or "")
    if line:
        lines.append("")
        lines.append("The citation points at line %s." % line.group(1))
    # A Markdown source can contain fenced code blocks of its own. Wrapping it
    # in another three-backtick fence closes the outer fence at the first inner
    # block and makes the rest of the archived page render as live Markdown.
    # Use a delimiter longer than every backtick run in the source so the raw
    # file remains one inert, readable block.
    longest = max([len(run) for run in re.findall(r"`+", text)] or [0])
    fence = "`" * max(3, longest + 1)
    lines += ["", fence + _language(name), text.rstrip("\n"), fence]
    return "\n".join(lines) + "\n", {"title": "%s/%s: %s" % (owner, repo, path),
                                     "publisher": "GitHub", "published": "",
                                     "authors": [owner]}


def _conversation(url, fetcher):
    owner, repo, shape, number = CONVERSATION.match(unquote(urlsplit(url).path)).groups()
    if shape == "discussions":
        # Discussions are GraphQL only, and this tool sends no credentials.
        raise Unavailable("a GitHub discussion is only served by the GraphQL API, "
                          "which needs a token this tool deliberately does not use")
    endpoint = "%s/repos/%s/%s/%s/%s" % (API, owner, repo,
                                         "pulls" if shape == "pull" else "issues", number)
    payload = _json(endpoint, fetcher)
    if payload is None:
        raise Unavailable("the issue API has no record for %s/%s#%s" % (owner, repo, number))

    title = (payload.get("title") or "").strip() or "%s/%s#%s" % (owner, repo, number)
    author = ((payload.get("user") or {}).get("login")) or ""
    lines = ["# " + title, ""]
    for name, value in (("Repository", "%s/%s" % (owner, repo)),
                        ("Opened by", author),
                        ("Opened", (payload.get("created_at") or "")[:10]),
                        ("State", payload.get("state") or "")):
        if value:
            lines.append("- %s: %s" % (name, value))
    body = (payload.get("body") or "").strip()
    if body:
        lines += ["", "## Body", "", body]

    comments = _json(endpoint.replace("/pulls/", "/issues/") + "/comments",
                     fetcher, optional=True) or []
    kept = [item for item in comments if (item.get("body") or "").strip()][:MAX_COMMENTS]
    if kept:
        lines += ["", "## Comments", ""]
        for item in kept:
            who = ((item.get("user") or {}).get("login")) or "someone"
            when = (item.get("created_at") or "")[:10]
            lines += ["### %s, %s" % (who, when), "", item["body"].strip(), ""]
        if len(comments) > len(kept):
            lines.append("_%d further comment(s) not preserved._"
                         % (len(comments) - len(kept)))
    return "\n".join(lines) + "\n", {"title": title, "publisher": "GitHub",
                                     "published": (payload.get("created_at") or "")[:10],
                                     "authors": [author] if author else []}


def _json(endpoint, fetcher, optional=False):
    """One API call. A refusal is reported as a refusal, never as no content."""
    response = fetcher.get(endpoint, extra_headers=API_HEADERS, max_bytes=4 * 1024 * 1024)
    if response.status == 404 and optional:
        return None
    if response.status in (403, 429):
        raise Unavailable("the GitHub API refused (http %d): unauthenticated requests are "
                          "limited to 60 an hour, so try again later"
                          % response.status)
    if not (200 <= response.status < 300) or not response.body:
        if optional:
            return None
        raise Unavailable("the GitHub API answered http %d" % response.status)
    try:
        return json.loads(response.body.decode("utf-8", "replace"))
    except ValueError:
        raise Unavailable("the GitHub API answered with something that is not JSON")


def _language(name):
    suffix = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return {"cs": "csharp", "py": "python", "ps1": "powershell", "js": "javascript",
            "ts": "typescript", "java": "java", "rb": "ruby", "go": "go",
            "xml": "xml", "json": "json", "yml": "yaml", "yaml": "yaml",
            "md": "markdown", "sh": "bash", "c": "c", "cpp": "cpp",
            "h": "c", "vb": "vbnet", "config": "xml"}.get(suffix, "")
