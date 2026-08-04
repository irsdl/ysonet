"""What kind of thing a reference is.

"Full content" means something different per kind, so the kind decides which
extractor runs and, before that, whether a page belongs in the browser ladder at
all. The measured case: 13 YouTube pages classified as `js-rendered`, which is
true and useless. A video reference is metadata, description and captions; it is
not an article whose body a browser should be waiting for.

Kind is decided from the URL first and the response second, because the URL is
what the archive has before it fetches anything.
"""

import re
from urllib.parse import urlsplit

VIDEO_HOSTS = ("youtube.com", "youtu.be", "vimeo.com", "bilibili.com",
               "youku.com", "dailymotion.com")

SLIDE_HOSTS = ("speakerdeck.com", "slideshare.net", "slides.com")

DOCUMENT_SUFFIXES = {
    ".pdf": "whitepaper",
    ".ppt": "slides", ".pptx": "slides",
    ".doc": "whitepaper", ".docx": "whitepaper",
    ".txt": "code", ".py": "code", ".cs": "code", ".ps1": "code",
    ".json": "code", ".xml": "code", ".yaml": "code", ".yml": "code",
}

CONTENT_TYPE_KINDS = (
    ("application/pdf", "whitepaper"),
    ("presentationml", "slides"),
    ("application/vnd.ms-powerpoint", "slides"),
    ("text/plain", "code"),
    ("image/", "image"),
)

# A repository URL is a package, not a page: the owner/name pair with nothing
# after it. A URL deeper into the tree is a FILE in a repository, which is a
# different thing and is archived as code.
GITHUB_REPO = re.compile(r"^/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")

# github.com/<something>/<something> is NOT always a repository. These first
# segments are GitHub's own pages, and treating them as repositories sent six
# security advisories to `git clone` and failed all six.
GITHUB_RESERVED = frozenset((
    "advisories", "orgs", "topics", "features", "settings", "sponsors",
    "collections", "events", "explore", "marketplace", "notifications",
    "pulls", "issues", "security", "enterprise", "about", "site", "apps",
))


def from_url(url):
    """The kind implied by the address alone, or "" when it is not obvious."""
    parts = urlsplit(url or "")
    host = (parts.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    path = parts.path or "/"

    if any(host == video or host.endswith("." + video) for video in VIDEO_HOSTS):
        return "video"
    if host in SLIDE_HOSTS:
        return "slides"
    if host == "github.com":
        match = GITHUB_REPO.match(path)
        if match and match.group(1).lower() not in GITHUB_RESERVED:
            return "repo"
        if "/advisories/" in path or path.startswith("/advisories"):
            return "advisory"
        if "/issues/" in path or "/pull/" in path or "/discussions/" in path:
            return "article"
        return "code"

    suffix = _suffix(path)
    if suffix in DOCUMENT_SUFFIXES:
        return DOCUMENT_SUFFIXES[suffix]
    if "advisor" in path or "/cve" in path.lower() or host.endswith("zerodayinitiative.com"):
        return "advisory"
    if host.endswith("microsoft.com") and ("/dotnet/" in path or "/powershell/" in path):
        return "vendor-doc"
    return ""


def from_response(url, content_type):
    """Refine the kind once a response has actually been seen."""
    kind = from_url(url)
    if kind:
        return kind
    lowered = (content_type or "").lower()
    for marker, name in CONTENT_TYPE_KINDS:
        if marker in lowered:
            return name
    return "article"


def wants_browser(kind):
    """Whether a walled or script-rendered page of this kind is worth a browser.

    A video page is never worth it: its useful content is metadata and captions,
    which come from the platform rather than from the rendered DOM. Driving a
    browser at one costs 90 seconds to obtain a player.
    """
    return kind not in ("video", "image")


def _suffix(path):
    tail = path.rsplit("/", 1)[-1].lower()
    if "." not in tail:
        return ""
    return "." + tail.rsplit(".", 1)[-1]
