"""The sandbox for data collection this tool will not do in-process.

ONE CONTAINER, several jobs. Everything here shares a property: it is either
third-party code the archive would otherwise run on this machine, or a fetch
that deliberately relaxes something the in-process client must never relax.
Keeping both in one place means the in-process fetcher stays strict, the
third-party code stays contained, and there is a single set of container rules
to read rather than one per tool.

What lives here today:

* **`captions`** - `yt-dlp`, for a talk's transcript.
* **`fetch_insecure`** - `curl` WITHOUT certificate verification, for a source
  whose certificate has expired. The maintainer decided on 2026-08-04 that this
  is acceptable for collecting a public document. It lives here rather than in
  the fetcher so that "our client always verifies" stays true: the exception is
  a different process, in a container, and cannot be reached by accident.
* **`pdf_page_images`** - `pdftoppm`, rendering a PDF whose text layer is
  unreadable into one image per page, so a reader can be shown the pages.

Original note, on why the first of these needed a container at all:

WHY A CONTAINER. These are the places the archive runs code that is not this
repository's. `yt-dlp` is a large, fast-moving project that exists to keep up
with a hostile platform; `pdftoppm` is a C parser fed documents chosen by
somebody else. Running either directly would give it this machine, this checkout
and the content store; running it in a container gives it a throwaway directory
and nothing else. The maintainer asked for exactly this, and it is the right
call whatever a tool's reputation.

WHY IT IS NEEDED AT ALL. Measured 2026-08-04: YouTube refuses timed text by
every route this tool owns. A plain fetch gets http 404 or a zero-byte body; the
same fetch made BY the page, with its session and origin, gets a zero-byte body;
and the page's own "Show transcript" opens a panel that spins forever. The
caption URL now needs a token the real player generates. `yt-dlp` asks a
different player client that still answers, which is why 13 talks in this corpus
have transcripts again.

WHAT THE CONTAINER GETS, and nothing more:

* one throwaway output directory, the only writable mount;
* no repository, no content store, no home directory, no environment variables;
* a read-only root filesystem with a small no-exec tmpfs for scratch;
* every capability dropped, no new privileges, a memory and process cap;
* a non-root user inside.

It does get the NETWORK, because fetching is the job. Nothing it downloads is
executed: the output is JSON that this module parses.

OPTIONAL BY DESIGN. No Docker, or no image, means a clear skip with a reason,
never a failure and never a silent empty transcript.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile

# Pinned. The base image is pinned by DIGEST so a rebuild cannot silently become
# a different image, and yt-dlp by version so a run is reproducible. YouTube
# breaks these tools regularly, so expect to bump YT_DLP when a fetch starts
# failing - that is a deliberate, visible edit rather than a moving tag.
BASE_IMAGE = ("python:3.12-alpine@sha256:"
              "6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df")
YT_DLP = "2026.07.04"
IMAGE = "ysonet-refs-toolbox:" + YT_DLP

# `curl` for the certificate exception and `poppler-utils` for `pdftoppm`. Their
# versions come from the pinned base image's package repository rather than
# being pinned themselves: pinning an apk version breaks the build the moment
# that repository moves on, and the digest pin already fixes the distribution
# release. A stated limit rather than an oversight.
DOCKERFILE = """FROM %s
RUN apk add --no-cache curl poppler-utils \\
 && pip install --no-cache-dir "yt-dlp==%s" \\
 && adduser -D -u 10001 fetcher
USER fetcher
""" % (BASE_IMAGE, YT_DLP)

# What the container may spend. A talk's caption track is a few hundred KB, so
# these are generous; they exist to bound a runaway, not to tune throughput.
MEMORY = "512m"
PIDS = "256"
TIMEOUT = 900

RUN_ARGS = (
    "--rm",
    "--network", "bridge",
    "--read-only",
    "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--memory", MEMORY,
    "--pids-limit", PIDS,
)

# Captions only, never the media. `--skip-download` is what keeps a 400 MB video
# off this machine; the rest asks for English, manual first then automatic.
YT_DLP_ARGS = (
    "--skip-download",
    "--write-subs",
    "--write-auto-subs",
    "--sub-langs", "en.*",
    "--sub-format", "json3",
    "--no-playlist",
    "--no-progress",
    "--ignore-errors",
    "-o", "%(id)s",
    "-P", "/out",
)

VIDEO_ID = re.compile(r"(?:v=|youtu\.be/|/embed/|/shorts/)([A-Za-z0-9_-]{6,})")


class Unavailable(Exception):
    """No container runtime, or the image could not be built. Reported, never guessed."""


def video_id(url):
    """The YouTube id in this URL, or ""."""
    match = VIDEO_ID.search(str(url or ""))
    return match.group(1) if match else ""


def available():
    """True when a container runtime is present and answering."""
    if not shutil.which("docker"):
        return False
    try:
        done = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        return done.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def ensure_image(log=None):
    """Build the pinned image if it is not present. Returns the image tag."""
    if not available():
        raise Unavailable("no container runtime: install Docker, or run with --no-transcripts")
    have = subprocess.run(["docker", "image", "inspect", IMAGE],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if have.returncode == 0:
        return IMAGE
    if log:
        log("building %s (yt-dlp %s, pinned base image)" % (IMAGE, YT_DLP))
    build = subprocess.run(["docker", "build", "-t", IMAGE, "-"],
                           input=DOCKERFILE.encode("utf-8"),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=TIMEOUT)
    if build.returncode != 0:
        raise Unavailable("could not build the transcript image: "
                          + build.stdout.decode("utf-8", "replace")[-400:])
    return IMAGE


def fetch(urls, log=None):
    """{video url: json3 caption text} for as many as answered.

    A url that produced nothing is simply absent from the result: the caller
    reports it as a gap, exactly as before. One container run covers the whole
    batch, so the image is built and started once rather than per video.
    """
    urls = [url for url in urls if video_id(url)]
    if not urls:
        return {}
    ensure_image(log=log)

    output = tempfile.mkdtemp(prefix="ysonet_refs_captions_")
    try:
        command = ["docker", "run"] + list(RUN_ARGS)
        command += ["-v", _mount(output) + ":/out"]
        command += [IMAGE, "yt-dlp"] + list(YT_DLP_ARGS) + urls
        if log:
            log("fetching %d caption track(s) in a container" % len(urls))
        done = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=TIMEOUT)
        if done.returncode != 0 and log:
            # --ignore-errors means a non-zero exit can still have produced most
            # of the batch, so this is reported and the results are still read.
            log("yt-dlp exited %d; reading whatever it wrote"
                % done.returncode)
        return _collect(urls, output)
    except subprocess.TimeoutExpired:
        raise Unavailable("the transcript container did not finish within %ds" % TIMEOUT)
    finally:
        shutil.rmtree(output, ignore_errors=True)


CURL_ARGS = (
    "--silent", "--show-error", "--location", "--max-redirs", "5",
    "--max-time", "60", "--max-filesize", "33554432",
    "--user-agent", "ysonet-refs/1 (reference archive)",
)


def fetch_insecure(url, log=None):
    """Fetch a URL WITHOUT verifying its certificate. Returns bytes.

    Maintainer decision 2026-08-04: acceptable for collecting a public document
    from a source whose certificate has expired. One reference in this corpus
    needs it, and the browser recorded the interstitial as if it were the page.

    It lives in the container and not in the fetcher on purpose. "Our client
    always verifies" stays true, because the exception is a different process
    behind a container boundary that nothing else reaches by accident, and what
    comes back is bytes that go through the same extraction as any other fetch.
    """
    ensure_image(log=log)
    output = tempfile.mkdtemp(prefix="ysonet_refs_insecure_")
    try:
        command = ["docker", "run"] + list(RUN_ARGS)
        command += ["-v", _mount(output) + ":/out"]
        command += [IMAGE, "curl", "--insecure"] + list(CURL_ARGS)
        command += ["--output", "/out/body", url]
        if log:
            log("fetching without certificate verification, in a container")
        done = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=TIMEOUT)
        body = b""
        path = os.path.join(output, "body")
        if os.path.exists(path):
            with open(path, "rb") as handle:
                body = handle.read()
        if not body:
            raise Unavailable("the insecure fetch returned nothing: "
                              + done.stdout.decode("utf-8", "replace")[-200:])
        return body
    except subprocess.TimeoutExpired:
        raise Unavailable("the insecure fetch did not finish within %ds" % TIMEOUT)
    finally:
        shutil.rmtree(output, ignore_errors=True)


# One image per page, at a resolution a reader can actually read. 150 DPI keeps
# a slide legible while keeping a 60-page deck to a few megabytes.
PDFTOPPM_ARGS = ("-png", "-r", "150")


def pdf_page_images(pdf_bytes, into, first=1, last=0, log=None):
    """Render each page of a PDF to a PNG in `into`. Returns the paths, in order.

    For the PDF whose text layer cannot be read: a scan, or a deck whose glyphs
    carry no usable encoding map. Extracting text from those produces confident
    nonsense - one in this corpus came out with 32% of its words containing a
    vowel - and the honest alternative is to LOOK at the pages.

    This only produces the images. Reading them is a separate, human or model
    step, because deciding what a page says is not a job for a converter.
    """
    ensure_image(log=log)
    source = tempfile.mkdtemp(prefix="ysonet_refs_pdf_")
    try:
        with open(os.path.join(source, "in.pdf"), "wb") as handle:
            handle.write(pdf_bytes)
        command = ["docker", "run"] + list(RUN_ARGS)
        command += ["-v", _mount(source) + ":/in:ro", "-v", _mount(into) + ":/out"]
        command += [IMAGE, "pdftoppm"] + list(PDFTOPPM_ARGS)
        command += ["-f", str(first)]
        if last:
            command += ["-l", str(last)]
        command += ["/in/in.pdf", "/out/page"]
        if log:
            log("rendering the PDF to page images in a container")
        done = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=TIMEOUT)
        pages = sorted(name for name in os.listdir(into) if name.endswith(".png"))
        if not pages:
            raise Unavailable("pdftoppm produced no pages: "
                              + done.stdout.decode("utf-8", "replace")[-200:])
        return [os.path.join(into, name) for name in pages]
    except subprocess.TimeoutExpired:
        raise Unavailable("rendering the PDF did not finish within %ds" % TIMEOUT)
    finally:
        shutil.rmtree(source, ignore_errors=True)


def _collect(urls, output):
    """Read the json3 files back, preferring a manual track over an automatic one."""
    found = {}
    for url in urls:
        identifier = video_id(url)
        # `<id>.en.json3` is the manual track where one exists; `<id>.en-orig`
        # and the rest are automatic. Prefer the plainest language tag.
        candidates = sorted(
            (name for name in os.listdir(output)
             if name.startswith(identifier + ".") and name.endswith(".json3")),
            key=lambda name: (len(name), name))
        for name in candidates:
            try:
                with open(os.path.join(output, name), "r", encoding="utf-8") as handle:
                    body = handle.read()
            except OSError:
                continue
            if _has_text(body):
                found[url] = body
                break
    return found


def _has_text(body):
    try:
        payload = json.loads(body or "{}")
    except ValueError:
        return False
    return any((segment.get("utf8") or "").strip()
               for event in (payload.get("events") or [])
               for segment in (event.get("segs") or []))


def _mount(path):
    """A host path Docker will accept.

    On Windows a POSIX-style path from a Git Bash shell reaches Docker as
    `C:/Program Files/Git/out` and the run dies on an "invalid working
    directory". Hand it the native path.
    """
    return os.path.abspath(path)
