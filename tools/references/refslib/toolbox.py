"""Archive container lifecycle and public retrieval entrypoints.

Source processors run non-root with a read-only root, capped no-exec tmpfs,
CPU/memory/process limits, bounded stdout/stderr and no direct networking.
Offline conversions get no retrieval capability. Network jobs use a dedicated
Unix socket to a separate public-IP broker; no host profile, credentials,
checkout, content store or Docker socket is exposed to either process.

Native job files stay in the worker's tmpfs. The host receives only bounded
JSON/bytes, validates identities, and owns final publication. No writable host
output directory is mounted into a source processor. Missing Docker or a failed
boundary is reported; no host browser/parser fallback is available.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager

# Pinned. The base image is pinned by DIGEST so a rebuild cannot silently become
# a different image, and yt-dlp by version so a run is reproducible. YouTube
# breaks these tools regularly, so expect to bump YT_DLP when a fetch starts
# failing - that is a deliberate, visible edit rather than a moving tag.
BASE_IMAGE = ("python:3.12-alpine@sha256:"
              "6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df")
YT_DLP = "2026.07.04"
WAYMORE = "8.9"
IMAGE = "ysonet-refs-toolbox:" + YT_DLP + "-source-workers-4"

# `curl` for the certificate exception, `poppler-utils` for `pdftoppm`, and
# Chromium for rendered DOM collection. Their
# versions come from the pinned base image's package repository rather than
# being pinned themselves: pinning an apk version breaks the build the moment
# that repository moves on, and the digest pin already fixes the distribution
# release. A stated limit rather than an oversight.
#
# `poppler-data` IS NOT OPTIONAL, and its absence fails silently. It carries the
# CJK character-collection maps (Adobe-Japan1, Adobe-GB1, Adobe-Korea1); without
# them poppler cannot map an `Identity-H` CID font and DROPS EVERY GLYPH IT
# CANNOT MAP - `pdftotext` returns the Latin fragments only, `pdftoppm` renders
# the slide with its Japanese text simply absent, and neither reports an error a
# caller can see. A 180-page Japanese conference deck came back as bullets and
# emoji, was judged a broken text layer, and had 103 blank-ish pages transcribed
# by hand from renders that had already thrown the text away. With the pack the
# same file extracts cleanly and needs no transcription at all.
DOCKERFILE = """FROM %s
RUN apk add --no-cache chromium curl poppler-utils poppler-data font-dejavu \\
 && pip install --no-cache-dir "yt-dlp==%s" "waymore==%s" \\
 && printf 'Pillow==12.3.0 --hash=sha256:0dd2064cbc55aaec028ef5fbb60fa47bb6c3e7918e07ff17935284b227a9d2df\\n' > /tmp/pillow.txt \\
 && pip install --no-cache-dir --only-binary=:all: --require-hashes -r /tmp/pillow.txt \\
 && rm /tmp/pillow.txt \\
 && adduser -D -u 10001 fetcher
USER fetcher
""" % (BASE_IMAGE, YT_DLP, WAYMORE)

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
    "--cpus", "2",
)


def run_args():
    """Container isolation arguments, using the host's non-root UID on POSIX.

    Match the non-root operator's ownership for selected read-only inputs.
    Source outputs stay in container tmpfs. A root operator still gets the
    image's unprivileged UID; Docker Desktop handles shared-file ownership on
    platforms without `getuid`.
    """
    args = list(RUN_ARGS)
    if hasattr(os, "getuid") and hasattr(os, "getgid") and os.getuid() != 0:
        args += ["--user", "%d:%d" % (os.getuid(), os.getgid())]
    else:
        args += ["--user", "10001:10001"]
    return args


def _run_container(command, timeout, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                   output_limit=128 * 1024 * 1024):
    with _public_egress(command) as isolated_command:
        return _run_container_direct(isolated_command, timeout, stdout, stderr, output_limit)


@contextmanager
def _public_egress(command):
    """Give retrieval workers only a socket to a public-address egress broker.

    The processing container itself has --network none. The small broker is a
    separate container with no inputs, credentials or host mounts other than a
    disposable socket directory and its trusted implementation file.
    """
    if "--network" not in command or command[command.index("--network") + 1] != "bridge":
        yield command
        return
    import time
    work = tempfile.mkdtemp(prefix="ysonet_source_egress_")
    identifier = ""
    try:
        os.chmod(work, 0o755)
        sockets = os.path.join(work, "sockets")
        os.mkdir(sockets, 0o777)
        os.chmod(sockets, 0o777)
        gateway = os.path.join(work, "gateway.py")
        shutil.copyfile(os.path.join(os.path.dirname(__file__), "gateway.py"), gateway)
        broker_cid = os.path.join(work, "broker.cid")
        broker = ["docker", "run", "--detach", "--cidfile", broker_cid] + run_args()
        broker += ["-v", _mount(sockets) + ":/source-egress",
                   "-v", _mount(gateway) + ":/source-gateway.py:ro",
                   IMAGE, "python", "-I", "-B", "/source-gateway.py", "broker"]
        started = subprocess.run(broker, capture_output=True, timeout=30)
        identifier = started.stdout.decode("ascii", "replace").strip()
        if started.returncode or not re.fullmatch(r"[0-9a-f]{12,64}", identifier):
            identifier = ""
            raise Unavailable("public egress broker could not start")
        deadline = time.monotonic() + 20
        while not os.path.exists(os.path.join(sockets, "proxy.sock")):
            if time.monotonic() >= deadline:
                raise Unavailable("public egress broker did not become ready")
            time.sleep(0.1)
        guarded = list(command)
        guarded[guarded.index("--network") + 1] = "none"
        image_at = guarded.index(IMAGE)
        guarded[image_at:image_at] = ["-v", _mount(sockets) + ":/source-egress:ro",
                                     "-v", _mount(gateway) + ":/source-gateway.py:ro"]
        image_at = guarded.index(IMAGE)
        guarded[image_at + 1:image_at + 1] = ["python", "-I", "-B", "/source-gateway.py", "relay"]
        yield guarded
    finally:
        if not identifier:
            try:
                with open(os.path.join(work, "broker.cid"), encoding="ascii") as handle:
                    candidate = handle.read(100).strip()
                if re.fullmatch(r"[0-9a-f]{12,64}", candidate):
                    identifier = candidate
            except OSError:
                pass
        if identifier:
            subprocess.run(["docker", "rm", "--force", identifier],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        shutil.rmtree(work, ignore_errors=True)


def _run_container_direct(command, timeout, stdout, stderr, output_limit):
    """Run one disposable container and force-remove it on every exit path.

    Docker's ``--rm`` only runs after the container process exits. If the host
    client times out or is interrupted, killing that client can leave Chromium
    running indefinitely. A host-side cidfile lets this wrapper remove the
    exact container in ``finally`` without matching names, images, or other
    Docker work.
    """
    control = tempfile.mkdtemp(prefix="ysonet_refs_container_")
    cidfile = os.path.join(control, "cid")
    command = list(command[:2]) + ["--cidfile", cidfile] + list(command[2:])
    try:
        if output_limit is not None:
            return _bounded_run(command, timeout, stdout, stderr, output_limit)
        return subprocess.run(command, stdout=stdout, stderr=stderr, timeout=timeout)
    finally:
        identifier = ""
        try:
            with open(cidfile, "r", encoding="ascii") as handle:
                identifier = handle.read().strip()
        except OSError:
            pass
        if re.fullmatch(r"[0-9a-f]{12,64}", identifier):
            try:
                subprocess.run(["docker", "rm", "--force", identifier],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=30)
            except (OSError, subprocess.SubprocessError):
                pass
        shutil.rmtree(control, ignore_errors=True)


def _bounded_run(command, timeout, stdout, stderr, limit):
    """Bound Docker attach streams on the host, including a compromised worker.

    Container ulimits do NOT constrain the host Docker client's output files.
    Drain two pipes concurrently and stop writing at the explicit byte limit.
    The caller's finally block force-removes the exact container on any failure.
    """
    import threading
    import io
    out = io.BytesIO() if stdout == subprocess.PIPE else stdout
    err = out if stderr == subprocess.STDOUT else (io.BytesIO() if stderr == subprocess.PIPE else stderr)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    exceeded = threading.Event()
    closing = threading.Event()
    read_errors = []

    def copy(source, destination):
        total = 0
        while True:
            try:
                chunk = source.read(65536)
            except (ValueError, OSError) as error:
                if not closing.is_set():
                    read_errors.append(type(error).__name__)
                return
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                exceeded.set()
                process.kill()
                break
            destination.write(chunk)

    readers = [threading.Thread(target=copy, args=pair, daemon=True)
               for pair in ((process.stdout, out), (process.stderr, err))]
    for reader in readers:
        reader.start()
    try:
        process.wait(timeout=timeout)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        for reader in readers:
            reader.join(timeout=5)
        incomplete = any(reader.is_alive() for reader in readers)
        closing.set()
        process.stdout.close()
        process.stderr.close()
    if exceeded.is_set():
        raise Unavailable("source worker exceeded its output limit")
    if incomplete or read_errors:
        raise Unavailable("source worker output was not completely collected")
    return subprocess.CompletedProcess(command, process.returncode,
                                        out.getvalue() if stdout == subprocess.PIPE else None,
                                        err.getvalue() if stderr == subprocess.PIPE else None)

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
        raise Unavailable("no container runtime: install Docker, or skip the container route")
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
        raise Unavailable("could not build the reference toolbox image: "
                          + build.stdout.decode("utf-8", "replace")[-400:])
    return IMAGE


def fetch(urls, log=None):
    """Fetch caption text inside a worker with no writable host output mount."""
    from . import isolation
    urls = [url for url in urls if video_id(url)]
    return isolation.call("captions", urls) if urls else {}


CURL_ARGS = (
    "--silent", "--show-error", "--location", "--max-redirs", "5",
    "--max-time", "60", "--max-filesize", "33554432",
    "--user-agent", "ysonet-refs/1 (reference archive)",
)


def _uncompressed(body):
    """Decode acquired bytes in an offline, resource-limited worker."""
    from . import isolation
    return isolation.call("fetcher.decompress", body)


def fetch_insecure(url, log=None):
    """Explicit certificate exception in a public-only retrieval worker."""
    from . import isolation
    return _uncompressed(isolation.call("curl_bytes", url, insecure=True))


def fetch_public(url, log=None):
    """Verified public retrieval, followed by isolated offline decompression."""
    from . import isolation
    return _uncompressed(isolation.call("curl_bytes", url))


def waymore_urls(domains, log=None, limit_requests=50):
    """Historical URL discovery; result files never leave the worker."""
    from . import isolation
    domains = sorted(set(str(d or "").strip().lower() for d in domains
                         if re.fullmatch(r"[a-z0-9.-]+", str(d or "").strip().lower())))
    return isolation.call("waymore", domains, limit_requests=limit_requests) if domains else []


def _waymore_results(path):
    """Legacy fixture helper; production URL parsing runs inside worker_jobs."""
    from .worker_jobs import read_result
    body = read_result(path, 8 * 1024 * 1024).decode("utf-8", "replace")
    return sorted(set(line.strip() for line in body.splitlines()
                      if line.strip().startswith(("http://", "https://"))))


# External pages run only in the toolbox. `--dump-dom` serialises the rendered
# document after Chromium has loaded it; the virtual-time budget is the wait
# which lets client-side rendering replace an empty shell. No host directory is
# mounted for this route, and downloads, extensions and background services are
# disabled.
CHROMIUM_ARGS = (
    "--headless=new",
    "--no-sandbox",  # Docker is the sandbox; every container capability is dropped.
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-extensions",
    "--disable-plugins",
    "--disable-sync",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-client-side-phishing-detection",
    "--disable-features=Translate,OptimizationHints,MediaRouter",
    "--no-first-run",
    "--no-default-browser-check",
    "--no-service-autorun",
    "--password-store=basic",
    "--use-mock-keychain",
    "--deny-permission-prompts",
    "--disable-file-system",
    "--block-new-web-contents",
    "--dump-dom",
)

# Chromium normally exits within a few seconds of its virtual-time budget. A
# generous 90-second grace let a broken page leave each rung waiting for
# minutes, even though the cidfile wrapper could now clean it up safely. This is
# process-exit grace, not page-rendering time: the caller already owns that
# budget and retries with longer rungs when useful content has not appeared.
BROWSER_PROCESS_GRACE = 20


def browser_dom(url, wait_seconds=10, log=None):
    """Return Chromium's rendered DOM for one public URL, from the container.

    `wait_seconds` becomes Chromium's virtual-time budget. The caller inspects
    visible text and wall markers, and can retry with a longer budget; this
    function deliberately returns evidence, not a truth verdict.
    """
    ensure_image(log=log)
    wait_seconds = max(1.0, min(float(wait_seconds), 120.0))
    milliseconds = int(wait_seconds * 1000)
    command = ["docker", "run"] + run_args()
    command += [IMAGE, "chromium-browser"] + list(CHROMIUM_ARGS)
    command += ["--user-data-dir=/tmp/browser-profile",
                "--virtual-time-budget=%d" % milliseconds, url]
    if log:
        log("rendering the page for %.0fs in headless Chromium, in a container"
            % wait_seconds)
    try:
        done = _run_container(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=wait_seconds + BROWSER_PROCESS_GRACE)
    except subprocess.TimeoutExpired:
        raise Unavailable("the browser container did not finish after %.0fs" % wait_seconds)
    dom = done.stdout.decode("utf-8", "replace")
    if not dom.strip():
        detail = done.stderr.decode("utf-8", "replace")[-300:]
        raise Unavailable("headless Chromium returned no DOM: " + detail)
    return dom


# PDF printing takes only a local, self-contained HTML file. Network is disabled
# for the entire container, and makepdf renders remote images as labelled links,
# so Chromium cannot turn a PDF build into an accidental third-party fetch.
BROWSER_PDF_ARGS = (
    "--headless=new",
    "--no-sandbox",  # Docker is the sandbox; every container capability is dropped.
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-extensions",
    "--disable-plugins",
    "--disable-sync",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-client-side-phishing-detection",
    "--disable-features=Translate,OptimizationHints,MediaRouter",
    "--no-first-run",
    "--no-default-browser-check",
    "--no-service-autorun",
    "--password-store=basic",
    "--use-mock-keychain",
    "--deny-permission-prompts",
    "--disable-file-system",
    "--block-new-web-contents",
    "--no-pdf-header-footer",
    "--run-all-compositor-stages-before-draw",
)


def browser_pdf(html, log=None, image=None):
    """Print offline; only PDF bytes cross back, never a container-created path."""
    from . import isolation
    return isolation.call("print_pdf", html)


# One image per page, at a resolution a reader can actually read. 150 DPI keeps
# a slide legible while keeping a 60-page deck to a few megabytes.
PDFTOPPM_ARGS = ("-png", "-r", "150")

# `-layout` keeps columns and code indentation, which is most of what a security
# whitepaper's meaning rests on.
PDFTOTEXT_ARGS = ("-layout", "-enc", "UTF-8")


def pdf_text(pdf_bytes, log=None):
    """Extract and repair PDF text entirely inside an offline worker."""
    from . import isolation
    return isolation.call("pdf_text", pdf_bytes)


def pdf_page_images(pdf_bytes, into, first=1, last=0, log=None):
    """Render bounded offline batches and publish validated bytes at fixed paths.

    The destination is controller-selected and is never mounted in a container.
    Workers cannot create a host symlink or consume unbounded host scratch space.
    """
    from . import isolation
    from pathlib import Path
    count = isolation.call("pdf_info", pdf_bytes, text=False)
    if type(count) is not int or not 1 <= count <= 500:
        raise Unavailable("PDF page count is outside the 1..500 bound")
    last = last or count
    if type(first) is not int or type(last) is not int or not 1 <= first <= last <= count:
        raise Unavailable("invalid PDF page range")
    target = Path(into)
    if target.is_symlink() or not target.is_dir():
        raise Unavailable("page output must be a controller-selected directory")
    paths, total = [], 0
    for start in range(first, last + 1, 5):
        end = min(last, start + 4)
        pages = isolation.call("pdf_images", pdf_bytes, start, end)
        if not isinstance(pages, list) or [row[0] for row in pages] != list(range(start, end + 1)):
            raise Unavailable("renderer returned an unexpected page range")
        for number, data in pages:
            if type(number) is not int or not isinstance(data, bytes) or not data.startswith(b"\x89PNG\r\n\x1a\n") or len(data) > 20 * 1024 * 1024:
                raise Unavailable("invalid rendered page bytes")
            total += len(data)
            if total > 512 * 1024 * 1024:
                raise Unavailable("rendered PDF exceeds the 512 MiB output budget; select fewer pages")
            dest = target / ("page-%03d.png" % number)
            descriptor, temporary = tempfile.mkstemp(prefix=".page-", dir=target)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(data)
                os.replace(temporary, dest)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            paths.append(str(dest))
    return paths


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
                from .worker_jobs import read_result
                body = read_result(os.path.join(output, name), 2 * 1024 * 1024).decode("utf-8")
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
