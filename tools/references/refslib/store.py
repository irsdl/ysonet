"""The content-addressed store: every byte the archive ever acquired.

Acquisition and publication are separate layers, and this is the acquisition
side. Raw responses, browser DOMs, assets, extractions and translations live
here by hash; `docs/references-md/` holds only what is rendered. That split is
what makes a depth switch a re-render instead of a re-crawl, and it is why a
lighter archive can be produced offline in seconds.

Three properties matter:

* **Addressed by content, so nothing is ever acquired twice.** Two citations
  that resolve to the same bytes share one object.
* **Its path never reaches tracked output.** The store may sit anywhere
  (`YSONET_REFS_STORE`), and `CLAUDE.md` forbids a local path in a committed
  file, so the manifest records hashes and never locations.
* **It never deletes.** `unreferenced()` reports what nothing points at and
  stops there. An automatic sweep would be one manifest bug away from destroying
  the only copy of a page that no longer exists online.
"""

import hashlib
import os
import tempfile


class Store(object):
    def __init__(self, root):
        self.root = str(root)

    def path_for(self, digest):
        """Two levels of fan-out: a flat directory of 100k objects is miserable
        on Windows, and 256 x 256 keeps every level small."""
        return os.path.join(self.root, "objects", digest[:2], digest[2:4], digest)

    def has(self, digest):
        return bool(digest) and os.path.exists(self.path_for(digest))

    def put(self, data):
        """Store bytes, returning their sha256. Idempotent by construction."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("the store holds bytes; encode text before storing it")
        digest = hashlib.sha256(data).hexdigest()
        target = self.path_for(digest)
        if os.path.exists(target):
            return digest
        directory = os.path.dirname(target)
        if not os.path.isdir(directory):
            os.makedirs(directory)
        handle, temporary = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(data)
            os.replace(temporary, target)
        except Exception:
            if os.path.exists(temporary):
                os.unlink(temporary)
            raise
        return digest

    def put_text(self, text, encoding="utf-8"):
        return self.put(text.encode(encoding))

    def get(self, digest):
        with open(self.path_for(digest), "rb") as stream:
            return stream.read()

    def get_text(self, digest, encoding="utf-8"):
        return self.get(digest).decode(encoding, "replace")

    def size(self, digest):
        try:
            return os.path.getsize(self.path_for(digest))
        except OSError:
            return 0

    def digests(self):
        """Every object in the store."""
        base = os.path.join(self.root, "objects")
        if not os.path.isdir(base):
            return []
        found = []
        for current, _directories, files in os.walk(base):
            for name in files:
                if not name.endswith(".tmp"):
                    found.append(name)
        return found

    def unreferenced(self, referenced):
        """Objects nothing points at. REPORTED, never deleted: a manifest bug
        would otherwise destroy the only copy of a page that is gone online."""
        known = set(referenced or ())
        return sorted(digest for digest in self.digests() if digest not in known)

    def verify(self, digest):
        """True when the stored bytes still hash to their name."""
        try:
            return hashlib.sha256(self.get(digest)).hexdigest() == digest
        except OSError:
            return False
