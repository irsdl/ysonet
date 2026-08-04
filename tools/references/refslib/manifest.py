"""The archive record: current state in JSON, full history in JSONL.

One record per URL holding what it is, when it was retrieved, where from, and
every process performed on it. That is the whole point of the file: it is what
makes a run auditable a year later, resumable after an interruption, and
re-renderable at another depth without a re-crawl.

It is split into two tracked files, and the split is deliberate:

* `manifest.json` - CURRENT state. One entry per URL, and inside it one row per
  step holding that step's latest outcome with its timestamp, tool, inputs and
  result. Bounded: re-running a step replaces its row rather than adding one.
* `history.jsonl` - the append-only journal. One JSON object per line, never
  edited. Every run of every step, forever.

The first version kept the whole history inside `manifest.json`. That grows
without bound AND rewrites the entire file on every run, so a tracked 700 KB
document would be re-added to git history each time. JSONL appends, so a run
adds lines and the diff is the lines it added.

Neither file may contain an absolute path or a store path: they are tracked, and
`CLAUDE.md` forbids a local path in a committed file. Content is addressed by
hash instead.
"""

import datetime
import json
import os
import tempfile

SCHEMA = 2


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


class Manifest(object):
    def __init__(self, path, data=None, journal_path=None):
        self.path = str(path)
        self.journal_path = str(journal_path or os.path.join(
            os.path.dirname(self.path) or ".", "history.jsonl"))
        self.data = data or {"schema": SCHEMA, "updated": None, "urls": {}}
        self.data.setdefault("urls", {})
        self._pending = []

    @classmethod
    def load(cls, path, journal_path=None):
        """Load, or start empty. A corrupt file RAISES rather than being
        replaced: overwriting it would destroy the only record of everything
        already acquired."""
        if not os.path.exists(str(path)):
            return cls(path, journal_path=journal_path)
        with open(str(path), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return cls(path, migrate(data), journal_path=journal_path)

    def entry(self, key):
        entry = self.data["urls"].get(key)
        if entry is None:
            entry = {
                "first_seen_utc": utc_now(),
                "spellings": [],
                "cited_by": [],
                "also_at": [],
                "steps": {},
            }
            self.data["urls"][key] = entry
        entry.setdefault("steps", {})
        return entry

    def record(self, key, step, **fields):
        """Record one step outcome.

        Replaces that step's row in the manifest (current state) and appends a
        line to the journal (history). Both carry the same payload, so nothing
        is lost by the manifest staying bounded.
        """
        entry = self.entry(key)
        row = {"utc": utc_now()}
        row.update(fields)
        entry["steps"][step] = row
        self._pending.append(dict(row, url=key, step=step))
        return row

    def last(self, key, step):
        """The most recent outcome for a step, or None. This is the resume point."""
        entry = self.data["urls"].get(key)
        if not entry:
            return None
        return (entry.get("steps") or {}).get(step)

    def steps_done(self, key):
        entry = self.data["urls"].get(key) or {}
        return sorted((entry.get("steps") or {}).keys())

    def save(self):
        """Write the manifest atomically, then append the journal lines.

        Manifest first: a journal line describing a step whose result was lost
        is confusing, while a journal missing a line the manifest already has is
        merely incomplete history.
        """
        self.data["schema"] = SCHEMA
        self.data["updated"] = utc_now()
        _write_atomic(self.path, json.dumps(self.data, indent=1, sort_keys=True,
                                            ensure_ascii=False) + "\n")
        if self._pending:
            directory = os.path.dirname(self.journal_path)
            if directory and not os.path.isdir(directory):
                os.makedirs(directory)
            with open(self.journal_path, "a", encoding="utf-8", newline="\n") as stream:
                for row in self._pending:
                    stream.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
            self._pending = []


def migrate(data):
    """Bring an older manifest up to the current schema.

    Schema 1 kept an append-only `process` list inside each entry. Those rows
    become the entry's `steps` (latest wins, which is what they were used for)
    and are not thrown away: `refs.py` writes the full list into the journal
    during the first save after a migration.
    """
    if not isinstance(data, dict):
        return {"schema": SCHEMA, "urls": {}}
    if data.get("schema", 1) >= SCHEMA:
        return data
    for entry in (data.get("urls") or {}).values():
        process = entry.pop("process", None) or []
        steps = entry.setdefault("steps", {})
        for row in process:
            step = row.get("step")
            if not step:
                continue
            fields = {key: value for key, value in row.items() if key != "step"}
            steps[step] = fields
        entry["migrated_process"] = process
    data["schema"] = SCHEMA
    return data


def drain_migrated(data):
    """Pull the schema-1 process rows out for journalling, once."""
    lines = []
    for key, entry in (data.get("urls") or {}).items():
        for row in entry.pop("migrated_process", []) or []:
            lines.append(dict(row, url=key))
    return lines


def _write_atomic(path, text):
    directory = os.path.dirname(str(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    handle, temporary = tempfile.mkstemp(dir=directory or ".", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        os.replace(temporary, str(path))
    except Exception:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise
