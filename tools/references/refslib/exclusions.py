"""The reviewable exclusion classifier.

Most URLs in this repository are not references. An XML namespace identifier, a
payload's target host, a package feed and a localhost test endpoint are all
addresses, and none of them is a document worth archiving.

The rules live in the tracked, hand-edited `exclude.json`, one reason per rule,
so a wrong exclusion is a line in the harvest report rather than a silent
disappearance. Nothing here decides anything on its own: an unmatched URL is
kept, which fails towards "review it" rather than "drop it".
"""

import re

from . import paths


class Rule(object):
    def __init__(self, raw):
        self.id = raw.get("id") or "unnamed"
        self.match = raw.get("match") or "regex"
        self.pattern = raw.get("pattern") or ""
        self.reason = raw.get("reason") or "no reason given"
        if self.match in ("regex", "host_regex"):
            self.compiled = re.compile(self.pattern, re.IGNORECASE)
        elif self.match not in ("host", "prefix"):
            raise paths.SetupError("exclude.json rule %r has unknown match kind %r" % (self.id, self.match))

    def applies(self, url, host):
        if self.match == "regex":
            return self.compiled.search(url) is not None
        if self.match == "host_regex":
            # Matching the PARSED host, not the raw string, so credentials, a
            # port, or a path cannot smuggle a match past a host rule.
            return bool(host) and self.compiled.search(host) is not None
        if self.match == "host":
            pattern = self.pattern.lower()
            return host == pattern or host.endswith("." + pattern)
        return url.lower().startswith(self.pattern.lower())


class Classifier(object):
    def __init__(self, rules):
        self.rules = rules

    @classmethod
    def load(cls):
        data = paths.load_json("exclude.json")
        rules = data.get("rules")
        if not isinstance(rules, list) or not rules:
            raise paths.SetupError("exclude.json has no rules; an empty classifier would archive everything")
        return cls([Rule(raw) for raw in rules])

    def excluded_by(self, url):
        """Return the first matching rule, or None to keep the URL."""
        from urllib.parse import urlsplit
        try:
            host = (urlsplit(url).hostname or "").lower()
        except ValueError:
            host = ""
        for rule in self.rules:
            if rule.applies(url, host):
                return rule
        return None
