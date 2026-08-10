"""redact_text keeps an absolute local path out of a free-text field.

Path FIELDS reach tracked output through rel(); this covers the other channel, a
path baked into a message (a git clone target that lands in a manifest 'reason').
The leak this closes was a git error string carrying the developer's checkout path
into the tracked history.jsonl.
"""

from . import support  # noqa: F401

import unittest

from refslib import paths


class TestRedactText(unittest.TestCase):
    def test_a_windows_path_in_a_message_becomes_a_placeholder(self):
        # An invented layout, never this machine's own: a fixture that pastes the
        # developer's real checkout path publishes it in every clone of the repo,
        # which is the leak this module exists to stop.
        message = ("repository: git clone failed: Cloning into bare repository "
                   "'E:\\Build\\Workspace\\refs\\tools\\references\\cache\\store\\"
                   "git\\advisories__GHSA-6r7c-6w96-8pvw.git'...")
        result = paths.redact_text(message)
        self.assertNotIn("Workspace", result)
        self.assertNotIn("D:\\", result)
        # The trailing name is derived from the URL, not the layout, so it stays.
        self.assertIn("<local-path>/advisories__GHSA-6r7c-6w96-8pvw.git", result)

    def test_a_posix_home_path_is_redacted(self):
        self.assertEqual(paths.redact_text("saved to /home/alice/work/x.html now"),
                         "saved to <local-path>/x.html now")

    def test_a_url_is_not_mistaken_for_a_local_path(self):
        # The lookbehind is what stops the "s:/" in https:// and the "/Users/"
        # inside a URL path from anchoring a match.
        for url in ("fetched https://example.org/Users/x ok",
                    "http 404 from https://host/mnt/data"):
            self.assertEqual(paths.redact_text(url), url)

    def test_text_with_no_local_path_is_unchanged(self):
        self.assertEqual(paths.redact_text("http 404 on acquisition"),
                         "http 404 on acquisition")

    def test_non_strings_pass_through(self):
        self.assertIsNone(paths.redact_text(None))
        self.assertEqual(paths.redact_text(123), 123)
        self.assertEqual(paths.redact_text(""), "")


if __name__ == "__main__":
    unittest.main()
