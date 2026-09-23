"""The explicit, bounded curl fallback used only by recovery commands."""

from . import support  # noqa: F401

import gzip
import unittest
from unittest import mock

from refslib import fetcher, toolbox


class TestCurlFallback(unittest.TestCase):
    @mock.patch("refslib.fetcher.shutil.which", return_value="/usr/bin/curl")
    @mock.patch("refslib.fetcher.subprocess.run")
    def test_successful_bytes_become_a_response(self, run, _which):
        run.return_value = mock.Mock(returncode=0, stdout=b"archive bytes", stderr=b"")
        response = fetcher.curl_get("https://archive.test/x", timeout=7, max_bytes=99)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body, b"archive bytes")
        command = run.call_args.args[0]
        self.assertIn("--max-filesize", command)
        self.assertIn("99", command)

    @mock.patch("refslib.fetcher.shutil.which", return_value=None)
    def test_missing_curl_is_a_network_failure(self, _which):
        self.assertEqual(fetcher.curl_get("https://archive.test/x").status, 0)

    @mock.patch("refslib.fetcher.shutil.which", return_value="/usr/bin/curl")
    @mock.patch("refslib.fetcher.subprocess.run")
    def test_a_gzip_body_curl_never_asked_for_is_unwrapped(self, run, _which):
        """A Wayback replay answers gzip whether or not the client asked.

        curl writes the body exactly as it arrives, so without this the store
        keeps the compressed bytes and extraction publishes binary noise.
        """
        page = b"<html><title>Hunting for Nginx Alias Traversals</title></html>"
        run.return_value = mock.Mock(returncode=0, stdout=gzip.compress(page), stderr=b"")
        self.assertEqual(fetcher.curl_get("https://web.archive.org/x").body, page)


class TestToolboxCurlBytes(unittest.TestCase):
    """The contained curl is a second client, held to the same guard."""

    def test_public_fetch_unwraps_a_gzip_body(self):
        page = b"<html>research</html>"
        compressed = gzip.compress(page)
        def worker(operation, *args, **kwargs):
            if operation == "curl_bytes":
                return compressed
            self.assertEqual(operation, "fetcher.decompress")
            self.assertEqual(args[0], compressed)
            return fetcher.decompress(args[0])  # trusted fixture, no source bytes
        with mock.patch("refslib.isolation.call", side_effect=worker) as called:
            self.assertEqual(toolbox.fetch_public("https://web.archive.org/x"), page)
        self.assertEqual([c.args[0] for c in called.call_args_list], ["curl_bytes", "fetcher.decompress"])

    def test_a_body_that_is_not_gzip_is_untouched(self):
        page = b"<html>plain</html>"
        with mock.patch("refslib.isolation.call", side_effect=[page, page]) as called:
            self.assertEqual(toolbox.fetch_public("https://web.archive.org/x"), page)
        self.assertEqual(called.call_args_list[-1].args, ("fetcher.decompress", page))


if __name__ == "__main__":
    unittest.main()
