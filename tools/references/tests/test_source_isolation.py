"""Enforced archive source and retrieval boundaries."""
from . import support
import base64
import hashlib
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
import tempfile
from unittest.mock import patch
from refslib import gateway, isolation, toolbox, wayback, worker_jobs

class WorkerBoundary(unittest.TestCase):

    def test_only_admitted_operations_and_data_types_cross_the_boundary(self):
        for operation in ("os.system", "eval", "__import__", "../../write"):
            with self.assertRaises(ValueError):
                isolation.call(operation, "touch /tmp/should-not-exist")
        with self.assertRaises(TypeError):
            isolation.encode(lambda: None)
        with self.assertRaises(ValueError):
            isolation.decode({"$class": "os.system", "values": ["echo bad"]})

    def test_offline_job_has_only_readonly_selected_inputs_and_enforced_limits(self):
        seen = []
        def run(command, **kwargs):
            seen.extend(command)
            mounts = [command[n + 1] for n, x in enumerate(command) if x == "-v"]
            self.assertEqual(len(mounts), 2)
            self.assertTrue(all(x.endswith(":ro") for x in mounts))
            self.assertNotIn("/var/run/docker.sock", " ".join(command))
            code = Path(mounts[0].split(":/code")[0])
            self.assertTrue((code / "refslib/isolation.py").is_file())
            self.assertFalse((code / "CLAUDE.md").exists())
            self.assertEqual(kwargs["output_limit"], isolation.LIMIT)
            kwargs["stdout"].write(json.dumps({"result": "inert fixture"}).encode())
            return subprocess.CompletedProcess(command, 0)
        with patch.object(toolbox, "ensure_image", return_value=toolbox.IMAGE), patch.object(toolbox, "_run_container", side_effect=run):
            self.assertEqual(isolation.call("read_text", b"source", 0, 20), "inert fixture")
        self.assertEqual(seen[seen.index("--network") + 1], "none")
        for flag in ("--read-only", "--cap-drop", "--security-opt", "--memory", "--pids-limit", "--cpus", "--user"):
            self.assertIn(flag, seen)
        self.assertNotEqual(seen[seen.index("--user") + 1].split(":")[0], "0")

    def test_missing_runtime_never_falls_back_to_local_parsing(self):
        with patch.object(toolbox, "ensure_image", side_effect=toolbox.Unavailable("absent")), patch.object(isolation, "dispatch") as dispatch:
            with self.assertRaises(toolbox.Unavailable):
                isolation.call("read_text", b"text", 0, 10)
            dispatch.assert_not_called()

    def test_output_is_bounded_during_collection_not_after_process_exit(self):
        out, err = io.BytesIO(), io.BytesIO()
        with self.assertRaises(toolbox.Unavailable):
            toolbox._bounded_run([sys.executable, "-c", "import os; os.write(1, b'x' * 200000)"], 5, out, err, 1000)
        self.assertLessEqual(len(out.getvalue()), 1000)

    def test_root_host_still_produces_a_nonroot_worker(self):
        with patch.object(toolbox.os, "getuid", return_value=0), patch.object(toolbox.os, "getgid", return_value=0):
            args = toolbox.run_args()
            self.assertEqual(args[args.index("--user") + 1], "10001:10001")

    def test_container_output_links_and_special_files_are_not_followed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "private-fixture").write_bytes(b"not an output")
            (root / "output").symlink_to(root / "private-fixture")
            with self.assertRaises(OSError):
                worker_jobs.read_result(root / "output")
            with self.assertRaises(ValueError):
                worker_jobs.read_result(root)
            with self.assertRaises(ValueError):
                worker_jobs.read_result(root / "private-fixture", limit=2)

    def test_offline_native_jobs_never_receive_a_retrieval_broker(self):
        self.assertTrue({"print_pdf", "pdf_info", "pdf_text", "pdf_images"}.isdisjoint(isolation.NETWORK))
        for job in ("print_pdf", "pdf_info", "pdf_text", "pdf_images"):
            self.assertIn(job, isolation.NATIVE)

    def test_pdf_page_writer_accepts_bytes_at_fixed_paths_not_worker_paths(self):
        png = b"\x89PNG\r\n\x1a\nfixture"
        with tempfile.TemporaryDirectory() as temp, patch.object(isolation, "call", side_effect=[1, [(1, png)]]) as called:
            paths = toolbox.pdf_page_images(b"%PDF-fixture", temp)
            self.assertEqual(Path(paths[0]).name, "page-001.png")
            self.assertEqual(Path(paths[0]).read_bytes(), png)
            self.assertEqual([c.args[0] for c in called.call_args_list], ["pdf_info", "pdf_images"])

    def test_wayback_index_json_is_interpreted_in_an_offline_worker(self):
        payload = json.dumps([
            ["timestamp", "original", "length", "statuscode"],
            ["20240102030405", "https://example.test/article", "1234", "200"],
        ]).encode("utf-8")
        answer = wayback.Snapshot("20240102030405", 1234,
                                  "https://example.test/article")
        def run(command, **kwargs):
            self.assertEqual(command[command.index("--network") + 1], "none")
            kwargs["stdout"].write(json.dumps(
                {"result": isolation.encode([answer])}).encode("utf-8"))
            return subprocess.CompletedProcess(command, 0)
        with patch.object(toolbox, "ensure_image", return_value=toolbox.IMAGE), \
                patch.object(toolbox, "_run_container", side_effect=run):
            found = isolation.call("wayback.parse_snapshots", payload)
        self.assertEqual(len(found), 1)
        self.assertIsInstance(found[0], wayback.Snapshot)
        self.assertEqual(found[0].timestamp, "20240102030405")
        self.assertEqual(found[0].length, 1234)
        self.assertEqual(found[0].original, "https://example.test/article")
        self.assertNotIn("wayback.parse_snapshots", isolation.NETWORK)

    def test_historical_discovery_is_a_fixed_bounded_network_worker(self):
        self.assertIn("waymore", isolation.NATIVE)
        self.assertIn("waymore", isolation.NETWORK)
        self.assertEqual(worker_jobs.WAYMORE_PROVIDERS, "commoncrawl,otx,urlscan")
        self.assertEqual(worker_jobs.WAYMORE_MAX_REQUESTS, 500)
        with self.assertRaisesRegex(ValueError, "between 1 and 500"):
            worker_jobs.waymore(["example.org"], limit_requests=0)
        with self.assertRaisesRegex(ValueError, "between 1 and 500"):
            worker_jobs.waymore(["example.org"], limit_requests=501)


class PublicEgress(unittest.TestCase):
    def rows(self, ip):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]

    def test_private_loopback_metadata_and_mixed_dns_answers_are_refused(self):
        for ip in ("127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0"):
            with patch.object(gateway.socket, "getaddrinfo", return_value=self.rows(ip)):
                with self.assertRaises(ValueError):
                    gateway.destination("attacker.example", 443)
        with patch.object(gateway.socket, "getaddrinfo", return_value=self.rows("1.1.1.1") + self.rows("127.0.0.1")):
            with self.assertRaises(ValueError):
                gateway.destination("mixed.example", 443)

    def test_connection_uses_the_validated_address_not_a_second_dns_lookup(self):
        with patch.object(gateway.socket, "getaddrinfo", return_value=self.rows("1.1.1.1")) as lookup, patch.object(gateway.socket, "socket") as connection:
            gateway.connect_public("changing.example", 443)
            lookup.assert_called_once()
            connection.return_value.connect.assert_called_once_with(("1.1.1.1", 443))

    def test_nonweb_and_credential_targets_are_refused(self):
        for url in ("file:///etc/passwd", "http://user:secret@example.org", "http://localhost:2375", "https://127.0.0.1/"):
            with self.assertRaises(ValueError):
                isolation.public_url(url)
