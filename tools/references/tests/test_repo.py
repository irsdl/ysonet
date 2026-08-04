"""Repository packages: what is read, and what is never run.

Repository content is hostile input. Clone and fetch are allowed; checkout,
submodules, LFS, hooks, package managers, builds and execution are not. These
tests drive a fake git so they need neither a network nor a repository.
"""

from . import support  # noqa: F401

import unittest

from refslib import repo

LISTING = "\n".join([
    "100644 blob aaa1    120\tREADME.md",
    "100644 blob aaa2    340\tdocs/getting-started.md",
    "100644 blob aaa3    200\tdocs/design.rst",
    "100644 blob aaa4     90\tLICENSE.md",
    "100644 blob aaa5    500\tREADME",                      # no extension, and common
    "100644 blob bbb1  40000\tsrc/Program.cs",              # code, not prose
    "100644 blob bbb2    100\tnode_modules/pkg/README.md",  # generated tree
    "120000 blob bbb3     20\tdocs/link.md",                # symlink
    "100644 blob bbb4 999999\tdocs/huge.md",                # over the size cap
    "160000 commit ccc1   0\tvendor/submodule",             # submodule
])


class FakeGit(object):
    def __init__(self, listing=LISTING):
        self.listing = listing
        self.calls = []

    def __call__(self, arguments):
        self.calls.append(list(arguments))
        if arguments[0] == "clone":
            return ""
        if "rev-parse" in arguments:
            return "c0ffee1234567890\n"
        if "ls-tree" in arguments:
            return self.listing
        if "cat-file" in arguments:
            return "# Document\n\nProse explaining the technique.\n"
        raise AssertionError("unexpected git call: " + " ".join(arguments))


class TestUrlParsing(unittest.TestCase):
    def test_a_canonical_repository_url_parses(self):
        self.assertEqual(repo.parse("https://github.com/tyranid/ExploitRemotingService"),
                         ("tyranid", "ExploitRemotingService"))
        self.assertEqual(repo.parse("https://github.com/owner/name.git"), ("owner", "name"))

    def test_a_file_inside_a_repository_is_not_a_repository(self):
        self.assertIsNone(repo.parse("https://github.com/o/n/blob/main/a.pdf"))

    def test_a_non_github_or_non_https_url_is_refused(self):
        for url in ("http://github.com/o/n", "https://gitlab.com/o/n",
                    "git://github.com/o/n", "https://github.com/o"):
            self.assertIsNone(repo.parse(url), url)


class TestSelection(unittest.TestCase):
    def setUp(self):
        self.git = FakeGit()
        self.package = repo.acquire("https://github.com/o/n", "/store", run=self.git)

    def test_prose_documents_are_preserved_with_their_path_and_blob(self):
        paths = [material.path for material in self.package.materials]
        self.assertIn("README.md", paths)
        self.assertIn("docs/getting-started.md", paths)
        self.assertIn("docs/design.rst", paths)

    def test_an_extensionless_root_readme_is_preserved(self):
        """Two repositories looked documentation-free because README and LICENSE
        carried no suffix and the selector demanded one."""
        self.assertIn("README", [m.path for m in self.package.materials])

    def test_source_code_is_not_flattened_into_markdown(self):
        self.assertNotIn("src/Program.cs",
                         [material.path for material in self.package.materials])

    def test_generated_trees_symlinks_submodules_and_oversized_blobs_are_rejected(self):
        paths = [material.path for material in self.package.materials]
        for rejected in ("node_modules/pkg/README.md", "docs/link.md",
                         "docs/huge.md", "vendor/submodule"):
            self.assertNotIn(rejected, paths)

    def test_the_commit_is_pinned(self):
        self.assertEqual(self.package.commit, "c0ffee1234567890")


class TestNoExecution(unittest.TestCase):
    def setUp(self):
        self.git = FakeGit()
        repo.acquire("https://github.com/o/n", "/store", run=self.git)
        self.commands = [" ".join(call) for call in self.git.calls]

    def test_the_clone_is_bare_shallow_and_single_branch(self):
        clone = [command for command in self.commands if command.startswith("clone")][0]
        for flag in ("--bare", "--depth 1", "--single-branch", "--no-tags"):
            self.assertIn(flag, clone)

    def test_nothing_checks_out_builds_or_runs(self):
        for forbidden in ("checkout", "submodule", "lfs", "worktree", "restore"):
            for command in self.commands:
                self.assertNotIn(forbidden, command)

    def test_blobs_are_read_through_the_object_database(self):
        self.assertTrue(any(command.startswith("-C") and "cat-file blob" in command
                            for command in self.commands))


class TestGitIsLockedDown(unittest.TestCase):
    """A repository can ask Git to do a surprising amount on its behalf."""

    def test_hooks_credentials_submodules_and_symlinks_are_disabled(self):
        flags = " ".join(repo.SAFE_GIT_FLAGS)
        for expected in ("core.hooksPath=", "credential.helper=",
                         "submodule.recurse=false", "core.symlinks=false",
                         "fetch.recurseSubmodules=false"):
            self.assertIn(expected, flags)

    def test_only_https_transport_is_allowed(self):
        flags = " ".join(repo.SAFE_GIT_FLAGS)
        self.assertIn("protocol.allow=never", flags)
        self.assertIn("protocol.https.allow=always", flags)
        self.assertEqual(repo.SAFE_GIT_ENV["GIT_ALLOW_PROTOCOL"], "https")

    def test_prompts_and_lfs_smudge_are_off(self):
        self.assertEqual(repo.SAFE_GIT_ENV["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(repo.SAFE_GIT_ENV["GIT_LFS_SKIP_SMUDGE"], "1")

    def test_the_user_config_is_ignored(self):
        """os.devnull is "nul" on Windows and "/dev/null" on POSIX; the point is
        that both config layers are pointed at it, not what it is called."""
        import os
        for layer in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"):
            self.assertEqual(repo.SAFE_GIT_ENV[layer], os.devnull)


class TestRendering(unittest.TestCase):
    def test_the_overview_names_the_commit_and_every_blob(self):
        package = repo.acquire("https://github.com/o/n", "/store", run=FakeGit())
        text = repo.to_markdown(package, "https://github.com/o/n")
        self.assertIn("c0ffee1234567890", text)
        self.assertIn("## `README.md`", text)
        self.assertIn("never checked out, built or run", text)


if __name__ == "__main__":
    unittest.main()
