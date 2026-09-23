#!/usr/bin/env python3
"""Run archive tests in offline Docker, including tests over archived text."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile

from refslib import toolbox

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "ysonet-reference-tests:source-workers-4"


def main():
    toolbox.ensure_image()
    if subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode:
        dockerfile = "FROM " + toolbox.IMAGE + "\nUSER root\nRUN apk add --no-cache git\nUSER fetcher\n"
        subprocess.run(["docker", "build", "-t", IMAGE, "-"], input=dockerfile.encode(), check=True, timeout=600)
    with tempfile.TemporaryDirectory(prefix="ysonet_reference_tests_") as folder:
        stage = Path(folder)
        os.chmod(stage, 0o755)
        shutil.copytree(ROOT / "tools/references", stage / "tools/references",
                        ignore=shutil.ignore_patterns("cache", "__pycache__"))
        shutil.copytree(ROOT / ".claude/agents", stage / ".claude/agents")
        (stage / "docs/archived-references/md").mkdir(parents=True)
        for name in ("references.md", "dotnet-deserialization-research.md"):
            shutil.copyfile(ROOT / "docs" / name, stage / "docs" / name)
        subprocess.run(["git", "init", "-q", str(stage)], check=True)
        command = ["docker", "run"] + toolbox.run_args()
        command[command.index("--network") + 1] = "none"
        command[command.index("--tmpfs") + 1] = "/tmp:rw,noexec,nosuid,size=128m"
        command += ["-v", str(stage) + ":/work:ro", "-v",
                    str(ROOT / "docs/archived-references/md") + ":/work/docs/archived-references/md:ro",
                    "--workdir", "/work", IMAGE, "python", "-B", "-m", "unittest",
                    "discover", "-s", "tools/references/tests", "-t", "tools/references"]
        result = toolbox._run_container(command, timeout=300)
        sys.stdout.write(result.stdout.decode("utf-8", "replace"))
        sys.stderr.write(result.stderr.decode("utf-8", "replace"))
        return result.returncode


if __name__ == "__main__":
    sys.exit(main())
