# CI and package testing

2026-09-25 - Behavioral CI uses an explicit strict runner invocation after compiling Debug without its automatic tests. PR/master builds also run NORMAL on an extracted Release ZIP; publication requires FULL on that ZIP before creating a tag. The shared gate checks the completed tier/status, console counts, exit code, and clean environment verdict, and always retains missing/skipped/failed evidence. - A Release build or a zero exit code alone does not establish behavioral coverage.

2026-09-25 - Package testing copies only the Release test runner, windowless sink and test-only .NET 4.0 host/config into the extracted ZIP and gives the runner the packaged product config. Product dependencies, victim hosts and source fixtures must come from the ZIP; checkout-only checks use YSONET_REPO_ROOT. - Copying a whole test output folder masks missing release files, and using its independently generated config can omit the product's binding redirects.
