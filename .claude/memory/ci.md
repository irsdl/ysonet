# CI and package testing

2026-09-25 - Behavioral CI uses an explicit strict runner invocation after compiling Debug without its automatic tests. PR/master builds also run NORMAL on an extracted Release ZIP; publication requires FULL on that ZIP before creating a tag. The shared gate checks the completed tier/status, console counts, exit code, and clean environment verdict, and always retains missing/skipped/failed evidence. - A Release build or a zero exit code alone does not establish behavioral coverage.

2026-09-25 - Package testing copies only the Release test runner, windowless sink and test-only .NET 4.0 host/config into the extracted ZIP and gives the runner the packaged product config. Product dependencies, victim hosts and source fixtures must come from the ZIP; checkout-only checks use YSONET_REPO_ROOT. - Copying a whole test output folder masks missing release files, and using its independently generated config can omit the product's binding redirects.

2026-09-25 - After a compile-only MSBuild invocation, use a full Rebuild before behavioral validation. Partial targets can omit embedded resources and generated binding redirects; a later incremental Build can retain that incomplete config as fresh. - Missing completion resources and MessagePack type-initializer failures can come from build staging, so regenerate the outputs before changing product code or assertions.

2026-09-25 - Release evidence is generated only after testing the exact archive, checked against current source/version, checksummed with an explicit subject list, then attested by the publishing workflow. Ordinary CI remains unsigned. Generated sidecars belong in ignored dist output. - Checksums establish integrity, signed attestations establish build identity, and neither substitutes for runtime observations or a reproducible-build proof.

2026-09-25 - Open CSV output with newline="" so the csv writer owns line endings; writing a StringIO CSV through a default Windows text stream produces doubled carriage returns and blank spreadsheet rows. - A byte-level assertion on Windows catches an export bug that Linux tests alone miss.
