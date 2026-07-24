# Tooling and repo hygiene

Entry format: date - what - why.

2026-07-23 - Stray .NET `.resources` files (binary, magic `0xBEEFCACE`) named after
GAC assemblies (e.g. `System.Management.resources`) appeared at the repo root during
decompilation work; deleted them and added `/*.resources` to `.gitignore`. - The repo
has zero tracked `.resources`, so any at the root are decompiler/build spillage and must
never be committed. Root cause of the writer is not fully pinned: a local decompile
library (whole-module-to-string) was tested against the exact assemblies and does NOT
leak, so the source is most likely a direct ILSpy/ilspycmd project-mode or resource-dump
run using the repo as its working directory. Rule: run any decompiler from a scratch dir,
never from inside the repo. Open security question (does ILSpy resource extraction allow
path traversal via crafted resource names) is under investigation in `dev-kitchen/dirty/`.
