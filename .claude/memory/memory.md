# Memory index

Git-tracked knowledge for contributors and their agents. See the "Memory Management"
section in `CLAUDE.md` for the rules. Entry format inside each topic file: `date - what - why`.

| File | Description | Last updated |
|---|---|---|
| [interactive-ui.md](interactive-ui.md) | Conventions and gotchas for the interactive menus/screens under `ysonet/Interactive/`. | 2026-07-24 |
| [testing.md](testing.md) | Test-harness gotchas: the test-artifact helpers and where tests write files, antivirus/compile hangs, why a failing fire row hides its real error, the payload families that must be fired in a subprocess, when a fire row needs no marker polling at all, how to prove a finalizer effect with a weak reference, how the OOB tier proves an SMB callback through DNS, and how a TFM-stamped child exe reproduces a pre-4.5.2 framework behaviour with no targeting pack and no registry write. | 2026-07-26 |
| [gadgets.md](gadgets.md) | Gadget conventions and traps: which JSON escaper a double-quoted template needs (and how fastJSON silently deletes `\'`), that the YAML minifier corrupts text too so every branch needs verifying, which WinForms getter carrier each serializer can build, `CommandInputType.UncPath`, the payload self-containment rule (no gadget payload in a helper or a shared builder) and what it replaced, the write-it-to-be-read rule (research material, payload visible in source, no obfuscation - not to be confused with the Release binary's antivirus string encryption), when MessagePack Typeless actually writes a type name, inner-gadget option leaks, the `Hosted` label and `Generators/HostedPayloads/`, the formatter `(N)` annotation, Soap vs generic roots, TreeSet/SortedDictionary shapes, the sorted-container argument order and its benign-comparison parameter, void sinks in the splice, the local-vs-target command input types, the DataContract shape a field-serialized target needs instead of an ISerializable marshal, the two separate things that rewrite operator text in an XML payload, which serializers can reach a property SETTER on a carrier that implements IList (and the two that fail silently), and the SharpSerializer binary type-name swap. | 2026-07-26 |
| [dependencies.md](dependencies.md) | Why each old/vulnerable library is pinned, which pins are load-bearing gadgets vs bump candidates, the MessagePack 2.5.301 bump and why it was safe, how to restore a `packages.config` project, the `1.3.3.7` assembly-version marker in `ysonet/dlls/`, and where the public triage record lives. | 2026-07-26 |
| [workflow.md](workflow.md) | Git/multi-agent workflow: use a git worktree (or at least a new branch) for new or parallel work so agents don't share one checkout. | 2026-07-22 |
| [tooling.md](tooling.md) | Repo hygiene: stray decompiler `.resources` at the repo root, the `/*.resources` gitignore guard, and running decompilers from a scratch dir. | 2026-07-23 |

A contributor may keep unpublished notes in an untracked `private/` folder next to
this index. When `private/index.md` exists, read it as well; it is personal, so never
add its rows here.
