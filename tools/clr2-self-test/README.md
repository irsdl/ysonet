# CLR2 self-test host

`Clr2SelfTestHost.cs` is the source for the deliberately vulnerable, one-shot process used
by `--testclr2`. The normal build invokes an installed CLR2 compiler and places
`ysonet.Clr2TestHost.exe` plus explicit `.x86.exe` and `.x64.exe` variants and their runtime
configs beside `ysonet.exe`; Release builds fail if that compiler is unavailable, so a
release cannot silently omit the advertised hosts. The unsuffixed executable remains the
backward-compatible default-architecture host.

The executable has no network listener. It accepts only a formatter and a local payload
file, verifies that it is actually running on CLR `2.0.50727` before opening that file,
reports its process bitness, deserializes once, prints a small machine-readable result, and
exits. The parent checks that an explicitly selected x86 or x64 host really ran at the
requested bitness. It is intentionally unsafe: run it only through ysonet and only with
payloads you intend to execute locally.

For payload runs, the parent copies the selected host and config into a fresh application
directory. An optional `clr2-deps.manifest` declares exact assembly identities and files
under `clr2-deps`; the child validates them before reading the payload, resolves only exact
full-name requests, and prints dependency plus full loaded-assembly ledgers. The
`--probe-assembly <full-identity>` mode instead starts without staged files and reports
whether CLR2 can bind that identity from its ambient/default context. This exposes a GAC
bind that `AssemblyResolve` cannot block.

Do not commit the generated executable. It is a build/release artifact under `bin/`.
