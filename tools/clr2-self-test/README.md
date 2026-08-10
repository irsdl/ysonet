# CLR2 self-test host

`Clr2SelfTestHost.cs` is the source for the deliberately vulnerable, one-shot process used
by `--testclr2`. The normal build invokes an installed CLR2 compiler and places
`ysonet.Clr2TestHost.exe` plus its runtime config beside `ysonet.exe`; Release builds fail
if that compiler is unavailable, so a release cannot silently omit the advertised host.

The executable has no network listener. It accepts only a formatter and a local payload
file, verifies that it is actually running on CLR `2.0.50727` before opening that file,
deserializes once, prints a small machine-readable result, and exits. It is intentionally
unsafe: run it only through ysonet and only with payloads you intend to execute locally.

Do not commit the generated executable. It is a build/release artifact under `bin/`.
