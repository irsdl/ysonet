# interactsh (out-of-band interaction observation)

`interactsh-client` is an out-of-band (OOB) interaction collector from
ProjectDiscovery: https://github.com/projectdiscovery/interactsh

ysonet's test suite uses it to prove ONE thing it cannot prove in process: that a
payload made the target call out to a host it does not control.

This is a dev tool. It is never linked into ysonet and never ships in a release.

## Why the test suite needs it

Most payload effects are proved locally. A command payload drops a marker file, and an
SSRF/remoting payload hits `LoopbackListener`, an ephemeral TCP port owned by the test.
No traffic leaves the machine.

The SMB/UNC callback cannot work that way:

- the effect is an outbound SMB connection made by `Win32Native.GetLongPathNameW` while
  the framework normalizes a path;
- SMB is fixed at port 445, and the Windows SMB client owns the loopback UNC path, so a
  listener on an ephemeral loopback port never sees it;
- binding 445 needs a machine that is not already serving SMB, plus elevation. That is
  not a developer workstation.

The way through: **before Windows can open the SMB connection it must resolve the host
name.** A DNS query for a host name that only this test run knows is proof the callback
was attempted, and DNS leaves the machine even when outbound 445 is blocked by a
firewall, an ISP, or a corporate network. So a recorded DNS interaction is a positive
result, with or without a completed SMB session.

interactsh gives exactly that: a run-unique host name, and a log of every DNS, HTTP and
SMTP interaction that reaches it.

## Install

```powershell
powershell -ExecutionPolicy Bypass -File tools\interactsh\get-interactsh.ps1
```

The script downloads the pinned release, verifies its SHA256 against the checksums file
published with that release, and puts `interactsh-client.exe` in `tools\interactsh\bin`.
That folder is git-ignored, so the binary is never committed; each machine fetches its
own copy. Use `-Force` to re-download and `-Version` to install a different release
(follow the dependency freshness policy in `CLAUDE.md`: nothing younger than one month).

The tests also accept a client installed anywhere else, via `YSONET_INTERACTSH_CLIENT`.

## Run the tests that use it

The OOB tests are a separate opt-in tier. They never run on a normal Debug build and are
not part of the FULL suite, because they are the only tests that send traffic off the
machine.

```powershell
# after a Debug build
ysonet\bin\Debug\ysonet.Tests.exe --oob

# or, with the env var
$env:YSONET_OOB_TESTS = "1"
ysonet\bin\Debug\ysonet.Tests.exe
```

Two rows run:

1. **UNC short-name expansion calls out.** Normalizes `\\<label>.<oob-domain>\share\aaaaaa~1\x`
   and requires an interaction for `<label>`. A control normalizes a plain
   `\\<other-label>.<oob-domain>\share\file.txt` (no `~`) and requires NO interaction for
   it: the framework only calls `GetLongPathNameW` when a path component holds a `~` and
   is 12 characters or fewer, so without the control a hit would not prove what caused
   it.
2. **UNC-callback gadgets are observed out of band.** Generates each UNC/SMB callback
   gadget's payload pointed at a run-unique host, deserializes it, and requires an
   interaction. The row table is `UncCallbackRows` in `ysonet.Tests/Tests.cs`; a gadget
   that is not registered yet is skipped by name.

The harness itself is `OobSession` in `ysonet.Tests/Oob.cs`.

## Environment variables

| Variable | Effect |
|---|---|
| `YSONET_OOB_TESTS` | Run the OOB tier (same as `--oob`). |
| `YSONET_INTERACTSH_CLIENT` | Full path to `interactsh-client.exe`, instead of `tools\interactsh\bin` or `PATH`. |
| `YSONET_INTERACTSH_SERVER` | Use a self-hosted interactsh server instead of the client's default public OAST servers. |
| `YSONET_INTERACTSH_TOKEN` | Auth token for a protected (self-hosted) server. |
| `YSONET_TRACE` | Print each fired path and keep the interaction JSONL file for inspection. |

## Safety notes

- **Opt in only.** Nothing in the NORMAL or FULL tier starts the client or sends a
  packet. A default `msbuild` Debug build is unaffected.
- **No host name in the repo.** The callback host is minted by the client at run time and
  is unique per run. No domain, payload host, or token is hardcoded in ysonet, its help
  text, or its tests.
- **Public by default.** With no `YSONET_INTERACTSH_SERVER`, the client uses
  ProjectDiscovery's public OAST servers, so the DNS query for the run-unique host is
  observed by a third party. Nothing is sent except that lookup, and the label carries no
  data about the machine. On a sensitive network, run your own `interactsh-server` (same
  repository) and set `YSONET_INTERACTSH_SERVER`.
- **Only the tool's own tests use it.** No gadget, plugin, or help text points at an OOB
  host.

## Limitations

- A machine with no outbound DNS, or a resolver that blocks the OAST domains, cannot run
  these tests. The client fails to register and every row logs a clear skip reason rather
  than failing.
- A DNS interaction proves the callback was ATTEMPTED. It does not prove the SMB session
  completed or that credentials were sent. When the SMB interaction itself is needed
  (NTLM material), use a lab endpoint that can log the connection and point the gadget at
  it manually.
