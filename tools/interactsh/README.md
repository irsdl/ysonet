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

interactsh gives exactly that: a run-unique host name, and a log of every interaction
that reaches it.

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

The whole tier starts and disposes ONE client session. Three separate sessions would
register three unrelated domains, and unlabeled interactions (see SMB below) could not
then be correlated at all.

### What the tier checks first

Two preconditions run once, before any payload row:

1. **A registered endpoint.** The client wrote a payload domain, so the server answered.
   Registration is an HTTPS exchange with the API. It does NOT prove that a DNS query for
   a name under that domain reaches the authoritative server.
2. **A recorded DNS lookup.** A run-unique label is resolved and the server must record it
   as exactly `dns`. This is the capability the payload rows actually depend on, and it is
   what stops an absence control from passing vacuously on a blind endpoint.

If either is unusable, every OOB check is a named skip in the run's environment report,
not a failure and not a pass. See "Environment verdict" in `CONTRIBUTING.md`.

### The three checks

1. **UNC short-name expansion calls out.** Normalizes `\\<label>.<oob-domain>\share\aaaaaa~1\x`
   and requires an exact `dns` interaction for `<label>`. A control normalizes a plain
   `\\<other-label>.<oob-domain>\share\file.txt` (no `~`) and requires NO interaction for
   it: the framework only calls `GetLongPathNameW` when a path component holds a `~` and
   is 12 characters or fewer, so without the control a hit would not prove what caused
   it. **Needs a self-hosted server you own** (see below).
2. **UNC-callback gadgets are observed out of band.** Generates each UNC/SMB callback
   gadget's payload pointed at a run-unique host, deserializes it, and requires an exact
   `dns` interaction. The row table is `UncCallbackRows` in `ysonet.Tests/Tests.cs`; a
   gadget that is not registered yet is skipped by name. **Needs a self-hosted server you
   own.**
3. **WbemClassObjectUnmarshal calls out to a real remote host.** Its `-c` is a bare host
   inside a COM OBJREF, not a UNC path, so no SMB session and no Windows authentication is
   involved. This one stays available on the default public endpoint. Its control payload
   is generated and never deserialized, which proves the tool does not resolve `-c` while
   building.

The harness itself is `OobSession` in `ysonet.Tests/Oob.cs`.

## Automated UNC needs a server you own

Windows sends authentication material when it opens an SMB session. On the default public
endpoint that would put it in front of a third party whose SMB configuration we do not
control, so the harness refuses:

- **Every automated UNC touch requires `YSONET_INTERACTSH_SERVER`.** Setting it is your
  DECLARATION that the server is self-hosted and yours. The harness cannot prove
  ownership. Never point it at a third-party service.
- On the public endpoint the two UNC checks are named skips and the SMB diagnostic is
  `NOT-PROBED`, decided before any label, UNC path, or socket is created.
- Constructing or serializing a UNC string as inert data is not a touch. Normalizing,
  resolving, opening, enumerating, or deserializing a payload so Windows acts on the path
  is.
- **This gates the test harness only.** Running `ysonet.exe ... -t` yourself is unchanged
  and stays governed by the gadget you chose.

## The egress profile

When the tier runs it also records one diagnostic profile, so a failed row can be told
apart from a machine that cannot reach the server. It never gates a payload row.

| Signal | How it is measured | States |
|---|---|---|
| `http` | an ordinary GET at a unique label, waiting for exactly `http` | `OBSERVED` or `NOT-CONCLUSIVE` |
| `https` | the same over TLS with NORMAL certificate validation, waiting for exactly `https` | `OBSERVED` or `NOT-CONCLUSIVE` |
| `smb` | only with an owned server: touch a unique UNC path and wait for a new `smb` record | `OBSERVED`, `NOT-CONCLUSIVE`, or `NOT-PROBED` |

Protocol names are matched EXACTLY. interactsh answers a TLS request as `https` and a
plain one as `http`, so accepting either would let one signal stand in for the other.

The HTTPS probe deliberately does not install an accept-all certificate callback: that
would have to go on a `ServicePointManager` process global every later request in the run
would inherit. A self-hosted server with an untrusted certificate therefore reports
`NOT-CONCLUSIVE` even when TCP 443 is reachable. That is acceptable because the signal is
diagnostic, not a gate.

**A negative signal is not a diagnosis.** `NOT-CONCLUSIVE` means the server recorded
nothing within the budget. That can be local policy, a proxy, name resolution, the remote
listener's configuration, or a transient failure, and this cannot tell them apart. Do not
report it as proof of a local firewall rule.

## Self-hosting, and SMB

interactsh serves SMB only when you self-host it:

```text
interactsh-server -smb ...
```

Per the v1.3.1 README, `-smb` is self-hosted only, is backed by Python 3 and impacket, and
listens on **real port 445**. A Windows UNC client cannot be told to use another port, so
the host must have 445 free.

Two facts about SMB records that the harness has to work around:

- the SMB server writes an interaction with protocol `smb` and **no `full-id`**, so label
  matching can never find it;
- the correlation left is positional. The harness remembers how many complete records the
  JSONL log held before an action and only looks at records after that point, runs its UNC
  actions serially, and finishes each wait before starting the next.

When a session's own egress profile observes SMB, each positive UNC row additionally
requires a new post-cursor `smb` record, on top of its exact DNS assertion.

The default public servers can change, rotate, or be unavailable, which is another reason
a missing observation is never presented as a local diagnosis.

## Environment variables

| Variable | Effect |
|---|---|
| `YSONET_OOB_TESTS` | Run the OOB tier (same as `--oob`). |
| `YSONET_INTERACTSH_CLIENT` | Full path to `interactsh-client.exe`, instead of `tools\interactsh\bin` or `PATH`. |
| `YSONET_INTERACTSH_SERVER` | Use a self-hosted interactsh server you OWN instead of the client's default public OAST servers. Required for every automated UNC touch. |
| `YSONET_INTERACTSH_TOKEN` | Auth token for a protected (self-hosted) server. |
| `YSONET_STRICT_ENV` | Make an incomplete run exit non-zero (same as `--strict-env`). It never runs a skipped row. |
| `YSONET_TRACE` | Print each fired path and KEEP the interaction JSONL file. See the warning below. |

## Safety notes

- **Opt in only.** Nothing in the NORMAL or FULL tier starts the client or sends a
  packet. A default `msbuild` Debug build is unaffected.
- **No host name in the repo.** The callback host is minted by the client at run time and
  is unique per run. No domain, payload host, or token is hardcoded in ysonet, its help
  text, or its tests.
- **Public by default, and limited by default.** With no `YSONET_INTERACTSH_SERVER` the
  client uses ProjectDiscovery's public OAST servers. Only the non-UNC DCOM check and the
  HTTP/HTTPS diagnostics run; both UNC checks are skipped. What the third party sees is
  the lookup itself, and the label carries no data about the machine.
- **The interaction log can hold sensitive data.** An SMB interaction's raw request can
  contain authentication material. The harness parses only the protocol field, never
  prints raw SMB data, and deletes the JSONL under normal cleanup. `YSONET_TRACE`
  deliberately RETAINS that file: it is outside git, so delete it yourself when you are
  done with it.
- **Only the tool's own tests use it.** No gadget, plugin, or help text points at an OOB
  host.

## Limitations

- A machine that cannot register with the server (no client installed, offline, blocked,
  or a dead server) marks the endpoint absent and skips every OOB check by name.
- Registering successfully does not prove DNS reaches the server, which is why the DNS
  precondition exists as a separate capability.
- A DNS interaction proves the callback was ATTEMPTED. It does not prove the SMB session
  completed or that credentials were sent. When the SMB interaction itself is needed
  (NTLM material), self-host with `-smb` on port 445, or use a lab endpoint that can log
  the connection and point the gadget at it manually.
