# .NET Framework 4.0 test host

This is the deliberately unsafe victim for the opt-in `ysonet.Tests.exe --net40` tier.
It is compiled with the .NET Framework 4.0 compiler and exact 4.0 reference assemblies.
It is not shipped with ysonet and is not a product self-test feature.

.NET Framework 4.5 and later are in-place replacements for 4.0. Consequently, copying a
net40 executable onto a current developer machine does not test 4.0: it runs on the
installed later CLR instead. Use an isolated, disposable Windows VM that has the full
.NET Framework 4.0 runtime and `System.Workflow.ComponentModel`.

Microsoft documents the in-place replacement model in
[Version compatibility](https://learn.microsoft.com/dotnet/framework/migration-guide/version-compatibility)
and [Versions and dependencies](https://learn.microsoft.com/dotnet/framework/install/versions-and-dependencies).

## Why a normal 4.x machine cannot test a 4.0-only payload

A payload such as `TypeConfuseDelegateNet40Workflow` rebuilds a private type shape that only
exists in genuine .NET Framework 4.0. It fires only where the machine's INSTALLED framework
is really 4.0. Two points trip people up:

- **4.0 and 4.5+ are not side by side.** Unlike 2.0 and 4.0, the 4.x releases are one CLR
  updated in place: installing 4.5 or later overwrites the 4.0 files. Once 4.5+ is on a
  machine, there is no 4.0 left on it to run against.
- **"Targets 4.0" is not "runs on 4.0."** An app (including an ASP.NET app with
  `<httpRuntime targetFramework="4.0"/>`, or an IIS app pool that shows
  **".NET CLR Version v4.0.30319"**) still executes on the installed 4.x CLR and BCL. The
  target attribute flips compatibility quirks; it does not restore 4.0's type layouts. `v4.0.30319`
  means "CLR 4", not ".NET 4.0". So a 4.0-only payload will not fire there.

Therefore a developer box on 4.8 cannot fire this payload, and neither can a 4.8 server
hosting a "4.0" app. You need an environment whose installed framework is genuinely 4.0.

## Confirming and getting a genuine 4.0 target

- **Confirm the runtime.** Run `ysonet.Net40TestHost.exe --probe` on the candidate. It
  prints `shape=netfx40` only on a real 4.0 runtime; on 4.5+ it prints `shape=not-netfx40`
  with the reason (for example `functorMembers=comparison` instead of `comparison,c`).
- **Quick registry check.** If `HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full`
  has a `Release` value, 4.5+ is installed and the machine is not a 4.0 target. Genuine 4.0
  has the `v4\Client`/`v4\Full` keys without that `Release` value.
## Building a genuine .NET Framework 4.0 VM

There is no image to download; you build a disposable VM whose installed framework stays at
4.0. ysonet does not ship one (OS licensing and size), so anyone extending ysonet makes
their own. Steps:

1. **Pick a base OS that shipped before 4.5** so nothing preinstalls it: Windows 7 SP1 or
   Windows Server 2008 R2 SP1 (x64) are the usual choices. They come with .NET 3.5.1.
2. **Keep .NET 3.5.1 enabled.** The gadget needs `System.Workflow.ComponentModel`, which is
   part of the 3.0/3.5 Windows Communication/Workflow components, so leave that feature on.
3. **Install the standalone .NET Framework 4.0 full redistributable**
   (`dotNetFx40_Full_x86_x64.exe`, Microsoft download) and stop there. Do NOT install 4.5,
   4.6, 4.7 or 4.8, and do NOT install any "language pack"/update that pulls 4.5+ in.
4. **Block it from updating.** 4.5+ arrives as an in-place Windows Update. Keep the VM off
   the network, or disable Windows Update, so 4.0 is not silently replaced.
5. **Verify.** Copy `ysonet.Net40TestHost.exe` and its config in and run
   `ysonet.Net40TestHost.exe --probe`. It must print `shape=netfx40`,
   `functorMembers=comparison,c`, `comparerCreate=absent`. Also confirm the registry has NO
   `HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full` `Release` value.
6. **Snapshot it.** A fired payload can delete files or run code; a clean snapshot lets you
   roll back between tests. Give the VM no network and no extra shared folders (see Safety).

Which files actually run the payload: deserialization executes against
`%WINDIR%\Microsoft.NET\Framework[64]\v4.0.30319\` (mscorlib, System, System.Web, etc.). On
this VM those are the real 4.0 files; on a 4.5-4.8 machine the same folder holds the newer
files, which is why only this VM fires a 4.0-only payload.

This is the same isolated 4.0 VM the `--net40` test tier drives through a mapped directory.

## Firing a single payload on the 4.0 target

Once `--probe` reports `shape=netfx40`, deserialize the payload directly (see
"Deserializing a single payload by hand" below):

```text
ysonet.exe -g TypeConfuseDelegateNet40Workflow -f BinaryFormatter -c calc > bf.b64
REM copy bf.b64 into the 4.0 VM, then in the VM:
ysonet.Net40TestHost.exe --deserialize BinaryFormatter bf.b64
```

## Setup

1. Build `ysonet.Tests` in Debug. The build writes
   `ysonet.Net40TestHost.exe` and its config beside the test runner.
2. Copy those two files into a local directory inside the isolated .NET 4.0 VM.
3. Map one empty directory between the developer machine and the VM. The host and guest
   paths may differ. Do not share the repository itself.
4. In the VM, first run the proof:

   ```text
   C:\Net40Host\ysonet.Net40TestHost.exe --probe
   ```

   It must exit 0 and print `shape=netfx40`, `functorMembers=comparison,c`,
   `comparerCreate=absent`, and `workflowMembers=type,memberDatas`.
5. Start the shared-folder agent in the VM, using the guest path to the mapped directory:

   ```text
   C:\Net40Host\ysonet.Net40TestHost.exe --serve Z:\ysonet-net40
   ```

6. On the developer machine, set the host path to that same mapped directory and run the
   tier:

   ```text
   set YSONET_NET40_SHARED_DIR=D:\vm-share\ysonet-net40
   ysonet\bin\Debug\ysonet.Tests.exe --net40
   ```

## Deserializing a single payload by hand

Besides the agent, the host can deserialize one payload directly, which is useful when
reproducing a gadget in the VM:

```text
--deserialize FORMATTER FILE [--input auto|raw|base64]
```

- `FORMATTER` is `BinaryFormatter`, `SoapFormatter` or `LosFormatter`, matched
  case-insensitively.
- `FILE` is a path, or `-` to read the payload from stdin.
- `--input` says how `FILE` is read. The default `auto` detects base64 vs raw from the
  bytes: a base64-looking `BinaryFormatter` or `SoapFormatter` file is decoded, raw bytes
  are used as-is. `LosFormatter` is always read raw because its payload is itself a base64
  string (ASP.NET viewstate) that the formatter consumes directly. So a payload made with
  `ysonet.exe -g <gadget> -f <formatter> -c <cmd>` reads correctly with or without `-o`.

This matters because ysonet writes `BinaryFormatter` payloads as base64 by default, so the
saved file is text, not raw bytes. Either let `auto` decode it, generate with `-o raw` and
pass `--input raw`, or pass `--input base64` explicitly. Run `--help` for the full list.

Like the agent, this path re-proves the exact .NET Framework 4.0 shape and refuses before it
opens the payload if the process is not that runtime.

The agent has no network listener or remote-execution API. It claims a job only after the
parent has written `ready`, then launches a fresh one-shot worker in that job directory.
The worker proves the exact runtime shape again before it opens `payload.bin`. A payload
crash therefore does not kill the long-running agent, and an 85-second worker deadline
prevents a hung payload from wedging it permanently. Results and the effect marker return
through the mapped directory.

The member check invokes Workflow's own internal
`FormatterServicesNoSerializableCheck.GetSerializableMembers` routine. That is the exact
routine `ObjectSerializedRef` later uses for a non-serializable target; the public
`FormatterServices.GetSerializableMembers` rejects such a type and is not equivalent.

## Safety

This executable intentionally deserializes untrusted BinaryFormatter, SoapFormatter, and
LosFormatter data. Run it only in a disposable VM, use a dedicated empty shared directory,
do not place untrusted files in that directory, and give the VM no network access or other
shared folders. Stop the agent when the test run finishes and discard or restore the VM.
