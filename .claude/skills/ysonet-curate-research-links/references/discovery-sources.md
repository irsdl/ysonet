# Where to look for new .NET deserialization material

## Contents
- How to run a sweep
- Query families
- Source families
- Per-source notes
- Coverage gaps worth checking

## How to run a sweep

1. Read the URL inventory first (`check_links.py --list`). Note which hosts are
   already well represented; those are the ones with more material you do not have.
2. Pick 10 to 20 queries across at least four query families below. One family
   alone returns one shape of result.
3. Search in batches, then fetch the promising hits. A snippet is not evidence.
4. For a host that already appears several times, go to its blog index or tag page
   and read the list rather than searching it one article at a time. That is the
   cheapest way to find everything it published since the newest entry you have.

## Query families

Vary the anchor term: `.NET deserialization`, `BinaryFormatter`, `ViewState`,
`ObjectStateFormatter`, `NetDataContractSerializer`, `LosFormatter`, `SoapFormatter`,
`DataContractSerializer`, `XamlReader`, `TypeNameHandling`, `JavaScriptSerializer`,
`SimpleTypeResolver`, `MessagePack typeless`, `.NET Remoting`, `DCOM`, `CLIXML`,
`PSObject`, `resx`, `DataSet`, `DataTable`, `gadget chain`, `serialization binder`.

- **Technique**: `<anchor> gadget chain`, `<anchor> bypass binder`, `new .NET
  deserialization gadget`, `serialization surrogate abuse`, `getter gadget .NET`.
- **Product and CVE**: `<product> deserialization RCE`, `CVE-<year>-<n> .NET
  deserialization analysis`, `<product> ViewState machine key RCE`. Products that
  keep producing: SharePoint, Exchange, Telerik, Sitecore, Veeam, SolarWinds,
  Progress (MOVEit, WhatsUp Gold, WS_FTP), Kentico, Umbraco, DotNetNuke, Ivanti,
  Citrix, Gladinet, TeamCity, Rockwell, Siemens, Schneider.
- **Tooling**: `ysoserial.net fork`, `.NET deserialization scanner`, `ViewState
  decoder`, `machine key scanner`, `gadget discovery tool .NET`, plus GitHub topic
  and code search.
- **Defence**: `BinaryFormatter migration`, `deserialization denylist bypass`,
  `System.Text.Json polymorphism security`, `serialization binder hardening`.
- **Conference**: `<conference> <year> .NET deserialization`, and the archive index
  pages under Source families.
- **Non-English**: much of the best formatter-by-formatter analysis is Chinese,
  Japanese, Korean or Vietnamese. Search the anchor term together with the local
  word for deserialization (translate it first; do not put the glyphs in this
  file, the repo style is plain ASCII), and search the known hosts directly:
  `xz.aliyun.com`, `anquanke.com`, `cnblogs.com`, `zhuanlan.zhihu.com`, `exp10it.io`,
  `3gstudent.github.io`, `y4er.com`, `zenn.dev`, `blog.viettelcybersecurity.com`.

## Source families

**Research vendors that publish .NET deserialization regularly**: Code White,
watchTowr Labs, Zero Day Initiative (blog and advisories), Synacktiv,
Bishop Fox, GoSecure, Assetnote / Searchlight Cyber, srcincite, Rapid7,
Mandiant / Google Cloud Threat Intelligence, Unit 42, Huntress, TrustedSec,
Black Lantern Security, Claroty Team82, STAR Labs, Viettel Cyber Security,
modzero, SEC Consult, Compass Security, Truesec, eye security, Kudelski.

**Independent researchers with long .NET output**: James Forshaw (tiraniddo.dev,
Project Zero), Alvaro Munoz, Oleksandr Mirosh, Piotr Bazydlo, Jonathan Birch,
Markus Wulftange, Dor Tumarkin, Y4er, Ivan1ee, nice0e3, frycos,
peterjson / testbnull, Orange Tsai, 0xdf.

**Conference archives**: Black Hat (`i.blackhat.com`, `media.blackhat.com`),
DEF CON media server, HEXACON, OffensiveCon, NorthSec, Nullcon, POC, TyphoonCon,
BSides, AppSec USA / OWASP Global, RomHack, Hack in the Box.

**Advisory and catalogue sources** (Usage section material): ZDI advisories, GitHub
Security Advisories (`github.com/advisories`), NVD, CISA KEV and ICS advisories,
vendor KBs, Snyk, attackerkb, exploit-db, packet storm.

**Code and tools**: GitHub topics `deserialization`, `ysoserial`, `viewstate`,
`dotnet-security`; GitHub search for `ysoserial.net` and `ysonet` in code and in
readmes; Burp BApp Store; NuGet packages claiming safe deserialization.

**Aggregators to mine, not to cite**: PayloadsAllTheThings, HackTricks, awesome
lists, `.NET-Deserialization-Cheat-Sheet` style repos. Follow their links to the
primary source and cite that instead.

## Per-source notes

- ZDI publishes the same work twice, on `thezdi.com` and `zerodayinitiative.com`.
  Pick one, and check the other form is not already listed.
- Mandiant moved to `cloud.google.com/blog/topics/threat-intelligence/`. Several
  consultancies have rebranded or reorganised their research blog onto a new host,
  so old URLs on those hosts are dead and only live in the Wayback Machine. When a
  whole class of citations breaks at once, suspect a host rename, not a lost page.
- Medium, HackMD, and Zenn posts disappear without warning; they are prime
  candidates for a snapshot even while alive.
- Telerik, Veeam, SolarWinds and Progress KB pages get rewritten in place. The
  content can change under a stable URL, so re-read before trusting an old note.
- X / Twitter threads are usually unreachable to the checker. Only add one when it
  is the sole published record, and prefer a snapshot URL.

## Coverage gaps worth checking

Ask these when deciding what to search for, rather than repeating the same sweep:

- Formatters with thin coverage in the list: `MessagePack` typeless, `Wire` /
  `Hyperion`, `ServiceStack.Text`, `YamlDotNet`, `fastJSON`, `protobuf-net`
  DynamicType, `SharpSerializer`.
- Modern .NET (not Framework): what replaced BinaryFormatter, what is still
  exploitable on .NET 8 and later, the compatibility package.
- Non-RCE outcomes: file write, file read, SSRF, denial of service, sandbox escape,
  privilege escalation through a serializer.
- Sinks outside web apps: desktop apps, installers, game engines, ICS and OT
  software, developer tooling.
- Detection and forensics: hunting rules, IIS and Exchange log artifacts, YARA.
- Anything from the last 12 months on a product already in the list; those recur.
