# References

The research and talks that show HOW the gadgets and plugins in this tool were made: the
work that discovered each technique, and the sources a gadget or plugin points at from its
own file.

What does NOT belong here: a CVE database record, a vendor advisory or patch note, product
documentation, or a defensive guide. None of those teach how a payload is built, and the
gadget file already spells out the behaviour it relies on. Put a link like that in
[.NET deserialization research](dotnet-deserialization-research.md) instead, along with the
wider literature - related tools, uses in the wild, and CTF write-ups.

To see who found the gadgets and built the tool, see [Credits](credits.md).

Back to [documentation index](README.md).

## Additional reading

- [Friday the 13th: JSON Attacks - Slides](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf)
- [Friday the 13th: JSON Attacks - Whitepaper](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)
- [Friday the 13th: JSON Attacks - Video (demos)](https://www.youtube.com/watch?v=ZBfBYoK_Wr0)
- [Making Serialization Gadgets by Hand - .NET (VulnCheck)](https://www.vulncheck.com/blog/making-dotnet-gadgets)
- [Exploiting Hardened .NET Deserialization - Hexacon 2023 Whitepaper](https://github.com/thezdi/presentations/blob/main/2023_Hexacon/whitepaper-net-deser.pdf)
- [.NET Remoting Revisited](https://codewhitesec.blogspot.com/2022/01/dotnet-remoting-revisited.html)
- [SSO Wars: The Token Menace - Whitepaper (Black Hat USA 2019)](https://i.blackhat.com/USA-19/Wednesday/us-19-Munoz-SSO-Wars-The-Token-Menace-wp.pdf) - where Oleksandr Mirosh and Alvaro Munoz published `WSManPluginManagedEntryInstanceWrapper`, the type WSManPluginInstance builds.
- [More Than DoS: Progress Telerik UI for ASP.NET AJAX Unsafe Reflection (CVE-2025-3600), watchTowr Labs](https://labs.watchtowr.com/more-than-dos-progress-telerik-ui-for-asp-net-ajax-unsafe-reflection-cve-2025-3600/) - Piotr Bazydlo's write-up of the same finalizer used as a pre-auth denial of service. It reaches the type through unsafe reflection rather than a deserializer, and it is the clearest published description of why freeing the unallocated `GCHandle` terminates the process.
- [Finding and Exploiting .NET Remoting over HTTP using Deserialisation](https://soroush.me/blog/finding-and-exploiting-net-remoting-over-http-using-deserialisation)
- [Attacking .NET serialization](https://speakerdeck.com/pwntester/attacking-net-serialization)
- [Exploiting .NET Managed DCOM](https://projectzero.google/2017/04/exploiting-net-managed-dcom.html)
- [.NET Serialiception (SCRT)](https://blog.scrt.ch/2016/05/12/net-serialiception/) - the published DataSet `XmlSchema` XXE path, including the out-of-band file read, that DataSetXxe implements.
- [Exploit Remoting Service](https://github.com/tyranid/ExploitRemotingService)
- [Are you my Type? - Slides](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_Slides.pdf)
- [Are you my Type? - Whitepaper](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf)
- [Use of Deserialisation in .NET Framework Methods and Classes (session-token research)](https://soroush.me/downloadable/use_of_deserialisation_in_dotnet_framework_methods_and_classes.pdf)
- [ZDI-26-412: SharePoint CVE-2026-50522](https://www.zerodayinitiative.com/advisories/ZDI-26-412/) - the pre-auth WS-Federation trust endpoint and its deflate-only `SessionSecurityToken` cookie, which is the path the `SharePoint` plugin builds.

## Talks

- [Exploiting Hardened .NET Deserialization (HEXACON 2023) - Video](https://www.youtube.com/watch?v=_CJmUh0_uOM)
- [Second Breakfast: Implicit and Mutation-Based Serialization Vulnerabilities in .NET (DEF CON 31)](https://forum.defcon.org/node/245716)
  - [Slides](https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/Jonathan%20Birch%20-%20Second%20Breakfast%20Implicit%20and%20Mutation-Based%20Serialization%20Vulnerabilities%20in%20.NET.pdf)
  - [Whitepaper](https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/Jonathan%20Birch%20-%20Second%20Breakfast%20Implicit%20and%20Mutation-Based%20Serialization%20Vulnerabilities%20in%20.NET-whitepaper.pdf)
- [RCEvil.net (BSides Iowa)](https://illuminopi.com/assets/files/BSidesIowa_RCEvil.net_20190420.pdf)
- [.NET serialization: detecting and defending vulnerable endpoints](https://speakerdeck.com/pwntester/dot-net-serialization-detecting-and-defending-vulnerable-endpoints)
- [Dangerous Contents - Securing .Net Deserialization (Jonathan Birch, BlueHat v17)](https://www.youtube.com/watch?v=oxlD8VWWHE8)

## Cited by gadgets and plugins

Sources a gadget or plugin points at from its own file. Several more are in Additional
reading above: the Hexacon 2023 whitepaper, the "Are you my Type?" whitepaper, and the
ZDI-26-412 advisory.

- [Bypassing .NET Serialization Binders (Code White)](https://code-white.com/blog/2022-06-bypassing-dotnet-serialization-binders/) - the type-spoofing technique behind `DataSetTypeSpoof`.
- [By Executive Order, We Are Banning Blacklists: Veeam Backup and Replication CVE-2025-23120 (watchTowr Labs)](https://labs.watchtowr.com/by-executive-order-we-are-banning-blacklists-domain-level-rce-in-veeam-backup-replication-cve-2025-23120/) - the deny-list bypass `DataTableTypeSpoof` reproduces.
- [RogueRemotingServer](https://github.com/codewhitesec/RogueRemotingServer) - the malicious remoting server that replies with a gadget payload, used to fire `ObjRef`.
- [Exploiting deserialisation in ASP.NET via ViewState](https://soroush.me/blog/exploiting-deserialisation-in-asp-net-via-viewstate) - the ViewState research the `ViewState` plugin implements.
- [SharePoint and Pwn: RCE against SharePoint Server abusing DataSet](https://srcincite.io/blog/2020/07/20/sharepoint-and-pwn-remote-code-execution-against-sharepoint-server-abusing-dataset.html) - the DataSet path used by `DataSetOldBehaviour` and the `SharePoint` plugin.
- [ASP.NET resource files (.resx) and deserialisation issues](https://soroush.me/blog/asp-net-resource-files-resx-and-deserialization-issues) - the .resx research behind the `Resx` plugin, including the .NET Reflector advisory it produced. The [paper](https://soroush.me/downloadable/aspnet_resource_files_resx_deserialization_issues.pdf) is linked from the post.
- [SharePoint ToolShell chain (Viettel Cyber Security)](https://blog.viettelcybersecurity.com/sharepoint-toolshell/) - Khoa Dinh's CVE-2025-49704 analysis: the path the `SharePoint` plugin builds, and the array trick that gets past the SharePoint restriction, which `DataSetOldBehaviour` variant 2 reproduces.
- [SharePoint properties deserialization (Viettel Cyber Security)](https://blog.viettelcybersecurity.com/sharepoint_properties_deser/) - the CVE-2024-38018 property path the `SharePoint` plugin builds.
- [MessagePack Typeless mode deserialization exploits explained (Netwrix)](https://www.netwrix.com/en/resources/blog/generating-deserialization-payloads-for-messagepack-cs-typeless-mode/) - the resolver-substitution form of the `XmlDocument.InnerXml` XXE that `XmlDocumentXxe` variant 2 builds: setting `XmlResolver` before `InnerXml` removes the pre-4.5.2 version gate. It also records the target-side limit that MessagePack-CSharp below 2.3.75 calls every setter, so `XmlNode.Value` throws before the parse.
