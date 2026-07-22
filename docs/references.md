# References

Learn more about .NET deserialization: background reading, talks, related tools, and real-world uses of YSoNet / ysoserial.net. To see who found the gadgets and built the tool, see [Credits](credits.md).

Back to [documentation index](README.md).

## Additional reading

- [Friday the 13th: JSON Attacks - Slides](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf)
- [Friday the 13th: JSON Attacks - Whitepaper](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)
- [Friday the 13th: JSON Attacks - Video (demos)](https://www.youtube.com/watch?v=ZBfBYoK_Wr0)
- [Making Serialization Gadgets by Hand - .NET (VulnCheck)](https://www.vulncheck.com/blog/making-dotnet-gadgets)
- [BinaryFormatter is removed from .NET 9](https://devblogs.microsoft.com/dotnet/binaryformatter-removed-from-dotnet-9/)
- [Exploiting Hardened .NET Deserialization - Hexacon 2023 Whitepaper](https://github.com/thezdi/presentations/blob/main/2023_Hexacon/whitepaper-net-deser.pdf)
- [Bypassing .NET Serialization Binders](https://codewhitesec.blogspot.com/2022/06/bypassing-dotnet-serialization-binders.html)
- [.NET Remoting Revisited](https://codewhitesec.blogspot.com/2022/01/dotnet-remoting-revisited.html)
- [Microsoft: BinaryFormatter security guide](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide)
- [Microsoft CA3075: Insecure DTD processing](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca3075)
- [SSO Wars: The Token Menace - Whitepaper (Black Hat USA 2019)](https://i.blackhat.com/USA-19/Wednesday/us-19-Munoz-SSO-Wars-The-Token-Menace-wp.pdf)
- [Finding and Exploiting .NET Remoting over HTTP using Deserialisation](https://web.archive.org/web/20190330065542/https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/march/finding-and-exploiting-.net-remoting-over-http-using-deserialisation/)
- [Attacking .NET serialization](https://speakerdeck.com/pwntester/attacking-net-serialization)
- [Exploiting .NET Managed DCOM](https://googleprojectzero.blogspot.com.es/2017/04/exploiting-net-managed-dcom.html)
- [.NET Serialiception (SCRT)](https://blog.scrt.ch/2016/05/12/net-serialiception/)
- [Exploit Remoting Service](https://github.com/tyranid/ExploitRemotingService)
- [Are you my Type? - Slides](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_Slides.pdf)
- [Are you my Type? - Whitepaper](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf)
- [Use of Deserialisation in .NET Framework Methods and Classes (session-token research)](https://soroush.me/downloadable/use_of_deserialisation_in_dotnet_framework_methods_and_classes.pdf)
- [SharePoint CVE-2026-50522: ZDI-26-412 advisory](https://www.zerodayinitiative.com/advisories/ZDI-26-412/)
- [SharePoint CVE-2026-50522: NVD record](https://nvd.nist.gov/vuln/detail/CVE-2026-50522)
- [SharePoint CVE-2026-50522: Microsoft update](https://support.microsoft.com/en-us/servicing/office/update/2026/5002882)

## Talks

- [Friday the 13th: JSON Attacks](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf)
- [Exploiting Hardened .NET Deserialization (HEXACON 2023) - Video](https://www.youtube.com/watch?v=_CJmUh0_uOM)
- [Second Breakfast: Implicit and Mutation-Based Serialization Vulnerabilities in .NET (DEF CON 31)](https://forum.defcon.org/node/245716)
  - [Slides](https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/Jonathan%20Birch%20-%20Second%20Breakfast%20Implicit%20and%20Mutation-Based%20Serialization%20Vulnerabilities%20in%20.NET.pdf)
  - [Whitepaper](https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/Jonathan%20Birch%20-%20Second%20Breakfast%20Implicit%20and%20Mutation-Based%20Serialization%20Vulnerabilities%20in%20.NET-whitepaper.pdf)
- [RCEvil.net (BSides Iowa)](https://illuminopi.com/assets/files/BSidesIowa_RCEvil.net_20190420.pdf)
- [Security boot camp for .NET developers (Confoo)](https://gosecure.github.io/presentations/2018-03-18-confoo_mtl/Security_boot_camp_for_.NET_developers_Confoo_v2.pdf)
- [Nullcon Goa 2018 slides](https://nullcon.net/website/archives/pdf/goa-2018/rohit-slides.pdf)
- [.NET serialization: detecting and defending vulnerable endpoints](https://speakerdeck.com/pwntester/dot-net-serialization-detecting-and-defending-vulnerable-endpoints)
- [Attacking .NET serialization](https://speakerdeck.com/pwntester/attacking-net-serialization)
- [Dangerous Contents - Securing .Net Deserialization (Jonathan Birch, BlueHat v17)](https://www.youtube.com/watch?v=oxlD8VWWHE8)

## Related tools

- [ProjectDiscovery DSL deserialization package](https://pkg.go.dev/github.com/projectdiscovery/dsl/deserialization) - Go helper that generates .NET (and Java) deserialization gadgets, reusing ysoserial-style gadget names.
- [GadgetExplorer](https://github.com/nines-nine/GadgetExplorer) - tooling to discover .NET deserialization gadget chains.
- [Metasploit .NET deserialization library / CLI](https://rapid7.github.io/metasploit-framework/docs/development/developing-modules/libraries/deserialization/dot-net-deserialization.html) - `Msf::Util::DotNetDeserialization` and `tools/payloads/ysoserial/dot_net.rb`, argument-compatible with YSoSerial.NET and reusing its gadget/formatter names, including ViewState signing. See also the [API docs](https://docs.metasploit.com/api/Msf/Util/DotNetDeserialization.html).
- [ViewStatePayloadGenerator](https://github.com/pwntester/ViewStatePayloadGenerator)
- [viewgen](https://github.com/0xACB/viewgen)
- [RCEvil.NET](https://github.com/Illuminopi/RCEvil.NET)
- [GadgetToJScript](https://github.com/med0x2e/GadgetToJScript) - generates .NET serialized gadgets that trigger assembly load/execution via BinaryFormatter from JS/VBS/VBA.
- [YSoSerial.Net](https://github.com/pwntester/ysoserial.net) - the original .NET tool by Alvaro Munoz (@pwntester) that YSoNet continues and updates.
- [DotNetToJScript](https://github.com/tyranid/DotNetToJScript) - embeds a BinaryFormatter-serialized .NET object into JScript to bootstrap in-memory assembly loading.
- [ysoserial](https://github.com/frohoff/ysoserial) - Chris Frohoff's original Java tool that inspired the .NET port.

## Uses in the wild

A collection of research and advisories that use YSoNet / ysoserial.net.

### Research

- https://www.resecurity.com/blog/article/from-web-request-to-domain-compromise-understanding-the-july-2026-sharepoint-attacks
- https://kudelskisecurity.com/research/persistent-exploitation-of-asp-net-components-fuels-remote-code-execution-attacks
- https://www.thezdi.com/blog/2024/9/18/exploiting-exchange-powershell-after-proxynotshell-part-3-dll-loading-chain-for-rce
- https://www.thezdi.com/blog/2024/9/11/exploiting-exchange-powershell-after-proxynotshell-part-2-approvedapplicationcollection
- https://www.thezdi.com/blog/2024/9/4/exploiting-exchange-powershell-after-proxynotshell-part-1-multivaluedproperty
- https://www.truesec.com/hub/blog/attacking-powershell-clixml-deserialization
- https://exp10it.io/posts/dotnet-new-deserialization-gadgets/
- https://exp10it.io/posts/dotnet-insecure-serialization/
- https://code-white.com/blog/teaching-the-old-net-remoting-new-exploitation-tricks/
- https://blog.netwrix.com/2023/04/10/generating-deserialization-payloads-for-messagepack-cs-typeless-mode/
- https://code-white.com/blog/leaking-objrefs-to-exploit-http-dotnet-remoting/
- https://community.microfocus.com/t5/Security-Research-Blog/New-NET-deserialization-gadget-for-compact-payload-When-size/ba-p/1763282
- https://www.mdsec.co.uk/2020/04/introducing-ysoserial-net-april-2020-improvements/
- https://muffsec.com/blog/finding-a-new-datacontractserializer-rce-gadget-chain/
- https://research.nccgroup.com/2019/08/23/getting-shell-with-xamlx-files/
- https://soroush.secproject.com/blog/2019/08/uploading-web-config-for-fun-and-profit-2/
- https://soroush.secproject.com/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/
- https://web.archive.org/web/20190330065542/https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/march/finding-and-exploiting-.net-remoting-over-http-using-deserialisation/
- https://swapneildash.medium.com/deep-dive-into-net-viewstate-deserialization-and-its-exploitation-54bf5b788817
- https://web.archive.org/web/20191210003556/https://www.nccgroup.trust/uk/our-research/use-of-deserialisation-in-.net-framework-methods-and-classes/
- https://www.netspi.com/blog/technical/adversary-simulation/re-animating-activitysurrogateselector/
- https://web.archive.org/web/20190401191940/https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/december/beware-of-deserialisation-in-.net-methods-and-classes-code-execution-via-paste/
- https://web.archive.org/web/20180903005001/https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/august/aspnet-resource-files-resx-and-deserialisation-issues/
- https://www.alphabot.com/security/blog/2017/net/How-to-configure-Json.NET-to-create-a-vulnerable-web-API.html

### Usage

- https://thehackernews.com/2026/07/cisa-adds-exploited-sharepoint-rce-zero.html
- https://www.rapid7.com/blog/post/ve-cve-2026-55040-microsoft-sharepoint-jwt-token-authentication-bypass-fixed/
- https://thehackernews.com/2026/05/microsoft-patches-sharepoint-rce-flaw.html
- https://cloud.google.com/blog/topics/threat-intelligence/viewstate-deserialization-zero-day-vulnerability
- https://research.eye.security/sharepoint-under-siege/
- https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/
- https://success.trendmicro.com/en-US/solution/KA-0019926
- https://www.bleepingcomputer.com/news/security/centrestack-rce-exploited-as-zero-day-to-breach-file-sharing-servers/
- https://kudelskisecurity.com/research/gladinet-centrestack-and-gladinet-triofox---critical-rce
- https://labs.watchtowr.com/by-executive-order-we-are-banning-blacklists-domain-level-rce-in-veeam-backup-replication-cve-2025-23120/
- https://www.broadcom.com/support/security-center/protection-bulletin/cve-2024-38094-microsoft-sharepoint-deserialization-vulnerability-exploited-in-the-wild
- https://labs.watchtowr.com/veeam-backup-response-rce-with-auth-but-mostly-without-auth-cve-2024-40711-2/
- https://github.com/gh-ost00/CVE-2024-4358
- https://www.telerik.com/report-server/documentation/knowledge-base/deserialization-vulnerability-cve-2024-1800
- https://blog.blacklanternsecurity.com/p/aspnet-cryptography-for-pentesters
- https://www.zerodayinitiative.com/blog/2023/9/21/finding-deserialization-bugs-in-the-solarwind-platform
- https://www.assetnote.io/resources/research/moveit-transfer-rce-part-two-cve-2023-34362
- https://starlabs.sg/blog/2023/04-microsoft-exchange-powershell-remoting-deserialization-leading-to-rce-cve-2023-21707/
- https://www.thezdi.com/blog/2023/2/27/cve-2022-38108-rce-in-solarwinds-network-performance-monitor
- https://www.microsoft.com/en-us/security/blog/2022/09/30/analyzing-attacks-using-the-exchange-vulnerabilities-cve-2022-41040-and-cve-2022-41082/
- https://web.archive.org/web/20220619183339/https://starlabs.sg/blog/2022/05/new-wine-in-old-bottle-microsoft-sharepoint-post-auth-deserialization-rce-cve-2022-29108/
- https://www.mdsec.co.uk/2022/03/abc-code-execution-for-veeam/
- https://mogwailabs.de/en/blog/2022/01/vulnerability-spotlight-rce-in-ajax.net-professional/
- https://medium.com/@frycos/searching-for-deserialization-protection-bypasses-in-microsoft-exchange-cve-2022-21969-bfa38f63a62d
- https://testbnull.medium.com/note-nhanh-v%E1%BB%81-binaryformatter-binder-v%C3%A0-cve-2022-23277-6510d469604c
- https://gmo-cybersecurity.com/blog/net-remoting-english/
- https://www.mandiant.com/resources/hunting-deserialization-exploits
- https://testbnull.medium.com/some-notes-of-microsoft-exchange-deserialization-rce-cve-2021-42321-f6750243cdcd
- https://peterjson.medium.com/some-notes-about-microsoft-exchange-deserialization-rce-cve-2021-42321-110d04e8852
- https://blog.assetnote.io/2021/11/02/sitecore-rce/
- https://www.mdsec.co.uk/2021/09/nsa-meeting-proposal-for-proxyshell/
- https://labs.withsecure.com/blog/autocad-designing-a-kill-chain/
- https://www.zerodayinitiative.com/blog/2021/6/1/cve-2021-31181-microsoft-sharepoint-webpart-interpretation-conflict-remote-code-execution-vulnerability
- https://blog.liquidsec.net/2021/06/01/asp-net-cryptography-for-pentesters/
- https://www.zerodayinitiative.com/blog/2021/3/17/cve-2021-27076-a-replay-style-deserialization-attack-against-sharepoint
- https://srcincite.io/pocs/cve-2020-16952.py.txt
- https://srcincite.io/blog/2020/07/20/sharepoint-and-pwn-remote-code-execution-against-sharepoint-server-abusing-dataset.html
- https://www.modzero.com/modlog/archives/2020/06/16/mz-20-03_-_new_security_advisory_regarding_vulnerabilities_in__net/index.html
- https://www.mdsec.co.uk/2020/05/analysis-of-cve-2020-0605-code-execution-using-xps-files-in-net/
- https://www.thezdi.com/blog/2020/4/28/cve-2020-0932-remote-code-execution-on-microsoft-sharepoint-using-typeconverters
- https://www.zerodayinitiative.com/blog/2020/4/28/cve-2020-0932-remote-code-execution-on-microsoft-sharepoint-using-typeconverters
- https://www.mdsec.co.uk/2020/02/cve-2020-0618-rce-in-sql-server-reporting-services-ssrs/
- https://www.thezdi.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys
- https://www.zerodayinitiative.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys
- https://blog.devsecurity.eu/en/blog/dnspy-deserialization-vulnerability
- https://www.youtube.com/watch?v=ZcOZNAmKR0c&feature=youtu.be
- https://bishopfox.com/blog/cve-2019-18935-remote-code-execution-in-telerik-ui
- https://github.com/noperator/CVE-2019-18935
- https://www.zerodayinitiative.com/blog/2019/10/23/cve-2019-1306-are-you-my-index
- https://dreadlocked.github.io/2019/10/25/kentico-cms-rce/
- https://www.zerodayinitiative.com/blog/2019/3/13/cve-2019-0604-details-of-a-microsoft-sharepoint-rce-vulnerability
- https://www.synacktiv.com/ressources/advisories/Sitecore_CSRF_deserialize_RCE.pdf
- https://www.nccgroup.trust/uk/our-research/technical-advisory-multiple-vulnerabilities-in-smartermail/
- https://www.nccgroup.trust/uk/our-research/technical-advisory-code-execution-by-viewing-resource-files-in-net-reflector/
- https://cert.360.cn/warning/detail?id=e689288863456481733e01b093c986b6
- https://medium.com/@qazbnm456/umbraco-lfi-exploitation-d32803661fa3
- https://notsosecure.com/exploiting-viewstate-deserialization-using-blacklist3r-and-ysoserial-net
- https://soroush.secproject.com/blog/2018/12/story-of-two-published-rces-in-sharepoint-workflows/
- https://srcincite.io/blog/2018/08/31/you-cant-contain-me-analyzing-and-exploiting-an-elevation-of-privilege-in-docker-for-windows.html
- https://www.zerodayinitiative.com/blog/2018/8/14/voicemail-vandalism-getting-remote-code-execution-on-microsoft-exchange-server
- https://www.redteam-pentesting.de/de/advisories/rt-sa-2017-014/-cyberark-password-vault-web-access-remote-code-execution
- https://labs.mwrinfosecurity.com/advisories/milestone-xprotect-net-deserialization-vulnerability/
- https://github.com/murataydemir/CVE-2017-9822
- https://devme4f.github.io/posts/2023/dotnetnuke_cve-2017-9822/

### CTF write-ups

- https://0xdf.gitlab.io/2022/10/15/htb-perspective.html
- https://cyku.tw/ctf-hitcon-2018-why-so-serials/
- https://github.com/orangetw/My-CTF-Web-Challenges
- https://xz.aliyun.com/t/3019
