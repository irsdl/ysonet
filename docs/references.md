# References

Learn more about .NET deserialization: background reading, talks, related tools, and real-world uses of YSoNet / ysoserial.net. To see who found the gadgets and built the tool, see [Credits](credits.md).

Back to [documentation index](README.md).

## Additional reading

- [Attacking .NET serialization](https://speakerdeck.com/pwntester/attacking-net-serialization)
- [Friday the 13th: JSON Attacks - Slides](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf)
- [Friday the 13th: JSON Attacks - Whitepaper](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)
- [Friday the 13th: JSON Attacks - Video (demos)](https://www.youtube.com/watch?v=ZBfBYoK_Wr0)
- [Are you my Type? - Slides](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_Slides.pdf)
- [Are you my Type? - Whitepaper](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf)
- [Exploiting .NET Managed DCOM](https://googleprojectzero.blogspot.com.es/2017/04/exploiting-net-managed-dcom.html)
- [Exploit Remoting Service](https://github.com/tyranid/ExploitRemotingService)
- [Finding and Exploiting .NET Remoting over HTTP using Deserialisation](https://web.archive.org/web/20190330065542/https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/march/finding-and-exploiting-.net-remoting-over-http-using-deserialisation/)
- [.NET Remoting Revisited](https://codewhitesec.blogspot.com/2022/01/dotnet-remoting-revisited.html)
- [Bypassing .NET Serialization Binders](https://codewhitesec.blogspot.com/2022/06/bypassing-dotnet-serialization-binders.html)
- [Exploiting Hardened .NET Deserialization - Hexacon 2023 Whitepaper](https://github.com/thezdi/presentations/blob/main/2023_Hexacon/whitepaper-net-deser.pdf)

## Talks

- [Friday the 13th: JSON Attacks](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf)
- [Attacking .NET serialization](https://speakerdeck.com/pwntester/attacking-net-serialization)
- [.NET serialization: detecting and defending vulnerable endpoints](https://speakerdeck.com/pwntester/dot-net-serialization-detecting-and-defending-vulnerable-endpoints)
- [Security boot camp for .NET developers (Confoo)](https://gosecure.github.io/presentations/2018-03-18-confoo_mtl/Security_boot_camp_for_.NET_developers_Confoo_v2.pdf)
- [RCEvil.net (BSides Iowa)](https://illuminopi.com/assets/files/BSidesIowa_RCEvil.net_20190420.pdf)
- [Nullcon Goa 2018 slides](https://nullcon.net/website/archives/pdf/goa-2018/rohit-slides.pdf)

## Related tools

- [ViewStatePayloadGenerator](https://github.com/pwntester/ViewStatePayloadGenerator)
- [viewgen](https://github.com/0xACB/viewgen)
- [RCEvil.NET](https://github.com/Illuminopi/RCEvil.NET)

## Uses in the wild

A collection of research and advisories that use YSoNet / ysoserial.net.

### Research

- https://www.alphabot.com/security/blog/2017/net/How-to-configure-Json.NET-to-create-a-vulnerable-web-API.html
- https://web.archive.org/web/20190401191940/https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/december/beware-of-deserialisation-in-.net-methods-and-classes-code-execution-via-paste/
- https://web.archive.org/web/20190330065542/https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/march/finding-and-exploiting-.net-remoting-over-http-using-deserialisation/
- https://web.archive.org/web/20180903005001/https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/august/aspnet-resource-files-resx-and-deserialisation-issues/
- https://web.archive.org/web/20191210003556/https://www.nccgroup.trust/uk/our-research/use-of-deserialisation-in-.net-framework-methods-and-classes/
- https://community.microfocus.com/t5/Security-Research-Blog/New-NET-deserialization-gadget-for-compact-payload-When-size/ba-p/1763282
- https://soroush.secproject.com/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/
- https://swapneildash.medium.com/deep-dive-into-net-viewstate-deserialization-and-its-exploitation-54bf5b788817
- https://research.nccgroup.com/2019/08/23/getting-shell-with-xamlx-files/
- https://soroush.secproject.com/blog/2019/08/uploading-web-config-for-fun-and-profit-2/
- https://www.mdsec.co.uk/2020/04/introducing-ysoserial-net-april-2020-improvements/
- https://www.netspi.com/blog/technical/adversary-simulation/re-animating-activitysurrogateselector/
- https://blog.netwrix.com/2023/04/10/generating-deserialization-payloads-for-messagepack-cs-typeless-mode/
- https://code-white.com/blog/leaking-objrefs-to-exploit-http-dotnet-remoting/
- https://code-white.com/blog/teaching-the-old-net-remoting-new-exploitation-tricks/

### Usage

- https://cert.360.cn/warning/detail?id=e689288863456481733e01b093c986b6
- https://www.redteam-pentesting.de/de/advisories/rt-sa-2017-014/-cyberark-password-vault-web-access-remote-code-execution
- https://labs.mwrinfosecurity.com/advisories/milestone-xprotect-net-deserialization-vulnerability/
- https://soroush.secproject.com/blog/2018/12/story-of-two-published-rces-in-sharepoint-workflows/
- https://srcincite.io/blog/2018/08/31/you-cant-contain-me-analyzing-and-exploiting-an-elevation-of-privilege-in-docker-for-windows.html
- https://www.zerodayinitiative.com/blog/2018/8/14/voicemail-vandalism-getting-remote-code-execution-on-microsoft-exchange-server
- https://www.synacktiv.com/ressources/advisories/Sitecore_CSRF_deserialize_RCE.pdf
- https://www.zerodayinitiative.com/blog/2019/3/13/cve-2019-0604-details-of-a-microsoft-sharepoint-rce-vulnerability
- https://www.zerodayinitiative.com/blog/2019/10/23/cve-2019-1306-are-you-my-index
- https://labs.withsecure.com/blog/autocad-designing-a-kill-chain/
- https://www.nccgroup.trust/uk/our-research/technical-advisory-multiple-vulnerabilities-in-smartermail/
- https://www.nccgroup.trust/uk/our-research/technical-advisory-code-execution-by-viewing-resource-files-in-net-reflector/
- https://blog.devsecurity.eu/en/blog/dnspy-deserialization-vulnerability
- https://www.mdsec.co.uk/2020/02/cve-2020-0618-rce-in-sql-server-reporting-services-ssrs/
- https://www.thezdi.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys
- https://www.thezdi.com/blog/2020/4/28/cve-2020-0932-remote-code-execution-on-microsoft-sharepoint-using-typeconverters
- https://www.mdsec.co.uk/2020/05/analysis-of-cve-2020-0605-code-execution-using-xps-files-in-net/
- https://srcincite.io/blog/2020/07/20/sharepoint-and-pwn-remote-code-execution-against-sharepoint-server-abusing-dataset.html
- https://srcincite.io/pocs/cve-2020-16952.py.txt
- https://www.zerodayinitiative.com/blog/2020/4/28/cve-2020-0932-remote-code-execution-on-microsoft-sharepoint-using-typeconverters
- https://www.modzero.com/modlog/archives/2020/06/16/mz-20-03_-_new_security_advisory_regarding_vulnerabilities_in__net/index.html
- https://www.zerodayinitiative.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys
- https://www.zerodayinitiative.com/blog/2021/6/1/cve-2021-31181-microsoft-sharepoint-webpart-interpretation-conflict-remote-code-execution-vulnerability
- https://blog.liquidsec.net/2021/06/01/asp-net-cryptography-for-pentesters/
- https://peterjson.medium.com/some-notes-about-microsoft-exchange-deserialization-rce-cve-2021-42321-110d04e8852
- https://www.mdsec.co.uk/2021/09/nsa-meeting-proposal-for-proxyshell/
- https://medium.com/@frycos/searching-for-deserialization-protection-bypasses-in-microsoft-exchange-cve-2022-21969-bfa38f63a62d
- https://www.zerodayinitiative.com/blog/2021/3/17/cve-2021-27076-a-replay-style-deserialization-attack-against-sharepoint
- https://blog.assetnote.io/2021/11/02/sitecore-rce/
- https://web.archive.org/web/20220619183339/https://starlabs.sg/blog/2022/05/new-wine-in-old-bottle-microsoft-sharepoint-post-auth-deserialization-rce-cve-2022-29108/
- https://gmo-cybersecurity.com/blog/net-remoting-english/
- https://www.mdsec.co.uk/2022/03/abc-code-execution-for-veeam/
- https://www.mandiant.com/resources/hunting-deserialization-exploits
- https://mogwailabs.de/en/blog/2022/01/vulnerability-spotlight-rce-in-ajax.net-professional/
- https://testbnull.medium.com/some-notes-of-microsoft-exchange-deserialization-rce-cve-2021-42321-f6750243cdcd
- https://testbnull.medium.com/note-nhanh-v%E1%BB%81-binaryformatter-binder-v%C3%A0-cve-2022-23277-6510d469604c
- https://www.zerodayinitiative.com/blog/2023/9/21/finding-deserialization-bugs-in-the-solarwind-platform
- https://www.youtube.com/watch?v=ZcOZNAmKR0c&feature=youtu.be

### CTF write-ups

- https://cyku.tw/ctf-hitcon-2018-why-so-serials/
- https://xz.aliyun.com/t/3019
