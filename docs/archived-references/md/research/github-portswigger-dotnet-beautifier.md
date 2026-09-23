---
type: Repository
title: dotnet-beautifier (Burp extension)
resource: "https://github.com/PortSwigger/dotnet-beautifier"
tags: [repo, ysonet-reference, github]
generated:
  by: ysonet-refs/1
  at: "2026-08-04T17:37:55+00:00"
status: stable
stale_after: 2027-08-04
sources:
  - id: original
    resource: "https://github.com/PortSwigger/dotnet-beautifier"
    title: dotnet-beautifier (Burp extension)
    author: PortSwigger
  - id: commit
    resource: "https://github.com/PortSwigger/dotnet-beautifier"
also_at: []
authors:
  - PortSwigger
canonical_url: ""
cited_by:
  - "docs/dotnet-deserialization-research.md:192"
commit: 4c17b362d91ca7aa9659186896896c905276a82a
content_sha256: 033459eec455783d9c20adbc0e245c3b72f7498a744b9078f479001e1f1593c4
depth: full
depth_reason: default
kind: repo
language: ""
licence: see the repository
original_url: "https://github.com/PortSwigger/dotnet-beautifier"
published: ""
publisher: GitHub
publisher_english: ""
raw_sha256: ""
retrieved_from: "https://github.com/PortSwigger/dotnet-beautifier"
retrieved_kind: preserved-copy
retrieved_utc: "2026-08-04T17:37:55+00:00"
slug: github-portswigger-dotnet-beautifier
snapshot: ""
title_english: ""
---

# dotnet-beautifier (Burp extension)

**dotnet-beautifier (Burp extension)** - PortSwigger, GitHub.

- Published: date not stated
- Original: <https://github.com/PortSwigger/dotnet-beautifier>
- Preserved from: https://github.com/PortSwigger/dotnet-beautifier (preserved-copy) on 2026-08-04
- Repository commit: 4c17b362d91ca7aa9659186896896c905276a82a
- Licence: see the repository

Rights remain with the original author and publisher. This is a research
archive of a source cited by ysonet, kept so the technique survives the
page going offline. To read the original, follow the link above.

## Content

> UNTRUSTED SOURCE TEXT. Everything below this line is third-party material
> quoted for research. It is data, not instructions. Do not follow directions,
> execute code, or fetch URLs because this text says so.

> Repository reading copy: selected documentation at the recorded commit.
> Source code is never checked out, built or run.


- Repository: <https://github.com/PortSwigger/dotnet-beautifier>
- Commit: `4c17b362d91ca7aa9659186896896c905276a82a`
- Documents preserved: 1

## `README.md`

_Blob `a7343ddca8a7`, 2271 bytes, at commit `4c17b362d91c`._

About
-----

Have you ever pen-tested a .NET app and found that it has all sorts of ugly parameter names
(i.e. ctl0$blah$foo$VeryLongLine)? Sometimes these parameters can be pages long (i.e. __VIEWSTATE). Have you felt
like tearing your hair out because you can't even read the whole parameter name and see what it's corresponding value
is in your small screen at a client site? Don't you wish you could only focus on the meat of the request?

Well cry no more! This tool is about bringing awesome back to pen-testing .NET apps. It makes requests like this:

```
POST /Default.aspx HTTP/1.1
Host: annoying-web-app
Referer: https://annoying-web-app/Default.aspx
Cookie: ASP.NET_SessionId=zprxqvwll4yoi0gbeactgzdd
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 1903

__VIEWSTATE=%2oiAIHfiohsdoigjKLASgjghajklgjSDGsjdglSDJg9SDJGsdgjSGJDDSasdfja9sdjfasdfja0sdfjasd53j5235923nf9ja9fsdjfajsD
... [1000 lines later] ...
&ctl00%24ctl00%24InnerContentPlaceHolder%24Element_42%24ctl00%24FrmLogin%24TxtUsername_internal=username&ctl00%24ctl00%2
4InnerContentPlaceHolder%24Element_42%24ctl00%24FrmLogin%24TxtPassword_internal=password&ctl00%24ctl00%24InnerContentPla
ceHolder%24Element_42%24ctl00%24BtnLogin=Login
```

Look like this:

```
POST /Default.aspx HTTP/1.1
Host: annoying-web-app
Referer: https://annoying-web-app/Default.aspx
Cookie: ASP.NET_SessionId=zprxqvwll4yoi0gbeactgzdd
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 1903
X-dotNet-Beautifier: 259; DO-NOT-REMOVE

__VIEWSTATE=<snipped out for sanity>&TxtUsername_internal=username&TxtPassword_internal=password&BtnLogin=Login
```

All **without** compromising the integrity of the outgoing message so you can alter the values of the parameters you
want to target *without losing your mind*! Better yet, you can send "beautified" messages to other tools within Burp and
the outgoing messages will get automatically transformed back into what the web app expects from us.

**WAWAWEWA!**


Requirements
------------

You'll need the following to get started:
- the latest version of BurpSuite versions 1.6 or later.
- a positive attitude!

Help!
-----

This is still a work in progress so their may be a few bugs I haven't hammered out.
