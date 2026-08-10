# Where an entry goes and how it is written

## Contents
- Which page
- Sections of the research page
- Entry format
- What to reject
- Duplicates
- After editing

## Which page

`docs/references.md` (short list) answers one question: **does this show HOW a
gadget or plugin in this tool was made?** That means the research that discovered
the technique, and the sources a gadget or plugin points at from its own file.

These FAIL that test even when they are accurate and even when a gadget depends on
the behaviour they describe:

- a CVE database record (NVD, CVE.org)
- a vendor advisory, patch note, or KB page
- product documentation (`learn.microsoft.com`, `devblogs.microsoft.com`,
  `support.microsoft.com`, API reference pages)
- a defensive guide, a scanner rule, a cheat sheet

The gadget file already spells out the behaviour it relies on, so a documentation
link adds nothing a reader of that gadget does not already have. All of the above,
plus tools, uses in the wild, CTF write-ups and general reading, go in
`docs/dotnet-deserialization-research.md`.

The research page is a strict SUPERSET. Anything added to the short list is added
to the wide one too. `scripts/audit_links.py` fails if that breaks.

Two gadget files point at `docs/references.md` from a source comment, so a link
they rely on must not drift out of the short list. `audit_links.py` lists every
source-cited URL that is on neither page.

## Sections of the research page

| section | holds |
| --- | --- |
| Additional reading | articles, papers, docs, specs, standards, defensive guidance |
| Talks | conference talks: slides, whitepapers, recordings |
| Related tools | anything runnable: exploit generators, decoders, scanners, Burp extensions, labs |
| Uses in the wild > Research | write-ups that discover or analyse a technique or bug |
| Uses in the wild > Usage | advisories, vendor bulletins, incident and exploitation reports for a specific CVE |
| Uses in the wild > CTF write-ups | CTF and lab solutions |

Ambiguous cases:

- A conference talk with a paper AND a video: one entry per artifact, grouped
  under Talks, with the artifact named in the link text ("- Slides", "- Video",
  "- Whitepaper").
- A vendor KB that also explains the technique: Usage, unless it is what a gadget
  was built from.
- A tool plus its introducing blog post: the tool in Related tools, the post in
  Research.
- A deliberately vulnerable app or lab: Related tools.

## Entry format

Additional reading, Talks, Related tools use a Markdown link plus an optional note:

```
- [Title of the piece (Author or venue)](https://example.org/path) - what it teaches, in one line.
```

- Title: what the page calls itself. Add the author, venue or year in parentheses
  when the title alone is ambiguous.
- Note: only when the title does not already say what a reader gets. Say what the
  page teaches or what it is evidence of, not that it is "interesting" or
  "comprehensive".
- The note is what makes the list usable for research later. Prefer naming the
  concrete thing: the type, the formatter, the sink, the CVE, the product.

The Uses in the wild subsections are bare URLs, one per line, no link text:

```
- https://example.org/blog/some-rce-writeup
```

Keep that style there. Do not convert those lines to Markdown links.

Ordering: append to the end of the section. Do not re-sort an existing section.

## What to reject

- A page you did not open.
- A link-farm summary, an SEO rewrite of someone else's research, or an AI
  content mill page.
- A duplicate of something already listed, including the same article under a
  different host, an AMP URL, a syndicated copy, or a snapshot of a live page.
- A generic "what is insecure deserialization" page with nothing .NET specific,
  unless the list has nothing covering that ground at all.
- Anything behind a login or paywall with no snapshot.
- A social media post, unless it is the only published record of the technique.

## Duplicates

Before adding, check the URL inventory (`check_links.py --list`) for:

- the same URL
- the same path on a renamed host (`thezdi.com` and `zerodayinitiative.com`,
  `mandiant.com` and `cloud.google.com`, and any vendor blog that moved host)
- a snapshot of the URL you are about to add

The short list must have no duplicate at all. In the wide page, the same source
may legitimately appear once per artifact (slides and video), but never twice as
the same artifact.

## After editing

```
python .claude/skills/ysonet-curate-research-links/scripts/check_links.py --only "new-url-fragment" --no-cache
python .claude/skills/ysonet-curate-research-links/scripts/audit_links.py
```

Then report what was added and what was rejected. Do not commit.
