# Archive pipeline: situational recipes

The conditional recipes for `tools/references/refs.py`, split out of `SKILL.md`
to keep its body navigable. `SKILL.md` covers the boundary, when to run, the
command list, and the two core flows (ordinary sync, and re-extract after an
extractor change). Reach for a recipe below only when its situation applies.

## Contents
- A JavaScript page needs the browser ladder
- Look for a better Wayback capture
- The container is the sandbox for unsafe collection
- The publisher's furniture is trimmed off
- Translation is a STAGE OF THE PIPELINE, not an afterthought
- What `verify` refuses to publish
- A PDF nobody can read becomes page images
- A talk's transcript needs yt-dlp, in a container
- GitHub pages are read through the API, not the page
- Importing documents obtained by hand

## A JavaScript page needs the browser ladder

`refs.py check-browser` renders the rows a plain GET cannot read and stores the
DOM, which acquisition then treats like any other fetched bytes.

Its scope is the health status **plus any row whose acquisition reported that
the bytes it had did not hold the document** - below the content floor, under
the loss guard, or a body that turned out to be a consent gate. Reading only
`needs-browser` missed nine such pages, every one of them readable by a browser.

```text
python tools/references/refs.py check-browser --only <substring> --force
python tools/references/refs.py acquire --force --only <substring>
```

Three rungs, and the escalation is the point: headless, then a visible window
(some walls fingerprint headless and refuse it), then a long re-read budget. **A
rendered wall is not a rendered page** - a Cloudflare "403 Forbidden" and an
anti-scraper challenge were both recorded as "confirmed alive" and only failed
three steps later - so a refusal on one rung escalates to the next, and a refusal
on all three is reported as unconfirmed.

What the browser cannot fix, measured on this corpus: **a proof-of-work wall**
(Anubis) and **a site whose certificate has expired**. Both are reported with
the exact reason rather than worked around, and no accept-all certificate
callback is installed to make the number go down.

## Look for a better Wayback capture

Not every capture of a URL is the same page. A citation pinned to whatever
capture was found first can be pinned to a bad one: the nullcon slides were
pinned to a 9,046-byte capture of the site's own "404" page while a 2020 capture
of the same URL is the 380,504-byte PDF, and an aliyun article was pinned to a
5,775-byte JavaScript shell while a 2023 capture extracts to 35,144 characters.

```text
python tools/references/refs.py wayback --only <substring>   # --force
python tools/references/refs.py acquire --force --only <substring>
```

Two mechanics matter. The CDX index is asked what else exists and the **largest**
successful capture is tried, and the replay used is `/web/<timestamp>id_/`, which
returns the ORIGINAL bytes rather than the archive's rendering - the only form in
which a captured PDF is still a PDF.

**One capture is not an answer, so try older dates.** The reading list can cite a
replay URL whose capture is a bot wall rather than the page: `xz.aliyun.com/t/3019`
was cited as its 2024 replay, a slider CAPTCHA extracting to 99 characters, while
the 2019 and 2022 captures carry the article. So the candidates are WALKED
(`--tries`, default 5) and each fetched capture is checked for wall wording before
it is accepted. Ties break oldest-first: a site gets its content before it gets
its anti-scraper. The archive fixes this on its own side and **never edits the
reading list** - that belongs to `ysonet-curate-research-links`.

**A rate-limited lookup is not an empty index.** The CDX helper used to swallow
every failure into an empty list, so a 429 printed "no better capture exists" - a
statement about the source - and the reference read as dead. It now raises, and
the command reports `ASK FAILED` separately from `none`. The run that found this
said "none" on the first attempt and found a capture 2.2x larger on the retry.

**The index length is not comparable to our own byte count**: CDX reports the
compressed record size, so a capture listed at 19,564 can be 140,067 bytes when
fetched. Candidate lengths are only compared with each other, and whether the
result is better is settled by fetching it and comparing like with like.

A capture also SUPERSEDES a stored browser DOM, because sometimes the wall is
what the browser captured.

## The container is the sandbox for unsafe collection

One image, `refslib/toolbox.py`, for every job the archive will not do
in-process. Everything in it is either third-party code that would otherwise run
on this machine, or a fetch that relaxes something the in-process client must
never relax.

| Route | Tool | For |
|---|---|---|
| `captions` | yt-dlp | a talk's transcript |
| `fetch_insecure` | curl `--insecure` | a source whose certificate has expired |
| `pdf_page_images` | pdftoppm | a PDF whose text layer is unreadable |

The container gets one throwaway directory and the network. It does not get the
repository, the content store, the environment, any capability, a writable root
filesystem, or a root user, and it is bounded on memory and process count. The
base image is pinned by digest; `curl` and `poppler-utils` come from that
release's package repository, which is a stated limit rather than an oversight.

```text
python tools/references/refs.py insecure  --only <substring>   # one reference at a time
python tools/references/refs.py pdf-pages --only <substring> [--into <dir>]
```

**Certificate verification is skipped only where it is asked for.** Maintainer
decision 2026-08-04, for collecting a public document. It lives in the container
so "our fetcher always verifies" stays true - the exception is a different
process behind a container boundary and cannot be reached by accident - and
`insecure` refuses to run as a sweep: name the one reference.

Recovering a document also RELEASES the identity minted from the broken capture.
A browser's TLS interstitial had produced the slug `chromewebdata-privacy-error`,
and its `final_url` was still attributing the recovered Chinese advisory to
"chromewebdata".

## The publisher's furniture is trimmed off

Container-level chrome removal catches a `<footer>` or a `class="newsletter"`.
It cannot catch furniture sitting in the article's own flow with no class worth
naming, and 111 archived files ended with some: a consultancy's "Ready to engage /
Get in touch / Copyright 2026", a vendor's "Learn how it works / See how you're
protected" panel, Medium's "Press enter or click to view image in full size",
"Back to all", "Author Posts".

`refslib/boilerplate.py` trims it during acquisition and RECORDS what it took.
Every pattern came from counting the trailing blocks of all 503 documents, and
so did the list of things that must survive: `## References` (20 files),
`## See also`, `## Conclusion`, `### Disclosure timeline`, `### Credit`.

Four safety rules, because deleting content is worse than keeping an advert:

- trimming works **inward from the edges** and stops at the first block that is
  not furniture, so an advert mid-article stays - that is the price of not
  guessing;
- a block holding a fenced code block is never furniture;
- a long block is never furniture, because calls to action are short;
- no trim may take a large share of the document.

One rule earned its narrowness the hard way: "a block that is only an image" was
deleting 2,115 characters of a conference deck, because **on a slide host every
slide is an image whose alt text IS the slide**. Only an image with an EMPTY alt
is decorative.

## Translation is a STAGE OF THE PIPELINE, not an afterthought

The archive is read in English, and a third of a technique is lost when the
write-up is in a language the reader cannot follow.

**Run it on every acquire, before you call the run finished.** This is the step
that gets forgotten, because nothing looks wrong without it: acquiring,
classifying and rendering a foreign-language write-up all succeed on their own
and produce a file with frontmatter, attribution and content. Only a reader who
cannot read the content ever finds out. So `verify` now warns for any document
that is not in English and has no translation, and a run is not done while that
warning stands.

```text
python tools/references/refs.py translate                # the backlog
python tools/references/refs.py translate --prepare      # mask and split ALL of it
#   ... translate each chunk-NN.txt, save it beside as chunk-NN.en.txt ...
python tools/references/refs.py translate --apply        # store them all
python tools/references/refs.py acquire --force          # re-render
```

Every step is a batch step, and `--only <substring>` narrows any of them to one
document. **One refusal never stops the others**: a batch where one translator
dropped a placeholder stores the rest and names the one to redo, rather than
leaving the whole backlog unapplied.

**Only the foreign segments are handed over.** A document is rarely uniformly one
language: a Chinese write-up quotes English error messages, an English one
carries a stray Chinese paragraph, and most of a repository README is already
English around the part that is not. `--prepare` measures each segment and hands
over only what needs work; `--apply` rebuilds from the full segment map, so a
segment that was already English comes back verbatim and a translator that drops
one cannot delete a paragraph from the archive.

**A segment is judged on PRESENCE, a document on share.** A document is what most
of it is, but a segment is a unit of work: any foreign text in it is text
somebody has to translate. Judging segments by share left the Chinese cells
inside a large mostly-English table untranslated, and the Chinese titles in a
list of otherwise English links, because each block averaged out as English.

Presence only counts the writing systems that mean somebody wrote in another
language - CJK, Hangul, Cyrillic, Hebrew, Arabic, Devanagari, Thai. **Greek is
deliberately not one of them**, because here it is mathematics: asking merely
"is this outside the Latin script" queued three documents on the strength of a
sigma in a set-membership formula, a stray hieroglyph, and a PDF whose text layer
had decoded to mojibake. A damaged text layer is a job for `malformed`, not for a
translator.

**The title and publisher are translated too; the author never is.** A title is
the first thing a researcher reads and the thing they scan a folder for, so a
file headed with a Chinese title (for example a "advanced .NET code audit -
deserialization" write-up) tells an English reader nothing about whether it is
worth opening. Both are prepared as extra segments, masked into the SAME
placeholder numbering as the body (two independent sets collide, and restoring
one then corrupts the other), and stored as `title_english` / `publisher_english`
BESIDE the originals rather than over them.

An author is an identifier, not content. "Ivan1ee dotNet security matrix" is a
credit that matches nothing searchable, so `METADATA_FIELDS` deliberately
excludes authors.

The rendered file then reads in English and still cites exactly: the `#` heading
uses the English title, while the frontmatter `title`, the attribution line and
the OKF `sources` block keep the source's own spelling, with the English one
listed under it.

**A declared `en` is not evidence.** The language comes from the page's `lang`
attribute, and a blogging platform sets that once for the whole site: Medium
serves every post as `lang="en"`, so a Vietnamese write-up on it declared English
and sat in the archive untranslated. The declaration is believed in ONE direction
only - a page that says it is German is German - and a claim of English has to
survive the measurement.

**A document is called foreign only on positive evidence of another language**: a
non-Latin script, or that language's own stop words. "Few English function words"
looks like the general test that needs no word list per language, and it is
wrong - slides, code listings and reference pages are fragments rather than
sentences, so a conference deck scored 0.012 and a Microsoft design document
0.052, the same range as a Vietnamese write-up. It flagged four plainly English
documents. That signal is used only to confirm a SHORT segment IS English, never
to conclude a document is not.

The stop-word list is calibrated against the whole archive, and any word that
collides with the subject matter is dropped: `com` is Portuguese and fired 226
times across 22 English documents, because this field is full of COM. With those
out, genuinely foreign documents score 0.026 and up and English ones at most
0.0065.

**A translator must never touch the payload.** These documents are made of type
names, CVE identifiers, base64 blobs, XML and shell commands, and every one of
them is the research: a fully-qualified .NET type name translated into another
language is not a smaller mistake than a mistranslated sentence, it is a corrupted
gadget. So `--prepare` masks every non-prose construct as `{{PH_n}}` first -
fenced blocks, inline code, link TARGETS, URLs, dotted identifiers, CVE ids,
hashes - and `--apply` restores them byte-identically. **A placeholder that does
not come back is a refusal**, not a warning; `--force` exists and should almost
never be used.

**Only code is masked.** Everything a human wrote to be READ is prose even when
it sits inside punctuation: a link's TEXT, an image's alt text and a table's
CELLS are sentences somebody wrote. Masking those constructs whole left 2,064
Chinese characters untranslated inside documents that reported themselves fully
translated, so `[text](url)` keeps its text and hands over only the target.

Two traps live in the code patterns themselves, and both cost prose:

- **`\w` is Unicode-aware in Python.** A rule meant to match an ASCII code token
  will eat the sentence after it - a bare `\bMS[-\d\w]{4,}\b` swallowed a whole
  Chinese clause. Spell out `[A-Za-z0-9_]` wherever "code token" is meant.
- **Hyphens belong inside an identifier pattern**, or `CVE-2021-42321` masks as
  `{{PH_1}}-42321` and half an identifier goes to a translator.

A placeholder can also be NESTED inside another, because masking runs
longest-construct first. The inner token then appears nowhere in the prose and
returns only when its parent does, so the "did every placeholder come back"
check asks only about the ones that stand alone. Without that it reported nine
intact documents as corrupted.

**Code stays code; a COMMENT inside it is prose.** Masking a fenced block whole
protects the payload and also hides the author's explanation of it, which left a
Japanese code comment sitting in an English rendering. So the block stays masked
and its comments come out as their own segments, going back into the same block
afterwards. The code itself is never shown to a translator and never changes.

`reference-translator` is the agent for the middle step and holds an empty tool
set, because the text comes from the open web and may be written to steer
whatever reads it. It cannot act, so it cannot be made to act. For a backlog too
large for one reader, ordinary file-writing agents may translate chunk files
directly instead, under the same rules - the masking is what protects the
payload, and `--apply` still refuses a lost placeholder.

**The original is never overwritten.** The rendered file carries the translation
first and the original underneath, because a machine translation of a security
write-up is evidence ABOUT the original rather than a replacement for it, and a
reader has to be able to check it.

**Run every command with `YSONET_REFS_STORE` set.** Without it the tool falls
back to the workspace cache, which holds only part of the archive, and every
count comes out quietly wrong: the translation backlog read as 11 documents when
it was 36. `translate` now reports how many documents the store could not supply
rather than skipping them in silence.

## What `verify` refuses to publish

Beyond attribution and local paths, the gate now reads each published file for
malformation. Three rules, each of which caught a real file:

- **mostly replacement characters** (fail) - a gzip body the client never
  unwrapped, decoded as if it were text: 2,977 of 6,230 characters.
- **unescaped HTML entities** (warn) - `&lt;`/`&gt;` written verbatim, so a
  reader sees the markup instead of the code being quoted.
- **an unclosed code fence** (warn) - everything after it renders as code.

They are deliberately narrow. A looser sweep produced 138 "ends mid-sentence"
findings that were all page footers, and called an inline `code` span an
unbalanced fence. A rule that cries wolf gets switched off.

## A PDF nobody can read becomes page images

The last resort, and deliberately only half a route. `pdf-pages` renders each
page to a PNG in one folder; a reader - human or model - then writes what the
pages say and `import` files it against the citation.

Deciding what a page SAYS is not a converter's job. The converter that guessed
produced text with 32% of its words containing no vowel, and that is worse than
nothing because it reads as though somebody checked it. **Write only what is on
the page.**

## A talk's transcript needs yt-dlp, in a container

YouTube refuses timed text by every route this tool owns: a plain fetch gets 404
or a zero-byte body, the same fetch made BY the page with its session and origin
gets a zero-byte body, and the page's own "Show transcript" spins forever. The
caption URL needs a token the real player generates. `yt-dlp` asks a player
client that still answers.

```text
python tools/references/refs.py transcripts          # --only <substring>, --force
python tools/references/refs.py acquire --force --kind video
```

**It runs in a container, and that is not optional.** This is the only
third-party code the archive executes: a large, fast-moving project whose job is
parsing hostile input. The container gets one throwaway output directory and the
network. It does not get the repository, the content store, the environment, any
capability, a writable root filesystem, or a root user, and it is bounded on
memory and process count. The base image is pinned by digest and yt-dlp by
version, so a rebuild cannot quietly become something else. Nothing it downloads
is executed: the output is JSON this tool parses.

`--skip-download` is what keeps the media file off the machine. Only the caption
track is fetched.

No Docker means a clear SKIP with a reason, never a failure: each talk keeps its
metadata and records the gap, exactly as before. Expect to bump the pinned
yt-dlp version when YouTube breaks it - that is a deliberate, visible edit.

The transcript is stored, so re-rendering a talk afterwards is offline.

## GitHub pages are read through the API, not the page

A GitHub security advisory, source file or issue is a JavaScript shell: a plain
fetch of one was reaching the extractor as 139 to 264 characters and failing the
content floor, which is correct behaviour on a document that is genuinely not in
that HTML. `refslib/github.py` asks the public API instead, and covers three
shapes:

| URL | What is preserved |
|---|---|
| `/{owner}/{repo}/security/advisories/GHSA-...` and `/advisories/GHSA-...` | summary, full description, severity, CVE, affected packages, references |
| `/{owner}/{repo}/blob/{ref}/{path}` | the file itself from `raw.githubusercontent.com`, fenced, with the cited `#L123` noted |
| `/{owner}/{repo}/issues|pull/{n}` | the body and up to 20 comments |

Three things about it are deliberate:

- **No credentials, ever.** No token is read from the environment and none is
  sent. An archive run must behave the same for every contributor, and a tool
  that quietly used one person's token would produce results nobody else can
  reproduce. The cost is the unauthenticated limit of 60 requests an hour, which
  a corpus with a couple of dozen of these never reaches.
- **A refusal is reported as a refusal.** A rate limit or a missing record says
  so; it is never turned into "this page has no content", because the difference
  decides whether a human retries or goes looking for another source.
- **An API answer is COMPLETE.** The route returns the whole record or refuses,
  so a short answer is a short record and not a stub, and it does not belong on
  the needs-work list. The same is true of a repository clone.

A GitHub discussion is the one shape not covered: it is served only by the
GraphQL API, which needs a token.

## Importing documents obtained by hand

Some sources no automated route can reach: an image-only PDF, a page behind a
wall, a talk with no caption track. `needs-work.md` is the list of those. Convert
them however works, drop the results in one directory, and:

```text
python tools/references/refs.py import <directory>
python tools/references/refs.py index --prune-files
```

The directory's path is never written into tracked output. What the import does
and what it refuses to do:

- **Several files for one document are JOINED.** Converters truncate and mangle,
  so two or three attempts at one source are normal. The plainest-named file is
  the base and anything another attempt found that the base lacks is appended
  under a labelled heading. Nothing is silently dropped.
- **Files that are not the same document are split apart**, even when they share
  a name, and the split-off one is matched on its own first page instead. A blog
  post and the whitepaper it describes arrived under one name.
- **A file whose name matches nothing is REPORTED, never guessed at.** Rename it
  after the reference's URL or title and run again - or state the URL outright
  (below), which is the only route when the reference has no usable title.
- **`<file>.url` states which reference a file IS, and outranks every heuristic.**
  Write one line, the URL, in a text file beside the document. Filename evidence
  cannot always work: a KTH thesis saved as `thesis-Mikhail-2024.pdf` had a
  reference whose recorded title was `Making sure you're not a bot!`, because the
  portal answered the probe with a bot check - there is no word in common to
  score, and no tuning would ever have matched them.
- **PDFs are imported directly**, through the same converter the fetch path uses.
  A paper behind a portal is the commonest thing to obtain by hand, and for a
  long time only HTML and text were read here, so a saved PDF was silently
  ignored.
- **`NO PAGE`** means only a `Thing_files/` resource folder was copied. The
  article lives in `Thing.html` next to it, so copy that too.
- **An import is sticky.** A later `acquire` leaves it alone, because re-running
  acquisition can only replace it with the failure that made the import
  necessary. `--replace-imports` is the deliberate escape hatch. It also means a
  correction that only the fetch path applies never reaches an imported entry, so
  anything the maintainer states has to be honoured on BOTH paths.
- **A title read off a wall is not a title**, and it becomes the heading, the
  frontmatter and the file name. Add `"title"` to that URL's entry in
  `decisions` (`overrides.json`) to state the real one; the pinned slug is
  released so the file is renamed after the document, and the old file becomes an
  orphan for `acquire --prune-files`.
- **`--redo`** reopens what a previous import filed, which is what an improved
  match needs. It then reports any reference a file MOVED AWAY from as
  `REASSIGNED`: that citation is holding a document that is not it, so
  re-acquire it or let it return to `needs-work.md`.
