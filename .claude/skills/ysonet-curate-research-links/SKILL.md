---
name: ysonet-curate-research-links
description: Rehydrates docs/dotnet-deserialization-research.md with new .NET deserialization articles, tools, talks, CVE write-ups and advisories, and repairs its links by adjudicating every redirect against the destination page, adopting the new URL when it holds the same material and falling back to a Wayback Machine snapshot when it does not. Use when the user asks to refresh, expand, top up or update the research reading list, add a paper, blog post, tool or CVE to the docs, check the links on a reference page, or fix 404s, moved pages and dead links in the documentation.
---

# Curate the .NET deserialization research list

Two jobs. Run either on its own.

- **A. Rehydrate**: find material the list is missing and add it.
- **B. Link sweep**: open every link, repair the dead ones from the Wayback Machine.

Both write to `docs/dotnet-deserialization-research.md`. Reports and caches go to
`dev-kitchen/link-checks/`, which is git-ignored.

## The ledger: read it before you do anything

`log/link-ledger.json`, inside this skill and tracked in git, is the memory of every
run: one record per link with when it was last checked, what came back, the decision
taken and why, when it was replaced, and the reason when it could NOT be checked. It
also holds `last_sweep` and `last_rehydrate`.

Start both jobs by asking it what is already known:

```
python .claude/skills/ysonet-curate-research-links/scripts/check_links.py docs/dotnet-deserialization-research.md docs/references.md --ledger-status
```

It prints the last sweep and last rehydration dates, and splits the links into
checked within 30 days (`--fresh-days`), checked longer ago, and never checked.

**Then tell the user what it says and ask before repeating recent work.** If the last
rehydration was under a month ago, say so and ask whether to top up again or just
sweep. If most links were checked days ago, offer to limit the run (`--only`, or the
never-checked list) instead of re-fetching everything. Do not silently redo a pass
somebody ran last week.

Every sweep updates the ledger. Record a rehydration pass explicitly, so the next
session knows when new material was last hunted for:

```
--record-rehydrate "anything published since the newest entry" --rehydrate-added 4 --rehydrate-rejected 5
```

`browser_fetch.py` writes its verdicts into the same file, so a link the HTTP checker
could not read carries the browser's answer beside it. `--no-ledger` turns all of
this off.

The ledger is tracked and public, so rule 0 of the seam applies: repo-relative paths
only, no local path, no user name, plain ASCII.

## The two pages

`docs/references.md` is the short list: how a gadget or plugin was made, plus the
sources a gadget file points at from its own source. `docs/dotnet-deserialization-research.md`
is the wide superset: everything else, and everything on the short list too.

Placement test, section taxonomy, and the annotation format are in
`references/page-rules.md`. Read it before adding an entry.

## A. Rehydrate

Goal: an entry an operator or researcher can act on later. Volume is not the goal;
a link nobody can learn from is noise.

1. **Inventory what is already there.** Never search before this: half of the
   plausible finds are already listed under a different URL.

   ```
   python .claude/skills/ysonet-curate-research-links/scripts/check_links.py --list > dev-kitchen/link-checks/urls.txt
   python .claude/skills/ysonet-curate-research-links/scripts/check_links.py --ledger-status
   ```

   The second command gives the date of the last rehydration. If it was under a
   month ago, tell the user and ask whether to run one at all: searching the same
   window twice mostly re-finds what was already rejected.

2. **Pick the scope** and say it in your first message. Default scope is "anything
   published since the newest thing already listed". A named scope (one product,
   one formatter, one CVE, one researcher) is also fine.

3. **Search.** Query families and the source list are in
   `references/discovery-sources.md`. Batch the searches; a normal sweep is 10 to 20
   of them. Follow each promising hit with a fetch, because a search snippet is not
   evidence the page says what the title claims.

4. **Vet every candidate** against all five:
   - It teaches something about .NET serialization or deserialization: a technique,
     a gadget, a sink, a formatter behaviour, a defence, a real exploitation account,
     or a tool that does the work.
   - You opened it. Never add a URL from memory or from a search snippet.
   - It is not already on the page under another URL, a different host, or a snapshot.
   - Prefer the primary source. Link the researcher's write-up, not the news article
     about it. Add the news article only when it carries detail the primary does not.
   - It is reachable without a login or a paywall, or a snapshot of it is.

5. **Place it** per `references/page-rules.md`: right section, one line, ASCII, and a
   short "what it teaches" note after ` - ` when the title alone does not say.

6. **Verify only what you added**, so a sweep does not re-fetch 480 healthy links:

   ```
   python .claude/skills/ysonet-curate-research-links/scripts/check_links.py --only "part-of-the-new-url" --no-cache
   ```

7. **Run the page audit** and fix what it reports as a rule break:

   ```
   python .claude/skills/ysonet-curate-research-links/scripts/audit_links.py
   ```

8. **Stamp the pass in the ledger**, so the next session knows when new material
   was last hunted for:

   ```
   python .claude/skills/ysonet-curate-research-links/scripts/check_links.py docs/dotnet-deserialization-research.md docs/references.md --record-rehydrate "<the scope you used>" --rehydrate-added N --rehydrate-rejected N
   ```

9. **Report**: how many entries added, per section, and anything you rejected and
   why. Do not commit; the maintainer decides that.

## B. Link sweep

Three steps: sweep, adjudicate the redirects, apply. Never skip step 2 when the
sweep queued anything: a redirect is a claim that the material moved, and only
reading the destination shows whether it did.

Pass BOTH pages every time. A URL on the short list is on the wide one too, and
`--apply` only edits the files it was given, so repairing one page alone leaves the
other pointing at a dead URL and breaks the audit.

### Step 1: sweep (writes nothing to the docs)

```
python .claude/skills/ysonet-curate-research-links/scripts/check_links.py docs/dotnet-deserialization-research.md docs/references.md --report dev-kitchen/link-checks/report.md
```

A full sweep of about 500 links takes roughly 10 to 20 minutes, most of it waiting
on the Wayback Machine rate limit. Run it in the background and read the report.

It writes three files under `dev-kitchen/link-checks/`: `report.md`,
`adjudicate.json` (the redirects to judge) and `lost-links.md`.

### Step 2: adjudicate every queued redirect

Read `dev-kitchen/link-checks/adjudicate.json`. Each item carries the original URL,
where it landed, the destination title, a page excerpt, how much of the original
slug survived, and a snapshot candidate. Decide per item whether the destination is
the SAME material the entry pointed at:

| decision | when | result |
| --- | --- | --- |
| `adopt` | the destination is the same article at its new address | the doc gets the new URL |
| `snapshot` | the destination is a home page, an index, a stub, or something else | the doc gets the archived copy |
| `keep` | the original still works for a reader (a bot wall blocked the checker, or the redirect is cosmetic) | nothing changes |
| `lost` | the material is gone and the archive has nothing usable | listed under Lost links, entry untouched |

Rules for this step:

- Judge the CONTENT, not the URL. A matching slug is a hint, not proof; a 0.00 slug
  match can still be the same article on a renumbered CMS.
- Fetch the destination yourself whenever the excerpt is empty, is an anti-bot
  challenge, or does not settle it. The excerpt exists to save a fetch, not to
  replace one.
- Prefer a durable address. If the destination is the right article but the URL
  carries a session or tracking parameter, or a random path segment, find the clean
  URL and put it in `replacement`. The tool refuses a bare `adopt` onto such a URL
  and falls back to the snapshot.
- When the author republished the work on their own site, adopt that copy over a
  corporate URL that keeps moving, and use the PDF when the post hosts one.
- Never guess. If you cannot tell, use `snapshot`; it is always safe.

Fill in `decision` and a one-line `reason` for every queued item, then save the file
(same shape, or a plain list of `{url, decision, reason, replacement}` objects).

Delegate this to a subagent when the queue is long: give it the queue file, the
table above, and have it return the finished decisions file.

### Step 3: apply

```
python .claude/skills/ysonet-curate-research-links/scripts/check_links.py docs/dotnet-deserialization-research.md docs/references.md --decisions dev-kitchen/link-checks/adjudicate.json --apply --report dev-kitchen/link-checks/report.md
```

Without `--decisions`, `--apply` still repairs dead, soft-404 and redirect-to-root
URLs from the archive and leaves every other redirect alone.

`--apply` also drops duplicate entries (see below), because adopting a moved URL
often lands on one the page already lists.

### Duplicate entries

Every run reports URLs listed more than once, and `--apply` removes the redundant
line. The rule is deliberately narrow:

- The FIRST appearance is the entry. Every later one is a repeat, in the same
  section or another, and is dropped.
- Only a line carrying no text of its own is dropped: a bare URL, or a Markdown
  link with no note.
- A later line that carries a note of its own is reported and NEVER removed,
  because that would delete writing. Fold it into the first entry yourself, or
  keep both on purpose (one entry per artifact: slides and video).
- This applies to the research page. `docs/references.md` is a short curated
  list with no duplicates, and `audit_links.py` rule 2 already guards it.

Check the "Duplicate entries" section of the report after every apply, and fold
anything it hands you into one entry yourself.

### Blocked links: check them in a real browser

`blocked` means a bot wall answered, not that the page is dead, so the checker never
touches those entries. Open them in an installed Chrome or Edge instead:

```
python .claude/skills/ysonet-curate-research-links/scripts/browser_fetch.py --list dev-kitchen/link-checks/blocked.txt
python .claude/skills/ysonet-curate-research-links/scripts/browser_fetch.py --list dev-kitchen/link-checks/blocked.txt --visible --fresh-per-url --wall-retries 10 --wall-wait 8
```

Escalate headless, then `--visible`, then `--visible --fresh-per-url` with a long
budget, stopping when a URL comes back `alive`. All 19 blocked URLs on this list
were alive; none had rotted. The full method, what was measured, and the rule
against automating a human-verification click are in
`references/blocked-links-and-ui-inspection.md`. Read it before treating a blocked
entry as a problem with the entry.

Getting the URL list: every run writes the blocked entries into the `## blocked`
section of the report.

### Lost links

Anything with no live page and no snapshot lands in `## Lost links` at the bottom of
the report and in `dev-kitchen/link-checks/lost-links.md`. Never delete such an entry
on your own. Report the list, and offer the maintainer the options: the same work
republished elsewhere, the author's own copy, or dropping the entry.

### What the checker does

Opens every URL with a browser user agent, follows redirects, and classifies it.
URLs that are already a snapshot (`web.archive.org`, `archive.today`) are skipped
without a request. For anything broken or redirected it asks the Wayback CDX API for
the newest good snapshot. The link text is never touched, only the URL.

### The classes

| class | meaning | what happens |
| --- | --- | --- |
| `ok` | alive at the same URL | nothing |
| `ok-redirect` | redirected, destination still matches the slug | queued for adjudication |
| `redirect-root` | landed on a home page or bare section root | queued; `--apply` alone uses the snapshot |
| `redirect-lowmatch` | landed somewhere sharing little with the original slug | queued for adjudication |
| `dead` | 404, 410, DNS gone, refused | `--apply` replaces it with a snapshot |
| `soft-404` | 200, but the page title says the content is gone | `--apply` replaces it with a snapshot |
| `blocked` | 401/403/429/5xx or a bot wall | never touched; open it in a browser, usually alive |
| `error` | timeout or TLS failure | never touched; re-run alone with a longer `--timeout` |

Even `ok-redirect` is queued. A perfect slug match still gets a look, because a CMS
migration can serve a stub or a category page under the old slug. A redirect stays
queued on every run until it carries a decision; once judged, the decision is
cached with it and it stops coming back.

Never silently drop an entry because a link broke. Replace it, snapshot it, or put it
in Lost links and let the maintainer decide.

### Useful switches

- `--only REGEX` check a subset. Use it for new entries and for re-testing one host.
- `--limit N` smoke test.
- `--workers N` concurrent fetches, default 8. Page fetches only; archive lookups
  are always serialised.
- `--timeout S` default 25 seconds.
- `--no-cache` ignore the cache under `dev-kitchen/link-checks/`. Healthy results are
  cached for 30 days (`--cache-days`); failures are always re-checked.
- `--verbose` include healthy URLs in the report.
- `--relevance F` how much of the original URL slug a redirect target must still
  contain before it is classed `ok-redirect` rather than `redirect-lowmatch`. It only
  sorts the queue; it never decides anything on its own. Default 0.34.
- `--queue PATH` / `--lost PATH` move the queue and lost-links files.
- `--excerpt-chars N` page text carried per queued redirect, default 1200. Raise it
  when the excerpts are too thin to judge; every excerpt is plain ASCII.
- `--include-lowmatch` mechanical fallback that snapshots every `redirect-lowmatch`
  without adjudication. Only for a bulk sweep nobody will read.
- `--recheck-archived` also verify snapshot URLs. Slow, rarely needed.
- `--ledger-status` what the ledger already knows: last sweep, last rehydration, and
  how many links were checked recently, long ago, or never. Prints and exits.
- `--fresh-days N` how recent counts as recently checked (default 30).
- `--record-rehydrate "<scope>"` with `--rehydrate-added` / `--rehydrate-rejected`,
  stamps a rehydration pass in the ledger.
- `--ledger PATH` / `--no-ledger` move the ledger, or leave it untouched.

The checker also works on any other Markdown file:

```
python .claude/skills/ysonet-curate-research-links/scripts/check_links.py docs/references.md docs/credits.md
```

## Rules for both jobs

- Plain ASCII everywhere, no em-dash or curly quotes. Titles copied from a page
  often carry them; strip them.
- One link per line. Do not reflow or re-sort existing entries; an unrelated
  reordering hides the real change in the diff.
- A link added to `docs/references.md` must also go in the research page. The
  reverse is not true. `audit_links.py` enforces it.
- Never name private material. If a source only exists in the private area,
  it does not go on a tracked page at all.
- Never commit. Report what changed and let the maintainer commit.
