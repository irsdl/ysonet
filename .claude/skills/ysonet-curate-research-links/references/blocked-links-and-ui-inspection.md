# Links a plain HTTP client cannot read

## Contents
- What `blocked` really means
- The workflow that works
- Why patience and a fresh session are the whole trick
- Looking at the screen when text is not enough
- Where the results go
- Rules

## What `blocked` really means

`check_links.py` fetches with a browser user agent and a cookie jar, and a bot wall
still answers it with 403 and a "Just a moment..." title. That is not evidence the
page is gone. It is evidence that a socket cannot settle the question.

Measured on this reading list: **19 URLs were `blocked`, and every single one turned
out to be alive.** Nothing had actually rotted. A sweep that stopped at `blocked`
would have left 19 entries permanently unverifiable.

## The workflow that works

`scripts/browser_fetch.py` drives an installed Chrome or Edge over the DevTools
protocol, so a real engine runs the JavaScript challenge. It is standard library
only: the DevTools connection is a hand written WebSocket client.

```
python .claude/skills/ysonet-curate-research-links/scripts/browser_fetch.py --list blocked.txt
python .claude/skills/ysonet-curate-research-links/scripts/browser_fetch.py --list blocked.txt --visible --fresh-per-url --wall-retries 10 --wall-wait 8
```

Escalate in this order, stopping as soon as a URL comes back `alive`:

1. **Headless.** Clears the simpler walls. Cleared 7 of 19 here.
2. **`--visible`.** Shows the window. Some walls fingerprint headless and refuse
   it. Cleared 6 more.
3. **`--visible --fresh-per-url` with a long budget.** Cleared the last 6.

Verdicts: `alive`, `still-walled`, `http-<code>`, `empty`, `error`. Exit code is 0
only when everything came back `alive`.

## Why patience and a fresh session are the whole trick

Two things were measured, and both are worth knowing before reaching for anything
more elaborate:

- **The challenge passes seconds before the article appears.** The DOM says
  "Verification successful. Waiting for medium.com to respond" and only then swaps
  in the page. Read once and a live page is reported as blocked. `--wall-retries`
  and `--wall-wait` re-read while a wall is on screen; a budget of about 80 seconds
  cleared pages that a 20 second budget did not.
- **The wall tracks the session, not the page.** One Medium article opened on its
  own cleared. The same article opened as the fifth tab of one browser session did
  not. `--fresh-per-url` restarts the browser with a clean profile per URL, which
  makes a batch behave like the single runs that worked. It is slower, so it is
  opt-in, and it is the thing to try before concluding a page is unreachable.

Notes for anyone extending this:

- `--dump-dom` is a dead end on Windows. A browser is a GUI subsystem program, so
  its stdout never reaches a pipe: the file comes back zero bytes with exit code 0,
  in old and new headless alike. Use the DevTools protocol.
- The launcher process exiting means nothing. Edge relaunches itself and the first
  process returns 0 while the browser runs on. Poll `DevToolsActivePort` inside the
  profile directory, never `proc.poll()`.
- Quitting needs `Browser.close` over CDP. Terminating the launcher leaves the real
  browser running, and a batch will strand dozens of windows on the maintainer's
  desktop.

## Looking at the screen when text is not enough

When the text of a page does not explain what is happening - a spinner, a cookie
banner, a consent dialog, a challenge that needs a person - look at it:

```
python .claude/skills/ysonet-curate-research-links/scripts/ui_control.py windows --match Edge
python .claude/skills/ysonet-curate-research-links/scripts/ui_control.py shot --match Edge --out shot.png --scale 2
```

`ui_control.py` is ctypes over Win32 with nothing installed: it lists visible top
level windows and writes a PNG (zlib only, no imaging library) that an agent can
read back. Run it against a window opened by `browser_fetch.py --visible` while the
fetch is still going.

It was built to diagnose the walls above, and in the end it was not needed for them:
patience and a fresh session were enough. Keep it for the case where a page's
behaviour genuinely has to be seen.

## Where the results go

Every verdict is written to the skill's ledger, `log/link-ledger.json`, beside the
HTTP result for the same URL:

- `browser` - the latest attempt: date, verdict, status, title.
- `browser_verified_on` - the date a browser last confirmed the page is really there.
- `unchecked` - only while nothing has confirmed it, with the reason.

A later attempt that hits a wall does NOT erase an earlier confirmed sighting. Walls
are served per session, so one failed attempt is not evidence the page went away.

## Rules

- **A wall is not a dead link.** Never rewrite, snapshot, or drop an entry because
  it came back `blocked`. Escalate, or record it as unverified and say so.
- **Do not automate a "verify you are human" checkbox.** Where a challenge needs a
  real click, the supported answer is a person: run `--visible` with a long budget,
  click it yourself, and let the tool read the page when it loads. On this list no
  such click was ever needed.
- **Never commit a screenshot, and read a window list before pasting it.** A capture
  shows whatever was on the maintainer's screen, and window titles carry the names
  of open files and folders - including private ones. Write captures to a scratch
  directory outside the repository.
