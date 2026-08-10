# Link ledger

`link-ledger.json` is the memory of this skill. It is tracked in git on purpose, so a
sweep run on one machine tells the next session what was already done.

One record per link:

| field | meaning |
| --- | --- |
| `first_seen` / `last_checked` | when the link entered the list, when it was last fetched |
| `class`, `note`, `http_status`, `title` | what the HTTP check found |
| `redirects_to` | where it lands, when that differs from the URL |
| `files` | which page lists it, repo-relative |
| `decision`, `decision_reason`, `decision_date` | how a redirect was judged |
| `replaced_on`, `replaced_by` | when the URL in the doc was rewritten, and to what |
| `unchecked` | nothing has confirmed this link, and why |
| `http_unreadable` | a bot wall blocks the HTTP check, but a browser confirmed the page |
| `browser`, `browser_verified_on` | the browser check: latest attempt, and last confirmed sighting |

Plus `last_sweep` (date, files, counts) and `last_rehydrate` (date, scope, added,
rejected) so a session can tell whether the list was topped up recently.

Read it before starting either job:

```
python .claude/skills/ysonet-curate-research-links/scripts/check_links.py --ledger-status
```

It is public, so nothing machine-specific goes in it: repo-relative paths only, no
local path, no user name, plain ASCII.
