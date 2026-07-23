# Workflow

Git and multi-agent working conventions. Entry format: `date - what - why`.

- 2026-07-22 - When starting new or parallel work that will live on its own branch, give the agent an isolated checkout with a git worktree (`git worktree add ../ysonet-<topic> master`, then work on a branch inside it) instead of sharing the one repo checkout. At minimum, use a dedicated branch. - Two agents sharing a single working tree block each other: you cannot switch off or delete the branch that is checked out, and switching branches reverts and clobbers the other agent's uncommitted work-in-progress. A separate worktree gives each agent its own working directory, so branches can be created, switched, and deleted freely without ever touching the other agent's files. This came up when a branch could not be deleted because a second agent was mid-edit in the same checkout.
