# Repository rules for AI coding assistants

These rules apply to every Claude Code session, Codex session or other AI
assistant working in this repository, local or cloud, and they override any
default attribution behaviour of the tool.

## No AI attribution in git history

- Never add `Co-Authored-By`, `Co-authored-by`, `Claude-Session`,
  `Generated with Claude Code` or any other AI attribution line to a commit
  message, pull request title or body, or review comment.
- The author and committer of every commit are the human operating the tool.
  Never set `user.name` or `user.email` to an AI identity such as
  `Claude <noreply@anthropic.com>`, and never run `--reset-author` to one.
- Do not create branches named `claude/...`, `codex/...` or similar; use the
  repository's `feat/`, `fix/`, `docs/`, `packaging/` and `release/` prefixes
  with a date suffix, for example `feat/pool-pruning-20261007`.

GitHub turns any `Co-Authored-By: ... <noreply@anthropic.com>` trailer into a
"claude" entry in the Contributors list, and that cannot be removed without
rewriting main. The `commit-attribution` CI job fails a push or pull request
that carries such a trailer, and `scripts/git-hooks/commit-msg` rejects it
locally once installed with:

```
git config core.hooksPath scripts/git-hooks
```

## Other conventions

- Do not bump the version or edit release inventories, manifests or HiveOS
  files; the maintainer makes release commits.
- Run `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`
  and the affected crate's tests before pushing.
