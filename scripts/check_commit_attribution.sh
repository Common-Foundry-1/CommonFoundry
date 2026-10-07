#!/bin/sh
# CI guard: fail when any commit in the given range carries an AI attribution
# trailer. Usage: scripts/check_commit_attribution.sh <rev-range-or-rev>
set -eu
range="${1:-HEAD}"
pattern='noreply@anthropic\.com|[Cc]o-[Aa]uthored-[Bb]y:.*(Claude|Codex|Copilot|ChatGPT|Gemini)|^Claude-Session:|Generated with \[?Claude Code'
status=0
for commit in $(git rev-list --no-merges "$range"); do
    if git log -1 --format=%B "$commit" | grep -Eq "$pattern"; then
        echo "::error::commit $commit carries an AI attribution line:" >&2
        git log -1 --format=%B "$commit" | grep -En "$pattern" >&2
        status=1
    fi
    for identity in "$(git log -1 --format='%an <%ae>' "$commit")" "$(git log -1 --format='%cn <%ce>' "$commit")"; do
        if printf '%s' "$identity" | grep -Eq 'noreply@anthropic\.com|^Claude <'; then
            echo "::error::commit $commit is authored or committed as $identity" >&2
            status=1
        fi
    done
done
if [ "$status" -ne 0 ]; then
    echo "AI attribution is not allowed in this repository; see CLAUDE.md." >&2
fi
exit "$status"
