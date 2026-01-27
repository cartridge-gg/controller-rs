# Smart Git Commit

## Purpose
Create a clean, conventional commit by inspecting changes, staging safely, and ensuring formatting/lint checks pass.

## When to use
- You need to commit local changes and want a consistent, conventional message.
- You want to avoid accidental partial commits or unformatted code.

## Workflow
1) Check for changes and summarize them:

```bash
# Check if we have changes to commit
if ! git diff --cached --quiet || ! git diff --quiet; then
    echo "Changes detected:"
    git status --short
else
    echo "No changes to commit"
    exit 0
fi

# Show detailed changes
git diff --cached --stat
git diff --stat
```

2) If nothing is staged, stage only modified/deleted files (not untracked):

```bash
if git diff --cached --quiet; then
    echo "No files staged. Staging modified files..."
    git add -u
fi

# Show what will be committed
git diff --cached --name-status
```

3) Analyze scope/type and prepare a conventional commit message:
- Type: `feat|fix|docs|style|refactor|test|chore`
- Scope: optional component/area
- Subject: concise, present tense
- Body: include rationale when needed

4) Run formatting/lint checks before committing:

```bash
trunk check --ci --fix
```

- If this fails, stop and ask for manual fixes before committing.

5) Commit with the chosen message. Do not add yourself as co-author.

## Notes
- Prefer existing repo conventions if recent history shows a pattern.
- Avoid staging untracked files unless explicitly requested.
