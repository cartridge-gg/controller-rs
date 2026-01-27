# PR Workflow

## Purpose
Prepare and publish a pull request with a clear summary that matches the diff and any linked issues.

## When to use
- You need to open or update a PR for the current branch.
- You want a concise summary based on the actual diff vs `origin/main`.

## Workflow
1) Ensure you are not on `main`. If you are, create a dedicated branch.

2) If there are pending changes, use the `commit` skill to stage and commit.

3) Fetch and review the PR diff:

```bash
git fetch origin main
git diff origin/main...
```

4) Summarize the content and intent of the diff in a few sentences.

5) If `$ARGUMENTS` are provided:
- Add a line `Close $ARGUMENTS` to the PR summary.
- Use the Linear MCP to fetch the issue and verify the PR aligns with it.

6) Use `gh` to create or update the PR description and title.

7) After creating the PR, wait a few minutes for an automated Claude review.
- If the review recommends changes, apply the fixes and update the PR.

## Notes
- Prefer concise, accurate summaries over aspirational descriptions.
- If Linear MCP is unavailable, note the limitation and proceed with the best available context.
