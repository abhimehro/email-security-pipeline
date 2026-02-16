# Workflow Compilation Required

The `daily-backlog-burner.md` workflow has been updated to fix the discussion creation failure.

## Changes Made

- Changed `create-discussion` to `create-issue` in safe-outputs configuration
- Updated workflow instructions to use GitHub Issues instead of Discussions
- This fixes the error: "Resource not accessible by integration" which occurred because Discussions are not enabled in this repository

## Action Required

To complete the fix, the workflow must be recompiled to generate the updated `.lock.yml` file:

```bash
gh aw compile daily-backlog-burner
```

Or to compile all workflows:

```bash
gh aw compile
```

## Why This Fix Works

The workflow was attempting to create GitHub Discussions to track backlog management progress, but Discussions are not enabled in this repository. By switching to GitHub Issues (which are enabled), the workflow will be able to:

1. Create a tracking issue titled "Daily Backlog Burner - Research, Roadmap and Plan"
2. Use this issue to coordinate backlog management activities
3. Comment on the issue with progress updates

This maintains all the workflow functionality while using a feature that's available in the repository.
