# Agentic Workflows Setup Guide

## Prerequisites

Several agentic workflows in this repository require **GitHub Discussions** to be enabled. These workflows use discussions to coordinate work, share research, and track progress.

### Workflows that require Discussions:

- **Daily Perf Improver** - Creates discussions to share performance research and improvement plans
- **Daily QA** - Creates discussions for quality assurance coordination
- **Daily Backlog Burner** - Creates discussions to track backlog item progress

### Workflows that benefit from Discussions (but don't create them):

- **Discussion Task Miner** - Reads discussions to mine tasks and creates issues (requires discussions to be enabled for reading, but does not create discussions)

## Enabling GitHub Discussions

If you see errors like:
```
Failed to create discussion in 'owner/repo': Resource not accessible by integration
```

This means GitHub Discussions are not enabled for your repository.

### Steps to Enable Discussions:

1. Go to your repository on GitHub: `https://github.com/your-username/your-repository`

2. Click on **Settings** tab

3. Scroll down to the **Features** section

4. Check the box next to **Discussions**

5. Click **Set up discussions** if prompted

6. Choose discussion categories (recommended categories):
   - **Announcements** - For workflow announcements and updates
   - **Ideas** - For workflow research and proposals (used by Daily Perf Improver and Daily Backlog Burner)
   - **General** - For general discussions (used by Daily QA)
   - **Q&A** - For questions and troubleshooting

### Verifying Discussions are Enabled:

After enabling discussions, you should see a new **Discussions** tab in your repository navigation.

You can verify discussions are working by:
- Visiting: `https://github.com/your-username/your-repository/discussions`
- You should see the discussions interface, not a 404 error

## Re-running Failed Workflows

Once discussions are enabled, you can re-run any failed workflows:

```bash
# Re-run a specific workflow manually
gh workflow run daily-perf-improver.lock.yml

# Or view and re-run from the GitHub Actions UI
# Go to: Actions tab → Select the failed workflow → Click "Re-run jobs"
```

## Troubleshooting

### Issue: "Invalid category ID" error

If discussions are enabled but you still see errors about invalid categories:

1. Check that the required categories exist in your discussions:
   - **Ideas** - Used by Daily Perf Improver and Daily Backlog Burner (slug: `ideas`)
   - **General** - Used by Daily QA
2. You can add or verify categories in: Settings → Discussions → Categories
3. GitHub accepts both category names (e.g., "Ideas") and slugs (e.g., "ideas")

### Issue: "Insufficient permissions" error

The agentic workflows in this repository request **read-only** permissions (for example, `permissions: all: read` or `permissions: read-all`) so they can read repository state and existing discussions.

**Discussion creation and updates are handled by the agentic workflow system's safe-outputs framework**, which uses its own GitHub App permissions. The workflows themselves do **not** require `discussions: write` on the `GITHUB_TOKEN`.

If you still see permission-related errors around discussions:

1. First verify that GitHub Discussions are enabled for the repository (see the steps above).
2. Check the workflow run logs (especially the "conclusion" or summary step) for the exact permission error message.
3. Review your agentic workflow / safe-outputs configuration or documentation to confirm that the GitHub App used for safe-outputs has `discussions: write` where required.
## Alternative: Using Issues Instead (Not Recommended)

If you cannot enable discussions for some reason, you could modify the workflows to use issues instead. However, this is **not recommended** because:

- Discussions are designed for coordination and research (the primary use case)
- Issues are better suited for tracking bugs and specific tasks
- The workflows are designed around the discussion model

If you must use issues, you would need to:
1. Modify each workflow's `safe-outputs` section to use `create-issue` instead of `create-discussion`
2. Update the workflow logic to use issue queries instead of discussion queries
3. This is a significant change and may break workflow coordination features

## Support

For more information about GitHub Discussions:
- [GitHub Discussions Documentation](https://docs.github.com/en/discussions)
- [Enabling Discussions](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/enabling-or-disabling-github-discussions-for-a-repository)

For agentic workflow issues:
- Check the workflow run logs in the Actions tab
- Look for error messages in the "conclusion" job
- Review the workflow documentation in `.github/workflows/*.md` files
