# Agentic Workflows Setup Guide

## Prerequisites

Several agentic workflows in this repository require **GitHub Discussions** to be enabled. These workflows use discussions to coordinate work, share research, and track progress.

### Workflows that require Discussions:

- **Daily Perf Improver** - Creates discussions to share performance research and improvement plans
- **Daily QA** - Creates discussions for quality assurance coordination
- **Daily Backlog Burner** - Creates discussions to track backlog item progress
- **Discussion Task Miner** - Monitors and mines tasks from discussions

## Enabling GitHub Discussions

If you see errors like:
```
Failed to create discussion in 'owner/repo': Resource not accessible by integration
```

This means GitHub Discussions are not enabled for your repository.

### Steps to Enable Discussions:

1. Go to your repository on GitHub: `https://github.com/abhimehro/email-security-pipeline`

2. Click on **Settings** tab

3. Scroll down to the **Features** section

4. Check the box next to **Discussions**

5. Click **Set up discussions** if prompted

6. Choose discussion categories (recommended categories):
   - **Announcements** - For workflow announcements and updates
   - **Ideas** - For workflow research and proposals (used by daily-perf-improver)
   - **Q&A** - For questions and troubleshooting
   - **General** - For other discussions

### Verifying Discussions are Enabled:

After enabling discussions, you should see a new **Discussions** tab in your repository navigation.

You can verify discussions are working by:
- Visiting: `https://github.com/abhimehro/email-security-pipeline/discussions`
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

1. Check that the "Ideas" category exists in your discussions
2. The workflow uses `category: "ideas"` - ensure this category is available
3. You can add categories in: Settings → Discussions → Categories

### Issue: "Insufficient permissions" error

The workflow needs the following permissions:
- `discussions: write` - To create and update discussions

These permissions are already configured in the workflow files. If you still see permission errors:

1. Check that the `GITHUB_TOKEN` has the required permissions
2. Verify that branch protection rules aren't blocking the workflow
3. Ensure you're not using a custom `GITHUB_TOKEN` with restricted permissions

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
