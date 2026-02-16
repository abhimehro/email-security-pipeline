# Action Required: Enable GitHub Discussions

## Problem

Several agentic workflows are failing because **GitHub Discussions are not enabled** in this repository.

### Failed Workflows:
- [Daily Perf Improver](https://github.com/abhimehro/email-security-pipeline/actions/runs/22034991943) - Failed to create "Research and Plan" discussion
- Daily QA (will fail when it tries to create discussions)
- Daily Backlog Burner (will fail when it tries to create discussions)

### Error Message:
```
Failed to create discussion in 'abhimehro/email-security-pipeline': 
Resource not accessible by integration. Common causes: 
(1) Discussions not enabled in repository settings
```

## Solution

Enable GitHub Discussions for this repository:

### Steps:

1. **Go to Repository Settings**
   - Navigate to: https://github.com/your-username/your-repository/settings

2. **Enable Discussions Feature**
   - Scroll down to the **Features** section
   - Check the box next to **Discussions**
   - Click **Set up discussions** if prompted

3. **Configure Discussion Categories** (recommended)
   - **Announcements** - For workflow announcements
   - **Ideas** - For workflow research and proposals (required by Daily Perf Improver and Daily Backlog Burner)
   - **General** - For general discussions (required by Daily QA)
   - **Q&A** - For questions and troubleshooting
4. **Verify Setup**
   - Visit: https://github.com/your-username/your-repository/discussions
   - You should see the discussions interface

5. **Re-run Failed Workflows**
   ```bash
   gh workflow run daily-perf-improver.lock.yml
   ```
   Or use the GitHub Actions UI to re-run the failed workflow runs.

## Documentation

For more details, see:
- [Agentic Workflows Setup Guide](AGENTIC_WORKFLOWS_SETUP.md)
- [GitHub Discussions Documentation](https://docs.github.com/en/discussions/quickstart)

## Impact

Until discussions are enabled:
- ❌ Agentic workflows cannot coordinate work or share research
- ❌ Performance improvement planning will fail
- ❌ QA automation cannot track progress
- ❌ Backlog management workflows cannot function

After enabling discussions:
- ✅ All agentic workflows will function properly
- ✅ Workflows can coordinate and track progress
- ✅ Research and plans will be shared in discussions
- ✅ Better collaboration and transparency

## Questions?

If you have any questions or need help with this setup, please:
- Comment on this issue
- Check the [setup guide](AGENTIC_WORKFLOWS_SETUP.md)
- Review the [GitHub Discussions documentation](https://docs.github.com/en/discussions)
