# Daily Backlog Burner Workflow Fix - Summary

## Problem Statement

The Daily Backlog Burner workflow failed with the error:
```
Failed to create discussion in 'abhimehro/email-security-pipeline': 
Request failed due to following response errors:
- Resource not accessible by integration. Common causes: 
  (1) Discussions not enabled in repository settings
```

## Root Cause

The workflow was configured to use GitHub Discussions to track backlog management progress, but **Discussions are not enabled** in the `abhimehro/email-security-pipeline` repository.

## Solution Implemented

Modified the workflow to use **GitHub Issues** instead of Discussions, since Issues are available in all repositories by default.

### Changes Made to `.github/workflows/daily-backlog-burner.md`

1. **Safe Outputs Configuration** (lines 18-22):
   ```yaml
   # Before:
   safe-outputs:
     create-discussion:
       title-prefix: "${{ github.workflow }}"
       category: "ideas"
       max: 3
   
   # After:
   safe-outputs:
     create-issue:
       title-prefix: "${{ github.workflow }}"
       labels: [backlog-management, automation]
       max: 3
   ```

2. **Phase Selection Logic** (line 51):
   ```markdown
   # Before:
   First check for existing open discussion titled "${{ github.workflow }}" using `list_discussions`
   
   # After:
   First check for existing open issue with title starting with "${{ github.workflow }} - Research, Roadmap and Plan" using `list_issues`
   ```

3. **Tracking Artifact Creation** (line 68):
   ```markdown
   # Before:
   Use this research to create a discussion with title "..."
   
   # After:
   Use this research to create an issue with title "..."
   ```

4. **All References Updated**:
   - "discussion" → "tracking issue" or "issue"
   - "planning discussion" → "planning issue"
   - Maintained all original functionality

## How It Works Now

### Phase 1: Research & Planning
1. Workflow researches the entire backlog of issues and PRs
2. Creates a **tracking issue** titled "Daily Backlog Burner - Research, Roadmap and Plan"
3. Issue contains comprehensive backlog analysis and recommendations
4. Maintainers can comment on the issue to adjust priorities

### Phase 2: Execution
1. Workflow reads the tracking issue and maintainer feedback
2. Selects a backlog item to work on
3. Creates a branch and implements changes
4. Creates a draft PR with the improvements
5. Comments on the tracking issue with progress

## Testing & Verification

### To Complete This Fix

The workflow needs to be recompiled to generate the updated `.lock.yml` file:

```bash
# Option 1: Compile specific workflow
gh aw compile daily-backlog-burner

# Option 2: Compile all workflows
gh aw compile
```

### To Test the Fix

After compilation, trigger the workflow manually:

```bash
# Run the workflow
gh aw run daily-backlog-burner --repo abhimehro/email-security-pipeline

# Or use GitHub UI: Actions → Daily Backlog Burner → Run workflow
```

### Expected Behavior

1. ✅ Workflow completes successfully (no "Resource not accessible" errors)
2. ✅ Creates a tracking issue: "Daily Backlog Burner - Research, Roadmap and Plan"
3. ✅ Issue contains backlog research and recommendations
4. ✅ On subsequent runs, workflow reads the issue and works on backlog items

## Alternative: Enable Discussions

If you prefer to use Discussions instead of Issues, you can:

1. Enable Discussions in repository settings:
   - Go to https://github.com/abhimehro/email-security-pipeline/settings
   - Scroll to "Features" section
   - Check "Discussions"
   - Create a category called "ideas"

2. Revert the workflow changes (use the original version)

3. Recompile the workflow

However, **using Issues is recommended** because:
- ✅ Issues are available in all repositories by default
- ✅ Better integration with project management tools
- ✅ More familiar to most developers
- ✅ Can be linked to PRs and other issues
- ✅ Support labels for better organization

## Files Modified

- `.github/workflows/daily-backlog-burner.md` - Workflow definition
- `.github/workflows/COMPILE_NEEDED.md` - Compilation instructions

## Files That Need Updating (After Compilation)

- `.github/workflows/daily-backlog-burner.lock.yml` - Compiled workflow (auto-generated)

## Related Workflows

The following workflows also use Discussions and may need similar fixes if Discussions remain disabled:

- `daily-qa.md` - Uses `create-discussion` with category "q-a"
- `daily-perf-improver.md` - Uses `create-discussion` with category "ideas"

Consider applying the same fix to these workflows if they encounter similar failures.

## Security Considerations

✅ This fix maintains the same security posture:
- Issues require the same permissions as Discussions
- Workflow still operates in read-only mode for repository content
- Safe-outputs configuration prevents unauthorized actions

## Support

If you encounter any issues after applying this fix:

1. Check workflow run logs: `gh aw logs daily-backlog-burner`
2. Verify the workflow was compiled: Check if `.lock.yml` file is updated
3. Ensure repository has Issues enabled (they should be by default)
4. Review the tracking issue created by the workflow

---

**Fix Author**: GitHub Copilot  
**Date**: 2026-02-16  
**Issue**: #232 - [agentics] Daily Backlog Burner failed
