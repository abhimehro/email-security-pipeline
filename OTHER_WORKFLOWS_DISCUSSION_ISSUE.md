# Potential Discussion-Related Failures in Other Workflows

## Overview

Since Discussions are not enabled in this repository, the following workflows may also fail when attempting to create discussions:

## Affected Workflows

### 1. Daily QA (`daily-qa.md`)
**Safe Output Configuration:**
```yaml
safe-outputs:
  create-discussion:
    title-prefix: "${{ github.workflow }}"
    category: "q-a"
    max: 1
```

**Purpose**: Creates QA findings discussions

**Recommended Fix**: Change to `create-issue` with label `[qa]` or `[quality-assurance]`

### 2. Daily Perf Improver (`daily-perf-improver.md`)
**Safe Output Configuration:**
```yaml
safe-outputs:
  create-discussion:
    title-prefix: "${{ github.workflow }}"
    category: "ideas"
    max: 5
```

**Purpose**: Creates performance optimization discussions

**Recommended Fix**: Change to `create-issue` with label `[performance]` or `[optimization]`

## How to Apply Similar Fixes

For each affected workflow, follow these steps:

### 1. Update Safe Outputs Configuration

Replace:
```yaml
safe-outputs:
  create-discussion:
    title-prefix: "${{ github.workflow }}"
    category: "ideas"  # or "q-a"
    max: N
```

With:
```yaml
safe-outputs:
  create-issue:
    title-prefix: "${{ github.workflow }}"
    labels: [appropriate-label, automation]
    max: N
```

### 2. Update Workflow Instructions

Search and replace in the workflow markdown:
- `list_discussions` → `list_issues`
- `create a discussion` → `create an issue`
- `discussion` → `issue` or `tracking issue` (context-dependent)
- Keep references to "discussion" in variable names if they don't affect functionality

### 3. Recompile the Workflow

```bash
gh aw compile <workflow-name>
```

### 4. Test the Updated Workflow

```bash
gh aw run <workflow-name> --repo abhimehro/email-security-pipeline
```

## Monitoring for Failures

To check if these workflows are failing:

```bash
# Check recent workflow runs
gh run list --workflow=daily-qa.lock.yml --limit=5
gh run list --workflow=daily-perf-improver.lock.yml --limit=5

# Get detailed logs for a specific run
gh aw logs daily-qa
gh aw logs daily-perf-improver
```

## Why Not Enable Discussions?

While enabling Discussions would allow these workflows to work as designed, using Issues instead offers several advantages:

1. **Universal Availability**: Issues are enabled by default in all repositories
2. **Better Integration**: Issues integrate better with project boards and milestones
3. **Familiar UX**: Most developers are more familiar with Issues
4. **Linking Capabilities**: Issues can be easily referenced in commits, PRs, and other issues
5. **Label Organization**: Issues support labels for better categorization

## Decision Matrix

| Factor | Use Discussions | Use Issues |
|--------|----------------|------------|
| Feature must be explicitly enabled | ❌ Yes | ✅ No |
| Supports threaded conversations | ✅ Better | ✅ Good |
| Integrates with project boards | ⚠️ Limited | ✅ Full |
| Can be assigned to users | ❌ No | ✅ Yes |
| Supports labels | ✅ Categories | ✅ Labels |
| Can be linked to PRs | ✅ Yes | ✅ Yes |
| Automatic closing/expiring | ✅ Yes | ✅ Yes |

## Recommendation

✅ **Convert all discussion-based workflows to use Issues** unless there's a specific reason to use Discussions.

This provides:
- More robust workflows (won't fail if Discussions are disabled)
- Better developer experience (familiar interface)
- Enhanced project management capabilities

## Files to Monitor

If you choose to fix these workflows later:
- `.github/workflows/daily-qa.md`
- `.github/workflows/daily-perf-improver.md`

## Related Issues

This fix addresses issue #232 for the daily-backlog-burner workflow. If similar failures occur for other workflows, they can be fixed using the same approach.

---

**Note**: This document is for informational purposes. Only the daily-backlog-burner workflow has been fixed as part of this issue resolution.
