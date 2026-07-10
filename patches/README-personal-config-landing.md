# Landing personal-config security fix (ABHI-1358, ABHI-1359, ABHI-1361)

The cloud agent cannot push to `abhimehro/personal-config` (403 for `cursor[bot]`).
The fix is shipped in this repository as an apply-able patch so you can land it from
your own credentials.

## Patch

`patches/personal-config-abhi-1358-1359-1361-command-injection.patch`

Commit message inside the patch:

```
security(ABHI-1358,1359,1361): stop sourcing GH_TOKEN.env in PR scripts
```

## Apply from a clean personal-config checkout

```bash
cd /path/to/personal-config
git fetch origin main
git checkout -b cursor-agent/fix-command-injection-pr-scripts-babb origin/main
git am /path/to/email-security-pipeline/patches/personal-config-abhi-1358-1359-1361-command-injection.patch
python3 -m pytest tests/test_gh_token_env.py tests/test_pr_automation_scripts.py -q
git push -u origin cursor-agent/fix-command-injection-pr-scripts-babb
```

Or fetch the patch from the email-security-pipeline PR branch:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/abhimehro/email-security-pipeline/cursor-agent/fix-close-prs-command-injection-babb/patches/personal-config-abhi-1358-1359-1361-command-injection.patch \
  -o /tmp/personal-config-security.patch
cd /path/to/personal-config
git checkout -b cursor-agent/fix-command-injection-pr-scripts-babb origin/main
git am /tmp/personal-config-security.patch
git push -u origin cursor-agent/fix-command-injection-pr-scripts-babb
```

## What the patch changes

| File | Change |
|------|--------|
| `close_prs.sh` | `source GH_TOKEN.env` → `source scripts/ensure_gh_token.sh` |
| `fix_drafts.sh` | same |
| `close_more.sh` | same |
| `gh_token_env.py` | reject command substitution in parsed values |
| `tests/test_gh_token_env.py` | regression test |
| `tests/test_pr_automation_scripts.py` | new — verifies no `source *.env` |

## Verify after apply

```bash
rg 'source .*GH_TOKEN\.env' close_prs.sh fix_drafts.sh close_more.sh  # expect no matches
python3 -m pytest tests/test_gh_token_env.py tests/test_pr_automation_scripts.py -q
```
