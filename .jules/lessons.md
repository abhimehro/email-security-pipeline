## YYYY-MM-DD - Pre-commit and patch files

**Learning:** Running `pre-commit` hooks like `trailing-whitespace` and `end-of-file-fixer` globally can inadvertently modify and break `.patch` files by stripping required leading whitespace from empty context lines.

**Action:** Before running `pre-commit` on a repository containing patch files, verify that `*.patch` files are explicitly excluded from formatting hooks in `.pre-commit-config.yaml` using the `exclude` directive.
