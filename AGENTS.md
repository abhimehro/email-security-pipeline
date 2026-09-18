# Agent Development Environment Setup

## Cursor Cloud specific instructions

### Project overview

Email Security Analysis Pipeline — a Python-based email security system that
monitors IMAP mailboxes and runs multi-layer threat detection (spam, NLP, media
analysis). Runtime is **Python 3.13** (CI and Docker). See `README.md` for full
details.

### Running tests

```bash
python3 -m pytest        # runs the full test suite; no external services or credentials needed
python3 -m pytest -v     # verbose output
```

Tests mock all IMAP connections and external services; no `.env` file is
required.

### Linting

```bash
python3 -m pre_commit run --all-files
```

Note: the repo may have pre-existing lint issues (trailing whitespace, EOF
fixes). These are not regressions.

### Running the application

The pipeline requires a `.env` file with IMAP credentials (see `.env.example`).
To start:

```bash
cp .env.example .env   # then edit with real credentials
python3 src/main.py
```

Without valid IMAP credentials the pipeline will fail at the connection step.
For local development without credentials, you can exercise the analysis modules
directly by importing from `src.modules`.

### Key gotchas

- **Colima required:** LaunchAgent / compose path expects Colima. Fail fast if
  `colima` is missing; never `colima delete` (shared with Jellyfin / Control D
  host DNS). After code changes: `compose up --rebuild` — image COPY's `src/`,
  not a bind mount.
- **Control D coexistence:** Colima/Lima must not forward guest `:53` to the
  host. Patch `~/.colima/_lima/_config/override.yaml` via
  `~/dev/personal-config/scripts/free-port53-for-controld.sh --patch-colima-ignore`
  (see personal-config `AGENTS.md` / Lesson 0dk). Otherwise limactl steals DNS
  from ctrld.
- **Alert gating:** Do not gate solely on `overall_threat_score >= THREAT_LOW` —
  layer-flagged medium/high can sit below the floor.
- **ML dependencies not installed by default**: optional `torch` /
  `transformers` / `sentencepiece` are **not** in `requirements.txt`
  (runtime-only pins for Docker) and are excluded from
  `requirements-ci.txt`. The NLP analyzer falls back to regex-based pattern
  matching when these are absent.
- **Dependencies**: Use `requirements-ci.txt` for development to avoid
  installing multi-GB ML libraries (`torch`, `transformers`, etc.). Do not
  add optional ML packages to `requirements.txt` without an explicit product
  choice — that file is the Docker/runtime pin set, not a commented extras
  list.
- **PATH for pip-installed scripts**: User-installed pip scripts land in
  `~/.local/bin`. Ensure this directory is in your `PATH`.
- **`core.hooksPath` conflict**: If `pre-commit install` fails with a
  `core.hooksPath` error, first check where it is set with
  `git config --show-origin --get-all core.hooksPath`. If it is set in the local
  repo, run `git config --unset-all core.hooksPath`; if it is set globally or
  system-wide, unset it with `git config --global --unset-all core.hooksPath` or
  `git config --system --unset-all core.hooksPath` as appropriate.

### CodeScene review/salvage trigger

During automated PR review or salvage sessions, if CodeScene is red on a PR,
post:

```bash
/cs-agent skill:fix-code-health-degradations
```

Then wait for that run to complete before final defer/salvage disposition.

<!-- gitnexus:start -->

# GitNexus — Code Intelligence

This project is indexed by GitNexus as **email-security-pipeline** (3302
symbols, 6939 relationships, 184 execution flows).

> Index stale? Run `node .gitnexus/run.cjs analyze --index-only` from the
> project root — it auto-selects an available runner. No `.gitnexus/run.cjs`
> yet? Bootstrap with `npx`, `bunx`, or `pnpm dlx` — e.g.
> `bunx gitnexus@latest analyze` (npm 11 npx crash; #1939).

## Always Do

- **MUST run impact analysis before editing.** Use
  `impact({target: "symbolName", direction: "upstream"})` (MCP) or
  `node .gitnexus/run.cjs impact "symbolName" --direction upstream --repo .`
  (CLI fallback); report callers, processes, and risk. Never substitute grep for
  graph analysis.
- **MUST analyze graph changes before committing.** Use
  `detect_changes({scope: "all"})` (MCP) or
  `node .gitnexus/run.cjs detect-changes --scope all --repo .` (CLI fallback).
  `partial: true` or `truncated: true` is not a clean check — a zero means
  unseen, not unaffected; re-run it. For regression review:
  `detect_changes({scope: "compare", base_ref: "main"})` or
  `node .gitnexus/run.cjs detect-changes --scope compare --base-ref "main" --repo .`.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before
  proceeding with edits.
- **MUST treat `risk: UNKNOWN` as unresolved, not as low.** An empty caller set
  is not evidence the symbol is unused — it can also mean the callers are not
  resolvable by the index (plain-object property access, dynamic dispatch,
  cross-language calls). `impact` pairs `UNKNOWN` with a `riskNote` saying so.
  Confirm with a text search before treating the symbol as safe to change or
  delete; do not proceed on the strength of a zero.
- When exploring unfamiliar code, use `query({search_query: "concept"})` to find
  execution flows instead of grepping. It returns process-grouped results ranked
  by relevance.
- When you need full context on a specific symbol — callers, callees, which
  execution flows it participates in — use `context({name: "symbolName"})`.
- For security review, `explain({target: "fileOrSymbol"})` lists taint findings
  (source→sink flows; needs `analyze --pdg`).

## Never Do

- NEVER edit a function, class, or method before MCP/CLI impact analysis.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis, and never
  read `UNKNOWN` as an all-clear — it means the walk could not answer, which is
  the one verdict that requires confirming by other means.
- NEVER rename symbols with find-and-replace — use `rename` which understands
  the call graph.
- NEVER commit before MCP/CLI graph change analysis.

## Resources

| Resource                                                 | Use for                                  |
| -------------------------------------------------------- | ---------------------------------------- |
| `gitnexus://repo/email-security-pipeline/context`        | Codebase overview, check index freshness |
| `gitnexus://repo/email-security-pipeline/clusters`       | All functional areas                     |
| `gitnexus://repo/email-security-pipeline/processes`      | All execution flows                      |
| `gitnexus://repo/email-security-pipeline/process/{name}` | Step-by-step execution trace             |

## CLI

| Task                                         | Read this skill file                                |
| -------------------------------------------- | --------------------------------------------------- |
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus-exploring/SKILL.md`        |
| Blast radius / "What breaks if I change X?"  | `.claude/skills/gitnexus-impact-analysis/SKILL.md`  |
| Trace bugs / "Why is X failing?"             | `.claude/skills/gitnexus-debugging/SKILL.md`        |
| Rename / extract / split / refactor          | `.claude/skills/gitnexus-refactoring/SKILL.md`      |
| Tools, resources, schema reference           | `.claude/skills/gitnexus-guide/SKILL.md`            |
| Index, status, clean, wiki CLI commands      | `.claude/skills/gitnexus-cli/SKILL.md`              |
| Work in the Tests area (690 symbols)         | `.claude/skills/gitnexus-area-tests/SKILL.md`       |
| Work in the Modules area (249 symbols)       | `.claude/skills/gitnexus-area-modules/SKILL.md`     |
| Work in the Scripts area (12 symbols)        | `.claude/skills/gitnexus-area-scripts/SKILL.md`     |
| Work in the Cluster_78 area (9 symbols)      | `.claude/skills/gitnexus-area-cluster-78/SKILL.md`  |
| Work in the Cluster_103 area (8 symbols)     | `.claude/skills/gitnexus-area-cluster-103/SKILL.md` |
| Work in the Cluster_36 area (5 symbols)      | `.claude/skills/gitnexus-area-cluster-36/SKILL.md`  |
| Work in the Cluster_104 area (4 symbols)     | `.claude/skills/gitnexus-area-cluster-104/SKILL.md` |

<!-- gitnexus:end -->
