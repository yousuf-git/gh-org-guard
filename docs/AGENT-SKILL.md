# Agent skill: `create-pr-guarded`

[`skills/create-pr-guarded/`](../skills/create-pr-guarded/) is an Agent Skill: a `SKILL.md` plus scripts that Claude Code, Cursor and Codex load when they're relevant. It teaches a developer's AI agent the org rules and gives it a local copy of the scan, so its work passes the first time and real attacks are escalated instead of "fixed".

- [Install](#install)
- [Update, list, remove](#update-list-remove)
- [Manual install (no npx)](#manual-install-no-npx)
- [What the agent learns](#what-the-agent-learns)
- [Preflight](#preflight)
- [Removing an AI trailer](#removing-an-ai-trailer)
- [Using it in your own org](#using-it-in-your-own-org)

## Install

The standard way to deliver skills is the [`skills`](https://github.com/vercel-labs/skills) CLI, which finds `skills/<name>/SKILL.md` in a GitHub repo:

```bash
# all three agents
npx skills add yousuf-git/gh-org-guard -g -a claude-code -a cursor -a codex

# one agent only
npx skills add yousuf-git/gh-org-guard -g -a claude-code
npx skills add yousuf-git/gh-org-guard -g -a cursor
npx skills add yousuf-git/gh-org-guard -g -a codex

# no -a: the CLI detects installed agents and asks
npx skills add yousuf-git/gh-org-guard -g
```

| Agent | Global location | How it loads |
|---|---|---|
| Claude Code | `~/.claude/skills/create-pr-guarded/` | Picked automatically from the description; also `/create-pr-guarded` |
| Cursor | `~/.cursor/skills/create-pr-guarded/` | Picked automatically; also `/create-pr-guarded` in Agent chat. Cursor also reads `~/.agents/skills/` and Claude's skill folders. User-level skills apply to local Cursor only, not cloud agents. |
| Codex | `~/.agents/skills/create-pr-guarded/` | Picked automatically; restart Codex if it doesn't appear |

> [!WARNING]
> **Always install globally (`-g`).** The CLI's default is a *project* install (`.claude/skills/`, `.agents/skills/` in the current repo). The skill bundles YARA rules and checkers that contain attack signatures as text. Committed to a scanned repo, they make `yara` and `repo-policy` flag that repo. If the skill gets committed by mistake, remove it from the repo in a PR and reinstall with `-g`.

Use `-y` to skip prompts (for setup scripts), and `--copy` to copy files instead of symlinking when your filesystem doesn't support symlinks.

## Update, list, remove

```bash
npx skills list -g                         # what is installed globally
npx skills update -g                       # pull the latest version of global skills
npx skills remove create-pr-guarded -g     # uninstall
```

## Manual install (no npx)

```bash
git clone --depth 1 https://github.com/yousuf-git/gh-org-guard /tmp/gh-org-guard
mkdir -p ~/.claude/skills    # or ~/.cursor/skills, or ~/.agents/skills for Codex
cp -r /tmp/gh-org-guard/skills/create-pr-guarded ~/.claude/skills/
rm -rf /tmp/gh-org-guard
```

## What the agent learns

`SKILL.md` covers:

- **What GitHub enforces**, and the exact errors the agent will see: `GH013 … Changes must be made through a pull request`, `Cannot force-push to this branch`, `REVIEW_REQUIRED`, `Required workflows 'security-scan' failed`.
- **Commits:**
  - never credit an AI tool; in Claude Code, turn attribution off with `"attribution": {"commit": "", "pr": ""}` in `settings.json`;
  - no secrets, `.env`, binaries or `node_modules`;
  - don't touch `.vscode/`, `.devcontainer/`, `.claude/`, `.github/`, git hooks, `.npmrc`/`.yarnrc*` or `package.json` scripts unless asked.
- **Dependencies:**
  - runtime libraries go in `dependencies`;
  - no versions under 72 h old, with the per-package-manager cooldown setting;
  - install untrusted code with `--ignore-scripts`.
- **Branches and PRs:**
  - feature branches only; `--force-with-lease` only on the agent's own branch;
  - run the preflight before pushing, and batch pushes to save Actions minutes;
  - never merge, approve or use `--admin` unless the user asks.
- **When a check fails:**
  - a **STOP** list of findings that mean possible compromise: hidden code, fake fonts, auto-run config, any YARA or ClamAV hit. The agent stops, doesn't run the project or destroy evidence, tells the user, and recommends credential rotation;
  - a table of normal fixes for every other finding, keyed to the checkers' exact messages;
  - a "never do these" list: editing the workflow, adding allowlists, asking for a bypass, `--no-verify`, closing the security issue;
  - how to report a false positive.

## Preflight

`scripts/preflight.sh` runs the same six checks as CI on the current branch, using the same YARA rules and checkers. `build.py` copies them into the skill, and the `self-test` workflow fails if the copies drift.

```bash
# from the repository root, after committing
bash ~/.claude/skills/create-pr-guarded/scripts/preflight.sh                # compares with origin/main
bash ~/.claude/skills/create-pr-guarded/scripts/preflight.sh origin/master  # other base branch
```

| Check | Needs | If missing |
|---|---|---|
| `repo-policy`, `ai-coauthor` | `git`, `python3` (standard library only) | — (always run) |
| `dependency-audit` | `python3`, `npm`/`npx`, network access to the npm registry | fails closed if the registry can't be reached |
| `yara` | `yara` CLI (`apt install yara`, `brew install yara`) | skipped and reported; CI still runs it |
| `clamav` | `clamscan` with signatures (`apt install clamav`, `brew install clamav`, then `freshclam`) | skipped and reported |
| `gitleaks` | [`gitleaks`](https://github.com/gitleaks/gitleaks) 8.x | skipped and reported |

`repo-policy` reads the git index, so commit or `git add` first. The submodule rule uses the org from the `origin` remote. The script exits 1 and prints `FAILED: <checks>` when anything fails.

## Removing an AI trailer

The recipe from `SKILL.md`, for a feature branch whose commits credit an AI tool:

```bash
base=$(git merge-base origin/main HEAD)
git -c core.editor=true rebase "$base" --exec \
  'git log -1 --format=%B | grep -viE "co-authored-by:.*(claude|anthropic|cursor|copilot|openai|chatgpt|codex|gemini|devin|aider|windsurf|codeium|tabnine)|generated with" | git commit --amend --reset-author -F -'
git log --format='%an <%ae>%n%B' "$base"..HEAD   # confirm nothing AI-credited is left
git push --force-with-lease
```

`--reset-author` replaces an AI author identity with the user's own. This recipe was tested on a sandbox branch: the trailer was removed, the author kept, and the preflight passed afterwards.

## Using it in your own org

The skill is generic: it describes the rulesets and checks in this repo, not a particular org. If you change thresholds, allowlists or checks in your fork, fork the skill too:

1. Edit `skills/create-pr-guarded/SKILL.md` to match, for example the cooldown hours or a removed check.
2. Run `python3 build.py` so `scripts/` carries your rules and checkers.
3. Have developers install from your fork: `npx skills add your-org/your-fork -g`.
