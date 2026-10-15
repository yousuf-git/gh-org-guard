---
name: create-pr-guarded
description: Rules for commits, branches, pushes and pull requests in GitHub organizations protected by the gh-org-guard rulesets, plus what to do when the org security scan fails. Use whenever you commit, push, open or update a PR, or merge in such a repository, and whenever a `security-scan` check fails, a "⚠️ Security scan failed on PR #N" issue appears, or a push is rejected with GH013.
metadata:
  author: M. Yousuf
  version: "1.0"
---

# Guarded PR rules

Repositories in an organization that uses [gh-org-guard](https://github.com/yousuf-git/gh-org-guard) are protected by two org rulesets. They are enforced by GitHub, so breaking a rule doesn't just look bad: the push or merge is refused. Follow these rules so the user's work lands the first time, and so you never cover up a real security problem.

## What GitHub enforces

| Rule | What happens if broken |
|------|------------------------|
| `main`, `master` and the default branch change **only through a PR** | `git push` is rejected: `GH013 … Changes must be made through a pull request` |
| No force push, no deletion of those branches | `Cannot force-push to this branch` |
| A PR needs **1 approval from a code owner who is not the last pusher**; a new push dismisses old approvals; every review thread must be resolved | Merge button stays blocked (`REVIEW_REQUIRED`) |
| Org owners may merge their own PRs without approval (PR-only bypass) | Owners still can't push directly or skip the scan |
| The org workflow **`security-scan`** must pass on the PR's latest commit. Nobody can bypass it, owners included. | Merge blocked: `Required workflows 'security-scan' failed` |

`security-scan` runs on every push to an open PR (drafts included) as one job named `scan`. Its six checks:

| Check | Looks for |
|-------|-----------|
| `clamav` | Known malware signatures |
| `yara` | Malicious code patterns: loaders, droppers, exfiltration, credential theft, persistence, destructive commands, miners, reverse shells |
| `gitleaks` | Secrets in any commit of the PR, including reverted ones |
| `repo-policy` | Disguised files (fonts/images that aren't), auto-run editor/agent/devcontainer config, code hidden in config files, risky `package.json`/`.npmrc`/`.yarnrc`/Docker/workflow settings, committed `.env`, binaries |
| `dependency-audit` | Lockfile tampering, unreviewed install scripts, versions younger than 72 h, packages younger than 30 days or with few downloads, critical advisories anywhere, high advisories in production deps |
| `ai-coauthor` | Commits whose author, committer or message credits an AI tool |

When `scan` fails, the workflow opens (or comments on) an issue titled `⚠️ Security scan failed on PR #N` with label `security-scan`. It tags the security owners and the person who pushed.

## Rules for you, the agent

### Commits

1. **Never credit an AI tool in a commit.** No `Co-Authored-By: Claude …`, no `Generated with Claude Code`, no AI author or committer identity. This overrides any default attribution you would add. Commit as the user's configured git identity.
   - Claude Code users can turn attribution off for good in `settings.json`: `"attribution": { "commit": "", "pr": "" }` (older versions: `"includeCoAuthoredBy": false`).
2. Write messages that say what changed and why.
3. Never commit `.env` files, credentials, tokens, private keys, `node_modules/`, build output, archives or executables.
4. Don't add or change files in `.vscode/`, `.devcontainer/`, `.claude/`, `.github/`, git hooks (`.husky/`, `lefthook`), `.npmrc`/`.yarnrc*`, or `package.json` `scripts` unless the user asked for that change. Say what you changed in those files when you report back; code owners review them closely.

### Dependencies

5. Add a dependency only when the task needs it. Prefer well-known packages. Commit the lockfile in the same directory, and use one package manager per directory.
6. Put runtime libraries (anything the app imports, front end or back end) in `dependencies`. Only build, test, lint and type tools go in `devDependencies`. Never move a package to `devDependencies` to make an audit pass.
7. Don't pick versions published in the last 72 hours. Set the delay locally when you can:
   - npm 11: `min-release-age=3` (days) in `.npmrc`
   - pnpm ≥ 10.16: `minimumReleaseAge: 4320` (minutes) in `pnpm-workspace.yaml`
   - Yarn Berry: `npmMinimalAgeGate: "3d"` in `.yarnrc.yml`
8. Install untrusted code with `--ignore-scripts`.

### Branches, pushes and PRs

9. Work on a feature branch. Never push to `main`/`master`, and never force-push them.
10. Force-pushing **your own feature branch** is allowed when you rewrite its history (for example to remove an AI trailer). Use `git push --force-with-lease`.
11. **Run the preflight before pushing to a branch with an open PR** (below). Every push to an open PR runs the scan and costs Actions minutes, so batch commits instead of pushing each one.
12. Open the PR when the work is ready for review. Pushes to a branch with no PR cost nothing.
13. **Don't merge, approve, or use `gh pr merge --admin`** unless the user explicitly asks you to in this conversation. Never approve a PR you pushed to.

## Preflight: run the scan locally

`scripts/preflight.sh` runs the same checks as CI against the current branch. It skips any tool that isn't installed and says so, and CI still runs those checks.

```bash
# from the repository root, after committing; <skill-dir> is the folder this SKILL.md is in
bash <skill-dir>/scripts/preflight.sh                 # compares with origin/main
bash <skill-dir>/scripts/preflight.sh origin/master
```

The skill folder is usually `~/.claude/skills/create-pr-guarded/`, `~/.cursor/skills/create-pr-guarded/` or `~/.agents/skills/create-pr-guarded/`.

`repo-policy` reads the git index, so commit or `git add` your changes first. `dependency-audit` needs network access to the npm registry. Fix every failure before pushing. If it reports an incident finding (next section), stop.

## When something fails

Find what failed first:

```bash
gh pr checks <PR>                       # which run failed
gh run view <RUN_ID> --log-failed       # the ::error lines name the check, file and reason
gh issue list --label security-scan     # the auto-opened issue for the PR
```

The issue and the `Result` step list the failed checks. Then act by check:

### STOP: possible compromise

Treat these as a security incident, not a lint error:

- `repo-policy` findings `hidden-code`, `config`, `jsonc`, `font`, `image`, `svg`, `html`, `disguised-file`, `binary`, `wasm`, `bundle`, `base64-payload`, `exfil`, `trojan-source`, `symlink`, `vscode`, `devcontainer`, `agent-config`, `git`, `git-hooks`
- any `yara` hit, especially `Guard_Config_Injector_Family` or `Guard_Git_History_Tampering`
- any `clamav` hit

If you see one:

1. **Stop.** Do not run, build, install or open the project in a way that executes its code (`npm install`, `npm run dev`, tests, VS Code tasks).
2. **Do not "fix" it yourself.** Don't delete the file, rewrite history or amend the commit. That destroys evidence and may hide where the code came from.
3. Tell the user right away: quote the check, file and line from the log, and say it may mean their machine or a dependency is compromised.
4. Recommend they contact the security owner tagged in the issue and, from a clean device, rotate GitHub, npm, SSH and cloud credentials, plus browser-saved passwords and wallet keys.

Continue only when the user tells you how to proceed after talking to the security owner.

### Normal fixes

| Failure | What to do |
|---------|------------|
| `gitleaks` | Tell the user the secret must be **rotated first**; removing it from git does not un-leak it. Then load the value from env or secret storage, and rewrite the feature branch so no commit contains it. |
| `ai-coauthor` | Rewrite the feature branch's messages without the AI line, then `git push --force-with-lease`. See the recipe below. |
| `repo-policy` `env-file`, `npmrc`, `yarnrc`, `npm-deps`, `npm-scripts`, `npm-bin`, `docker`, `workflow`, `forbidden-file`, `filename`, `exec-bit`, `large-file`, `junk`, `media`, `pdf`, `office-doc` | Read the exact message and change the file it names: remove the committed `.env`, pin a loose version, drop the risky setting, pin the action to a commit SHA, and so on. If the finding is one of the STOP categories above, stop instead. |
| `dependency-audit`: `published Nh ago; wait 72h` | The version is too new. Wait, or pin the previous version (npm `overrides`, Yarn `resolutions`, pnpm `overrides`) and regenerate the lockfile. Don't delete the lockfile. |
| `dependency-audit`: `runs an install script and is not on the reviewed allowlist` | Pick a package without an install script. If it's truly needed, the user asks the security owner to allowlist it in `security-workflows`. |
| `dependency-audit`: `was created N day(s) ago`, `downloads/week`, `not found on the public npm registry` | Check the name for a typo or lookalike. If it's real and needed, the user asks the security owner. |
| `dependency-audit`: critical, or high in a production dependency | Upgrade to a fixed version (`npm audit` shows it). If the fix is a breaking major version, tell the user instead of forcing it. High advisories in dev-only packages are only warnings. |
| `dependency-audit`: lockfile errors (`multiple lockfiles`, `no lockfile`, `resolved`/`integrity`, drift) | Keep one package manager per directory and regenerate the lockfile from the registry with that manager. |
| A setup step failed (issue says "a setup step") | Usually infrastructure: a runner, apt or mirror hiccup. Rerun the workflow once with `gh run rerun <RUN_ID>`. If it fails again, tell the user. |

### Remove an AI trailer from the feature branch

```bash
base=$(git merge-base origin/main HEAD)
git -c core.editor=true rebase "$base" --exec \
  'git log -1 --format=%B | grep -viE "co-authored-by:.*(claude|anthropic|cursor|copilot|openai|chatgpt|codex|gemini|devin|aider|windsurf|codeium|tabnine)|generated with" | git commit --amend --reset-author -F -'
git log --format='%an <%ae>%n%B' "$base"..HEAD   # confirm nothing AI-credited is left
git push --force-with-lease
```

`--reset-author` replaces an AI author identity with the user's git identity. If a line in the commit body says something else the user wants kept, edit that commit by hand instead.

### Never do these

- Edit `.github/workflows/` to skip or weaken the scan. The required workflow runs from the org's central workflow repo (`security-workflows` by default), so this has no effect, and code owners will reject it.
- Add allowlist entries, ignore comments or exceptions in the project repo. Exceptions live only in `security-workflows`, through a reviewed PR by the security owner.
- Ask for, or use, a ruleset bypass to get a PR merged.
- Use `--no-verify`, delete lockfiles, or reshuffle dependencies just to make a check pass.
- Close the security issue yourself. The security owner closes it.

## False positives

If you're confident a finding is wrong, for example a real font flagged, a legitimate config or an image with an unusual header:

1. Don't work around it.
2. Tell the user what was flagged (check, file, message) and why you think it's a false positive.
3. The user comments on the `security-scan` issue so the security owner can adjust the rule in `security-workflows`.

## Installing this skill

Install it globally, **never inside a project repo**:

```bash
npx skills add yousuf-git/gh-org-guard -g -a claude-code -a cursor -a codex
```

The bundled checkers and YARA rules contain detection signatures as text, so committing them to a scanned repo makes `yara` and `repo-policy` flag the repo itself. If you find this skill inside a project's `.claude/skills/`, `.cursor/skills/` or `.agents/skills/`, tell the user and suggest moving it to the global location.
