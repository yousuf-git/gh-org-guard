# Testing and evidence

gh-org-guard was tested in two ways: live on a real GitHub organization, and offline against synthetic clean and attack repositories. This page records what was run, what happened, and what was **not** verified.

- [Summary](#summary)
- [Live org tests](#live-org-tests)
- [Offline regression suite](#offline-regression-suite)
- [Agent skill tests](#agent-skill-tests)
- [Not verified](#not-verified)
- [Changes since the live tests](#changes-since-the-live-tests)

## Summary

| Area | Result |
|---|---|
| Org rulesets with the `workflows` rule on the **Team** plan | Works |
| Ruleset A: direct push, force push, delete, unapproved merge | All rejected, org owners included |
| Org-owner PR-only bypass | Owner merged own green PR; still couldn't push directly or merge a failed scan |
| 10 attack PRs (fonts, `.vscode`, configs, miner, EICAR, token, install script, vulnerable dep, AI trailer) | All 10 blocked by the intended check |
| Yarn v1 and pnpm audit commands | Ran correctly |
| Failure issue | Tagged owners and pusher; repeat failures commented instead of duplicating |
| Cost | 1 billed minute per clean scan (was 6 with six jobs) |
| Synthetic clean MERN monorepo | 0 blocking findings |
| Synthetic attack repo | 50 blocking findings; every malicious file blocked |
| YARA | 15 rules; 24/24 malicious samples matched, 0 false positives |

## Live org tests

**Environment:**
- a GitHub organization on the **Team** plan, 2026-10-14 and 2026-10-15;
- two private sandbox repos: a central workflow repo, and a target repo with a small Express + Vite/Tailwind app;
- org-wide settings left unchanged. Both rulesets were scoped to the target repo only, and `SECURITY_OWNER` was set to two org owners.

Every change was logged with its undo command and removed afterwards.

### Rulesets

| # | Test | Expected | Result |
|---|------|----------|--------|
| T1 | `git push origin main` with a new commit | rejected | `GH013 … Changes must be made through a pull request` |
| T2 | Force push of rewritten history to `main` | rejected | `Cannot force-push to this branch` |
| T3 | `git push origin :main` | rejected | Refused (default branch) |
| T4 | Create a protected `master` by push | rejected | `Required workflow 'security-scan' is not satisfied`: protected refs can't be created outside PRs |
| T7 | Merge state of an unapproved PR | blocked | `BLOCKED`, `REVIEW_REQUIRED` |
| T14 | Org owner merges own green PR, 0 approvals, owner was last pusher | allowed via PR-only bypass | Merged |
| T15 | Org owner `git push origin main` and `--force` after the bypass was added | rejected | Both rejected; `main` unchanged |
| T28 | Org owner `gh pr merge --squash --admin` on a PR whose scan failed | refused | `Repository rule violations found — Required workflows 'security-scan' failed` |

### Attack PRs

Each case was a branch cut from a clean `main` and opened as its own PR against the target repo.

| # | Case | Expected | Failed checks | Issue opened |
|---|------|----------|---------------|--------------|
| T16 | JavaScript saved as `client/public/fonts/Inter.woff2` | `repo-policy` | `yara`, `repo-policy` | yes |
| T17 | `.vscode/tasks.json` with `runOn: folderOpen` | `repo-policy` | `repo-policy` | yes |
| T18 | `tailwind.config.js` + 300 spaces + `child_process` | `repo-policy` | `repo-policy` | yes |
| T19 | `tsconfig.json` with code after the closing brace | `repo-policy` | `repo-policy` | yes |
| T20 | `stratum+tcp://` miner pool URL | `yara` | `yara` | yes |
| T21 | EICAR test string | `clamav` | `clamav` | yes |
| T22 | Random `ghp_` token in source | `gitleaks` | `gitleaks` | yes |
| T23 | `deasync@0.1.30` (has an install script) | `dependency-audit` | `dependency-audit`: `runs an install script and is not on the reviewed allowlist` | yes |
| T24 | `lodash@4.17.20` in server `dependencies` | `dependency-audit` | `dependency-audit`: high advisory in a production dependency | yes |
| T25 | Commit with `Co-Authored-By: Claude <noreply@anthropic.com>` | `ai-coauthor` | `ai-coauthor` | yes |
| T26 | Yarn v1 sample app (Express) | audit runs | `yarn audit` critical and production passes ran: `0 vulnerabilities found`. The PR still failed, correctly: transitive `qs@6.16.1` was 10 h old (`was published 10h ago; wait 72h`). | yes |
| T27 | pnpm sample app (Express) | audit runs | `pnpm audit` critical and production passes ran: `No known vulnerabilities found`. Same `qs` cooldown block. | yes |

All twelve scan jobs took 42–55 s, each 1 billed minute.

### Failure issue

| # | Test | Result |
|---|------|--------|
| T6 | First failure on a PR | Issue created with label `security-scan`. `Security owners:` listed both owners; `Pushed by:` named the pusher, marked `(also a security owner)` |
| T6 | Second failure on the same PR | Comment added to the existing issue; no duplicate |
| T16 | Issue body | Listed `Failed checks: yara, repo-policy`, the commit SHA and the run link |

### Cost and workflow behaviour

| # | Test | Result |
|---|------|--------|
| T5 | Clean PR with Tailwind CSS 3 | `npm audit` failed: Tailwind ≤ 3.4.19 pulls in 6 high advisories (braces, micromatch, chokidar). This led to the audit policy: high advisories only block **production** deps. |
| T8 | Same PR after the policy change | All six checks green; `report` skipped; dev-only high advisories shown as a warning |
| T9 | First single-job version | Failed: non-root `freshclam --config-file` gave `Can't open/parse the config file`. This confirmed fail-closed behaviour, and the failure issue said "a setup step". Fixed. |
| T10 | Single-job version after the fix | Green in 56 s = **1 billed minute**, against 6 billed minutes for the previous six-job run. ClamAV cache saved (113 MB, 3.6 million signatures). |
| T11 | Second push to the same PR | Cache restored in 2 s; scan 41 s. Uncached `freshclam` was only about 3 s on that run, so the cache mainly guards against slow mirrors and rate limits; the job merge gives most of the saving. |
| T12 | Skip draft PRs, scan on "ready for review" | **Failed**: required workflows aren't triggered by `ready_for_review`, so the ready PR had only a skipped scan. The draft skip was removed. |
| T13 | Draft PR without the skip | Scanned on the draft (36 s); marking it ready added no extra run |

### How to reproduce

Create two private sandbox repos and scope both rulesets' `repository_name.include` to the target repo only. Point `SECURITY_OWNER` at that repo with `--visibility selected`. Then push one branch per case above and open a PR for each. Remove everything afterwards: the two rulesets, the variable and the repos.

## Offline regression suite

`tests/run.sh` runs in the `self-test` workflow on every push, and locally with `bash tests/run.sh`.

| Group | Cases |
|---|---|
| `repo-policy` clean repo (`tests/mkfixtures.py`, `tests/extra_fixtures.py`) | A realistic MERN monorepo produces **0** errors. It contains: WOFF/WOFF2/TTF/OTF fonts; PNG/JPEG/GIF/WebP; Vite, Tailwind and PostCSS configs; a JSONC `tsconfig`; workspace `*` deps; Yarn workspaces; husky; Docker; a SHA-pinned workflow. False-positive regressions are included too: a JPEG named `.png`, a `.docx`, wide markdown tables, deep JSX indentation, long SVG paths, `typescript.tsdk`, `.DS_Store`. |
| `repo-policy` attack repo | **50** blocking findings, and every malicious file is blocked. Cases: <ul><li>fonts: JS as a font, fonts with appended payloads, ELF as a font</li><li>images: PE as JPEG, PNG polyglot, SVG `onload`</li><li>editor: `folderOpen` tasks (plain and `\u`-escaped), terminal env injection</li><li>configs: off-screen, blank-line and `global.i` payloads; `tsconfig` with appended code</li><li>package files: `postinstall`, alias/GitHub/wildcard deps, hostile `.npmrc` and `.yarnrc.yml`, `.env`</li><li>dev and agent config: host-command devcontainer, Claude hooks, malicious `AGENTS.md`</li><li>git and infra: git filter, foreign submodule, privileged compose file, `pull_request_target` workflow</li><li>file tricks: double extension, `.exe`, out-of-repo symlink, Trojan Source</li><li>payloads: base64 ELF, C2 host, IP exfiltration, history-tampering `.bat`</li></ul> |
| Submodules | A submodule in the same org passes (case-insensitive); fails closed when the org is unknown |
| `deps_policy.py` lockfile rules (`tests/deps_fixtures.py`) | A clean npm lockfile passes. These fail: non-allowlisted install script, non-registry `resolved`, missing integrity, `package.json`/lockfile drift, two lockfiles in one directory, no lockfile |
| `ai-coauthor` | 3 of 3 AI-credited commits flagged (Claude trailer, "Generated with Claude Code", Cursor agent author). A human co-author named *Claude* and Dependabot pass. |
| Failure issue (`tests/report_test.mjs`) | Runs the real `github-script` body against a mock API. Checks owner and pusher tagging, PR-author line, bot naming, the missing-`SECURITY_OWNER` warning and repeat-failure comments. |
| YARA (`tests/yara-samples/`) | Rules compile. All 24 malicious samples match. The 4 benign samples and the clean repo don't match. The attack repo's asset loader matches `Guard_JS_Executes_Asset_File`. |
| Build | The workflow and the skill's script copies match their sources |

The registry gates (version age, package age, downloads, unknown package) were checked during development against a stubbed registry: a 5-hour-old version, a 3-day-old package, 12 downloads a week, and an unpublished scoped name. They were then verified live by T26/T27. `npm audit` was checked against lodash 4.17.20/4.17.21 (fail) and 4.18.1 (pass). Gitleaks 8.30.1 flagged a planted token.

## Agent skill tests

Run locally against branches of the sandbox target repo:

| Case | Result |
|---|---|
| Fake-font branch | `repo-policy` failed: `not a real .woff2 font` |
| AI-trailer branch | `ai-coauthor` failed |
| Install-script branch | `dependency-audit` failed: `deasync … install script` |
| Clean `main` | All checks passed |
| AI-trailer removal recipe on a copy of the AI-trailer branch | Trailer removed, user kept as author, preflight passed afterwards. Nothing was pushed. |

## Not verified

- `yarn npm audit` (Yarn Berry) in CI.
- The preflight's `yara`, `clamav` and `gitleaks` steps on a developer machine. Those tools weren't installed where the skill was tested, and the script skips them when they're missing. The same rules ran in CI.
- Whether @mentioned owners received the email or web notification. The issue text and mentions were verified; delivery wasn't.
- `npx skills add` against this public repo. The layout (`skills/<name>/SKILL.md`) follows the CLI's documented discovery rules.

## Changes since the live tests

For the public release, the rules and checkers were made org-neutral. The changes were:

- YARA rule names renamed to the `Guard_` prefix; the rule logic is unchanged;
- the submodule check reads the org from `GITHUB_REPOSITORY_OWNER` instead of a hardcoded name;
- the registry User-Agent renamed.

The offline suite covers all of these, but the renamed workflow hasn't been re-run on a live org.
