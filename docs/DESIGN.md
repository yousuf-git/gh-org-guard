# Design decisions

Why gh-org-guard is built the way it is, including the alternatives that were tried or rejected.

## Choices and reasons

| Obvious approach | What gh-org-guard does | Why |
|---|---|---|
| Ruleset rule **Restrict updates** to block direct pushes | Not used | It lets *only bypass actors* update the branch, merges included. With an empty bypass list nobody could merge. The pull-request rule already rejects direct pushes. |
| Commit-metadata rule to reject AI co-authors | CI check `ai-coauthor` | Metadata restrictions are GitHub Enterprise only. |
| Block every `*[bot]` committer | Named AI tools only | A `[bot]` wildcard also blocks Dependabot and `github-actions[bot]`. |
| CodeQL, secret push protection, `dependency-review-action` | Gitleaks, `repo-policy`, `dependency-audit` | On private repos those need the paid Code Security / Secret Protection add-ons. They are listed as optional upgrades in [SETUP.md](SETUP.md#10-operating-the-policy). |
| A `security-scan.yml` committed in each repo | One central workflow required by an org ruleset | A PR's own workflow file runs the PR's version, so a PR could disable its own scan. A ruleset-required workflow runs from a repo the PR can't touch. |
| `gitleaks/gitleaks-action` | Gitleaks CLI binary, checksum-verified | The action requires a `GITLEAKS_LICENSE` key for organization repos. The CLI is MIT-licensed and needs none. |
| Run on `push` and `pull_request` | `pull_request` only | Protected branches only change through PRs. |
| Six parallel jobs | One `scan` job with six steps | GitHub bills each job rounded up to a whole minute. Measured: 1 billed minute instead of 6 for a clean run (41–56 s). |
| Skip draft PRs to save minutes | Drafts are scanned | Tested and rejected. GitHub didn't start the required workflow when the PR was marked ready for review, so the ready PR had only a *skipped* scan on its head commit. |
| `paths:` filter to skip docs-only PRs | No filter | A required workflow skipped by a path filter stays "Pending" forever. |
| Store rules and checkers as separate files | Embedded as heredocs in one workflow file | The required workflow then needs no access to any other repo, and one file is the whole scanner. `build.py` keeps the sources editable. |
| Secret team as the owner bypass actor | Org-admin role, pull-request mode | GitHub rejected a secret team with a 422 (`Actor … team must be part of the ruleset source or owner organization`). |

## How the workflow is put together

- **Every check runs.** Each check step has `if: ${{ !cancelled() }}`, so one run reports every finding. The `Result` step reads each step's `outcome`, writes the failed list as a job output and fails the job.
- **Least privilege.** The workflow has `contents: read`, and the checkout doesn't persist credentials. Only the separate `report` job gets `issues: write`, and it only runs when `scan` fails.
- **Untrusted-config ordering.** `dependency-audit` runs last because package-manager audits can execute repo-controlled config (for example Yarn Berry's `yarnPath`). No other check runs after it. The Python checkers run with `python3 -I`, so a planted module in the repo can't be imported.
- **ClamAV signature cache.** Signatures (about 113 MB) are restored with `actions/cache`, keyed by UTC day, and copied into `/var/lib/clamav`. `freshclam` then downloads only the daily diffs. Running `freshclam` as non-root with its own config file failed on the runner (`Can't open/parse the config file`), so the workflow copies files around root's default setup. Caches made by `pull_request` runs are scoped to that PR, so each PR's first run downloads the full set.
- **Fail closed.** If a setup step fails (apt, signature download, Gitleaks checksum), the check steps fail and the issue says "a setup step". If the npm registry can't be reached, new-package vetting fails instead of passing.
- **Exceptions live in one place.** Allowlists are in the central workflow only. A PR in a scanned repo can't add an exception for itself.

## Known limits

- Scans run after the push, so a leaked secret is already on GitHub. Always rotate.
- Pattern rules can be evaded by novel obfuscation. That's why they're layered with structural checks: file headers, config purity, lockfile rules.
- Org owners can edit or delete rulesets. Review the org audit log.
- Typosquat detection relies on age and download signals. Reviewers still need to read new dependency names.
- A failing scan blocks merges org-wide if Actions minutes run out, so set a budget alert rather than a hard limit.
- The agent skill guides cooperative agents. It isn't a control: enforcement is the rulesets and the required workflow.
