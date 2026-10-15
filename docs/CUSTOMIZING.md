# Customizing for your org

Fork or copy this repo, edit the **sources**, rebuild, and copy the built workflow into your `security-workflows` repo:

```bash
python3 build.py      # rebuilds workflow/security-scan.yml and syncs skills/create-pr-guarded/scripts
bash tests/run.sh     # regression suite
cp workflow/security-scan.yml ../security-workflows/.github/workflows/security-scan.yml
```

Never edit `workflow/security-scan.yml` or the skill's `scripts/` copies by hand; `build.py` overwrites them.

## Who gets tagged

`SECURITY_OWNER` (org Actions variable) holds handles separated by commas or spaces. Change it any time; the next failure uses the new value. The pusher and the PR author are tagged automatically.

## Thresholds

In `checkers/deps_policy.py`:

| Constant | Default | Meaning |
|---|---|---|
| `MIN_VERSION_AGE_HOURS` | `72` | Cooldown for any new or changed package version, transitive included |
| `MIN_PACKAGE_AGE_DAYS` | `30` | Packages created more recently need owner review |
| `MIN_WEEKLY_DOWNLOADS` | `1000` | Direct dependencies below this need owner review |
| `MAX_LOOKUPS` | `400` | Registry lookups per run; larger upgrades vet the first 400 and warn |

If you change the cooldown, update the matching developer settings in [DEVELOPERS.md](DEVELOPERS.md) and the skill's rule 7.

The advisory policy is in the `dependency-audit` step of `workflow/security-scan.template.yml`: critical blocks everywhere, high blocks in production deps, and high in dev-only deps is a warning. To block high everywhere, make the `all_high` command fail the step instead of printing a warning.

## Allowlists

| List | File | Format |
|---|---|---|
| `ALLOW` | `checkers/repo_policy.py` | `"path"`, `"path:check"` or `"*:check:detail"`; turns the error into a warning |
| `INSTALL_SCRIPT_ALLOW` | `checkers/deps_policy.py` | package name whose install/build script you reviewed |
| `ALLOW` | `checkers/deps_policy.py` | `"name"` or `"name@version"`, exempt from the age and download gates |

Keep entries narrow (`path:check` over `path`) and record why in the PR.

## Removing a check

For example, if your org allows AI co-authors:

1. Delete the `ai-coauthor` step from `workflow/security-scan.template.yml`.
2. Delete the `ai-coauthor=${{ steps.ai_coauthor.outcome }}` line from the `Result` step's `OUTCOMES`.
3. Remove the `ai_coauthor` check from `skills/create-pr-guarded/scripts/preflight.sh` and rule 1 from `SKILL.md`.
4. Remove the ai-coauthor cases from `tests/run.sh`, then rebuild and test.

The same pattern works for any check. Keep `dependency-audit` last.

## Branches and repos covered

- Both rulesets target `~DEFAULT_BRANCH`, `main` and `master`. Add patterns such as `refs/heads/release/*` to `ref_name.include`.
- `repository_name.include: ["~ALL"]` covers every repo, including ones created later. List repos in `exclude` to skip them; `security-workflows` must stay excluded from Ruleset B.
- To require two approvals, set `required_approving_review_count` to `2`.
- To stop org owners merging their own PRs without review, set `"bypass_actors": []` in Ruleset A.

## Other stacks

`clamav`, `yara`, `gitleaks`, `repo-policy` and `ai-coauthor` work on any repo. Most YARA rules target JavaScript and shell; add rules for your languages in `rules/guard.yar`, with samples in `tests/yara-samples/`.

`dependency-audit` only understands npm, Yarn and pnpm. Repos without a `package.json` or lockfile pass it. For other ecosystems, add a step before `Result` that runs that ecosystem's audit, for example `pip-audit` or `govulncheck`, and add its outcome to `OUTCOMES`.

## Runner and versions

- The scan runs on `ubuntu-24.04` with the `apt` versions of ClamAV and YARA.
- Gitleaks is downloaded at `GITLEAKS_VERSION` and its checksum verified.
- Audits use `yarn@1.22.22`, `pnpm@12.8.2` and the runner's npm.
- `actions/checkout`, `actions/cache` and `actions/github-script` are pinned to commit SHAs.

Bump any of these on purpose, choosing releases at least two weeks old, then rebuild and test.
