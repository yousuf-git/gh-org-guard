# Setup guide

This guide applies gh-org-guard to a GitHub organization. Replace `your-org` with your org's login. Every step has a CLI form (`gh`) and, where it matters, the UI path.

- [1. Prerequisites](#1-prerequisites)
- [2. Central workflow repo](#2-central-workflow-repo)
- [3. CODEOWNERS in every repo](#3-codeowners-in-every-repo)
- [4. Ruleset A: protect main and master](#4-ruleset-a-protect-main-and-master)
- [5. Ruleset B: require the security scan](#5-ruleset-b-require-the-security-scan)
- [6. Clean existing repos before enforcing](#6-clean-existing-repos-before-enforcing)
- [7. Verify on a pilot repo](#7-verify-on-a-pilot-repo)
- [8. Rollout plan](#8-rollout-plan)
- [9. Fallback: per-repo workflow + required status check](#9-fallback-per-repo-workflow--required-status-check)
- [10. Operating the policy](#10-operating-the-policy)

## 1. Prerequisites

Do these once, as an org owner.

1. **Plan.** GitHub Team or higher. Org rulesets became available on Team in June 2025. The `workflows` rule (*Require workflows to pass before merging*) was accepted on a Team org during testing.
2. **`gh` CLI** authenticated with `admin:org`, `repo` and `workflow` scopes: `gh auth refresh -s admin:org,repo,workflow`.
3. **Security owners.** Pick the GitHub handle(s) the failure issue tags.
4. **Code-owners team.** Create a team for people allowed to approve merges, for example `@your-org/security-leads`.
5. **Org Actions settings** (*Org → Settings → Actions → General*):
   - Policy: allow only actions created by GitHub plus actions from your org. The workflow uses only `actions/checkout`, `actions/cache` and `actions/github-script`, pinned to commit SHAs.
   - Workflow permissions: **Read repository contents and packages permissions**.
6. **Org variable** `SECURITY_OWNER` holds one or more handles, comma- or space-separated (a leading `@` is optional). Repository access: all repositories.

   ```bash
   gh variable set SECURITY_OWNER --org your-org --visibility all --body "alice, bob"
   ```

   UI: *Org → Settings → Secrets and variables → Actions → Variables*.
7. **Dependabot alerts.** Enable them for all repos (*Org → Settings → Code security*). They are free on every plan.

## 2. Central workflow repo

The scan must live in a repo that ordinary PRs can't change. A workflow committed inside each repo would run the PR's own version, so a malicious PR could disable its own scan.

```bash
git clone https://github.com/yousuf-git/gh-org-guard && cd gh-org-guard
gh repo create your-org/security-workflows --private --description "Org-required security scan"
git clone https://github.com/your-org/security-workflows ../security-workflows
mkdir -p ../security-workflows/.github/workflows
cp workflow/security-scan.yml ../security-workflows/.github/workflows/
printf '* @your-org/security-leads\n' > ../security-workflows/.github/CODEOWNERS
git -C ../security-workflows add . && git -C ../security-workflows commit -m "Add org security scan"
git -C ../security-workflows push -u origin HEAD:main
```

Allow repos in the org to use the workflow:

```bash
gh api --method PUT repos/your-org/security-workflows/actions/permissions/access -f access_level=organization
```

UI: *security-workflows → Settings → Actions → General → Access → Accessible from repositories in the organization*.

> [!NOTE]
> `security-scan.yml` contains detection signatures as text. Keep it, and any copy of this repo, out of the repos Ruleset B scans, or the scan flags itself. Ruleset B's JSON already excludes `security-workflows`.

## 3. CODEOWNERS in every repo

Add `.github/CODEOWNERS` to each repo's default branch. [`CODEOWNERS.example`](../CODEOWNERS.example) gives the auto-execution surfaces an explicit owner, so changes to them always need a lead's review:

```text
*                         @your-org/security-leads

/.github/                 @your-org/security-leads
/.vscode/                 @your-org/security-leads
/.devcontainer/           @your-org/security-leads
/.claude/                 @your-org/security-leads
/.cursor/                 @your-org/security-leads
/.husky/                  @your-org/security-leads
**/package.json           @your-org/security-leads
**/package-lock.json      @your-org/security-leads
**/yarn.lock              @your-org/security-leads
**/pnpm-lock.yaml         @your-org/security-leads
**/.npmrc                 @your-org/security-leads
**/.yarnrc*               @your-org/security-leads
**/*.config.*             @your-org/security-leads
**/tsconfig*.json         @your-org/security-leads
**/Dockerfile*            @your-org/security-leads
**/docker-compose*        @your-org/security-leads
**/AGENTS.md              @your-org/security-leads
**/CLAUDE.md              @your-org/security-leads
```

If a repo has no `CODEOWNERS`, Ruleset A's *Require review from Code Owners* has nothing to enforce; the one-approval rule still applies.

## 4. Ruleset A: protect main and master

[`rulesets/protect-main-master.json`](../rulesets/protect-main-master.json):

```json
{
  "name": "protect-main-master",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [
    { "actor_type": "OrganizationAdmin", "actor_id": 1, "bypass_mode": "pull_request" }
  ],
  "conditions": {
    "ref_name": {
      "include": ["~DEFAULT_BRANCH", "refs/heads/main", "refs/heads/master"],
      "exclude": []
    },
    "repository_name": { "include": ["~ALL"], "exclude": [], "protected": false }
  },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": true,
        "require_last_push_approval": true,
        "required_review_thread_resolution": true,
        "allowed_merge_methods": ["squash", "merge"]
      }
    }
  ]
}
```

```bash
gh api --method POST orgs/your-org/rulesets --input rulesets/protect-main-master.json
```

UI equivalent: *Org → Settings → Rules → Rulesets → New branch ruleset*.

- Target **All repositories**, and the branches *Default*, `main` and `master`.
- Enable **Restrict deletions** and **Block force pushes**.
- Enable **Require a pull request before merging** with 1 approval. Turn on dismiss stale approvals, Code Owners review, approval of the most recent push, and conversation resolution.
- Allowed merge methods: Squash and Merge.
- **Bypass list:** the **Organization admin** role, set to **For pull requests only**. Never choose *Always*: that would let owners push directly and force-push.
- **Leave "Restrict updates" off.** It lets *only* bypass actors update the branch, merges included. The pull-request rule already rejects direct pushes.

**The bypass entry lets org owners merge their own PRs without a second person's approval.** They still can't push directly, force-push or delete. If you want owners reviewed like everyone else, set `"bypass_actors": []`. The bypass actor must be the org-admin role or a *visible* team. GitHub rejects a *secret* team with `Actor … team must be part of the ruleset source or owner organization`.

## 5. Ruleset B: require the security scan

[`rulesets/require-security-scan.json`](../rulesets/require-security-scan.json) has a `REPO_ID` placeholder for the `security-workflows` repo id:

```bash
REPO_ID=$(gh api repos/your-org/security-workflows --jq .id)
sed "s/REPO_ID/$REPO_ID/" rulesets/require-security-scan.json > /tmp/ruleset-b.json
```

**Pilot first.** Edit `/tmp/ruleset-b.json` so `repository_name.include` is `["<pilot-repo>"]` instead of `["~ALL"]`, then:

```bash
gh api --method POST orgs/your-org/rulesets --input /tmp/ruleset-b.json
```

Once the pilot passes [step 7](#7-verify-on-a-pilot-repo), switch `include` back to `["~ALL"]`. Update the ruleset in the UI, or with `gh api --method PUT orgs/your-org/rulesets/<id> --input /tmp/ruleset-b.json`.

Ruleset B has **no bypass actors**, owners included. To pin the scanner to an exact version, replace `"ref": "refs/heads/main"` with `"sha": "<commit>"`.

UI equivalent: *New branch ruleset → Require workflows to pass before merging → Add workflow → security-workflows / `.github/workflows/security-scan.yml` / `main`*. If the UI doesn't offer that rule on your plan, use the [fallback](#9-fallback-per-repo-workflow--required-status-check).

The "evaluate" (dry-run) enforcement mode is Enterprise-only, which is why the rollout uses a pilot repo instead.

## 6. Clean existing repos before enforcing

Existing repos fail the scan until they comply. Find out what each repo needs before Ruleset B covers it: run the [agent skill's preflight](AGENT-SKILL.md#preflight) on a clone, or commit `security-scan.yml` to a throwaway branch's `.github/workflows/`, open a draft PR so it runs, and close it afterwards. Typical one-time cleanup:

- Pin third-party actions to commit SHAs.
- Delete committed `.env` files and **rotate** the secrets in them.
- Remove `.bat`, `.zip`, `.idea/` and `.DS_Store`.
- Fix `latest` and `*` dependency versions.
- Rename mislabelled images (a JPEG saved as `.png` is a warning; a non-image saved as `.png` is an error).

> [!CAUTION]
> Treat any `hidden-code`, `config`, `font`, `disguised-file` or YARA hit in an existing repo as a **possible infection**, not a lint error. Escalate to the security owner before touching it, and assume the machine that committed it is compromised.

## 7. Verify on a pilot repo

**Ruleset A**
- [ ] `git push origin main` is rejected (`GH013 … Changes must be made through a pull request`).
- [ ] `git push --force origin main` is rejected, for org owners too.
- [ ] Deleting `main` is rejected.
- [ ] A PR with 0 approvals, or approved only by its author, can't merge.
- [ ] A new push after approval needs a fresh approval from someone else.
- [ ] An unresolved review thread blocks merge.
- [ ] **An approved PR with green checks *can* merge.** This proves "Restrict updates" is off.
- [ ] If you kept the owner bypass, an org owner can merge their own green PR without approval (`gh pr merge --admin`).
- [ ] An org owner **can't** merge a PR whose `security-scan` failed.

**Ruleset B:** one throwaway PR per row, closed without merging. These are the cases from [TESTING.md](TESTING.md#live-org-tests).
- [ ] `public/fonts/x.woff2` containing JavaScript fails `repo-policy` (`font`), and an issue is opened tagging the owner and the pusher.
- [ ] `.vscode/tasks.json` with `"runOptions": {"runOn": "folderOpen"}` fails `repo-policy`.
- [ ] `tailwind.config.js` with `require('child_process')` after 300 spaces fails `repo-policy`.
- [ ] `tsconfig.json` with code after the closing brace fails `repo-policy`.
- [ ] A file containing `stratum+tcp://pool.example:3333` fails `yara`.
- [ ] The EICAR test string fails `clamav`.
- [ ] `ghp_` followed by 36 random alphanumerics fails `gitleaks`.
- [ ] A package with a non-allowlisted install script (for example `deasync`) fails `dependency-audit`.
- [ ] `"lodash": "4.17.20"` in `dependencies`, with its lockfile, fails `dependency-audit`.
- [ ] A commit with `Co-Authored-By: Claude <noreply@anthropic.com>` fails `ai-coauthor`.
- [ ] A second failing push to the same PR comments on the existing issue instead of opening a new one.
- [ ] A clean PR passes `scan`, `report` is skipped, and the PR can merge after approval.
- [ ] Editing `.github/workflows/*` in the pilot repo's PR doesn't change what runs.

## 8. Rollout plan

1. [Prerequisites](#1-prerequisites).
2. Create `security-workflows` ([step 2](#2-central-workflow-repo)) and add `CODEOWNERS` everywhere ([step 3](#3-codeowners-in-every-repo)).
3. Create Ruleset A for all repos ([step 4](#4-ruleset-a-protect-main-and-master)).
4. Clean each existing repo ([step 6](#6-clean-existing-repos-before-enforcing)). Escalate anything that looks like an infection.
5. Create Ruleset B for one pilot repo, run [step 7](#7-verify-on-a-pilot-repo), then widen it to `~ALL` ([step 5](#5-ruleset-b-require-the-security-scan)).
6. Brief the team on [CHECKS.md](CHECKS.md) (how to read a failure) and [DEVELOPERS.md](DEVELOPERS.md) (workstation rules).
7. Every developer installs the agent skill globally: `npx skills add yousuf-git/gh-org-guard -g -a claude-code -a cursor -a codex` ([AGENT-SKILL.md](AGENT-SKILL.md)).

## 9. Fallback: per-repo workflow + required status check

Use this only if your plan doesn't offer *Require workflows to pass before merging*.

1. Commit `workflow/security-scan.yml` to each repo as `.github/workflows/security-scan.yml`.
2. Replace Ruleset B's `workflows` rule with [`rulesets/fallback-required-status-checks.json`](../rulesets/fallback-required-status-checks.json):

   ```json
   {
     "type": "required_status_checks",
     "parameters": {
       "strict_required_status_checks_policy": true,
       "do_not_enforce_on_create": false,
       "required_status_checks": [{ "context": "scan", "integration_id": 15368 }]
     }
   }
   ```

   `15368` is the GitHub Actions app. Pinning the source stops anyone posting a fake green `scan` status from another integration.
3. `CODEOWNERS` on `/.github/` becomes the only guard against a PR weakening its own scan. Reviewers must reject any such change.
4. Enable the rule on a repo only after its workflow is merged. Otherwise PRs wait forever for a check that never reports.

## 10. Operating the policy

- **Changing rules.** Edit the sources in a fork or copy of this repo, run `python3 build.py` and `bash tests/run.sh`, then open a PR to `security-workflows` with the rebuilt file. It applies to every repo once merged.
- **Owner merges.** Every bypass merge is recorded in the org audit log and in *Rules → Insights*; review it periodically. Keep the owner list short, because every owner can skip review.
- **Emergency merge despite a failing scan.** There is no standing bypass. An org owner temporarily adds themselves to Ruleset B's bypass list (*for pull requests only*), merges, and removes it straight away. This is audit-logged; post the reason in the security issue.
- **Actions minutes.**
  - A clean scan of a small repo bills 1 minute. Large repos and many lockfiles take longer, because `npm audit` and the registry checks run per lockfile.
  - Every push to an open PR, draft or not, runs the scan. Pushes to branches without a PR cost nothing.
  - Set an Actions budget with an alert under *Org → Settings → Billing*. Don't set a hard $0 limit: when minutes run out, the required workflow can't run and every merge in the org is blocked.
- **Version bumps.** `GITLEAKS_VERSION`, the action SHAs (`checkout`, `cache`, `github-script`) and the yarn/pnpm versions used for audits are pinned. Bump them deliberately, choosing releases at least two weeks old. ClamAV signatures and advisory data update on every run.
- **Paid add-ons that strengthen this.**

  | Add-on | Adds |
  |--------|------|
  | GitHub Secret Protection | Push protection: secrets rejected at `git push`, before they reach GitHub |
  | GitHub Code Security | CodeQL and `dependency-review-action` on private repos, and the *Require code scanning results* rule |
  | GitHub Enterprise | Commit-metadata rules that reject AI trailers at push time, "evaluate" dry-run mode, and push rulesets that block file paths such as `.vscode/tasks.json` |
