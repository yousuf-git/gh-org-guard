# Developer workstation rules

The attacks behind this project started on developer machines: a cloned "interview task", an opened folder, a `npm run dev`. CI catches the result. These rules reduce the chance of the first infection. Share them with the team at rollout.

1. **VS Code:** keep Workspace Trust on, and open unfamiliar repos in **Restricted Mode**. Set `"task.allowAutomaticTasks": "off"` in your *user* settings.
2. **Untrusted code** (take-home tests, "recruiter" repos, zip files): open it in a disposable VM or Codespace, never on your work machine. Install with `npm install --ignore-scripts`.
3. **Never run** `.bat`, `.cmd`, `.ps1` or `.sh` files that came with a repo without reading them first.
4. **Before `npm run dev` on a branch you didn't write,** skim `git diff` on configs (`*.config.*`, `tsconfig*.json`, `.vscode/`). Config files execute when tools load them.
5. **If any scan reports `hidden-code`, `config`, `font`, `disguised-file`, `Guard_Config_Injector_Family` or `Guard_Git_History_Tampering` on your branch,** stop, don't run the project, and tell the security owner. Assume the machine is compromised. From a clean device, rotate GitHub, npm, SSH and cloud credentials, browser-saved passwords and wallet keys.
6. **No AI co-author trailers in commits.** Turn attribution off in your AI tools' settings.
7. **Put each dependency in the right section.** Anything application code imports, front end or back end, goes in `dependencies`, even when a bundler like Vite ships it. Only build, test, lint and type tools (`vite`, `tailwindcss`, `eslint`, `jest`, `@types/*`, …) go in `devDependencies`. The audit gate trusts this split.
8. **Open the PR when the work is ready for review.** Every push to an open PR, drafts included, runs the scan and uses Actions minutes. Pushes to a branch without a PR cost nothing. Push in batches.
9. **Match the CI cooldown locally,** so lockfiles never pick a version younger than 72 hours:

   | Package manager | Setting | Where |
   |---|---|---|
   | npm 11 (present in 11.12; older npm lacks it) | `min-release-age=3` (days) | `~/.npmrc` or the project `.npmrc` |
   | pnpm 10.16+ | `minimumReleaseAge: 4320` (minutes). pnpm 11's default of 1440 (one day) is shorter than CI's 72 h. | `pnpm-workspace.yaml` |
   | Yarn Berry | `npmMinimalAgeGate: "3d"` | `.yarnrc.yml` |
   | Yarn v1 | no setting; wait, or pin the previous version with `resolutions` | — |

   A committed `.npmrc` or `.yarnrc.yml` is reviewed by `repo-policy`. These keys are allowed, but put the setting in your user config if you prefer.
10. **Install the agent skill globally** if you use Claude Code, Cursor or Codex: `npx skills add yousuf-git/gh-org-guard -g` ([AGENT-SKILL.md](AGENT-SKILL.md)).
