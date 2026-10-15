# What each check covers

The `security-scan` workflow runs one job, `scan`, with six check steps. Each step runs even when an earlier one fails. The `Result` step lists the failed checks, and the `report` job opens or updates an issue.

- [The incidents behind the checks](#the-incidents-behind-the-checks)
- [repo-policy](#repo-policy): files, auto-execution surfaces, configs, manifests
- [yara](#yara): malicious code patterns
- [dependency-audit](#dependency-audit): supply chain
- [clamav, gitleaks, ai-coauthor](#clamav-gitleaks-ai-coauthor)
- [False positives and exceptions](#false-positives-and-exceptions)
- [The failure issue](#the-failure-issue)
- [Reading a failure](#reading-a-failure)

## The incidents behind the checks

These are techniques seen in real attacks on developer teams (the "fake job interview" / BeaverTail family, and config-file injectors):

| Technique | What stops it |
|-----------|---------------|
| **Font files that aren't fonts:** `.woff2`/`.ttf` files holding JavaScript that other code later loads | `repo-policy` checks every font's real header (`wOFF`, `wOF2`, `OTTO`, `\x00\x01\x00\x00`, `true`, `ttcf`, EOT) and its declared length or table layout, so a payload appended to a real font is caught too. It also blocks code markers inside binary assets. YARA `Guard_JS_Executes_Asset_File` blocks code that reads an asset and runs it. |
| **`.vscode` auto-run:** a task with `runOn: folderOpen` that executes as soon as the folder is opened | `repo-policy` blocks `folderOpen` tasks (including `\u`-escaped keys), settings that change shells, env, interpreters, tool paths or workspace trust, unexpected files in `.vscode/`, and the same keys in `.code-workspace` files |
| **Code appended to `tailwind.config.*`, `postcss.config.*` or `tsconfig.json`**, pushed off-screen by hundreds of spaces | `repo-policy` blocks content after a long whitespace run or 30+ blank lines, long lines in configs, configs that run code (`eval`, `child_process`, base64 `Buffer.from`, `global.x =`, unicode-escaped module names, network calls), and JSON configs that aren't pure JSON. YARA `Guard_Config_Injector_Family` matches the injector's `global.i` / `global.r=require` markers. |
| **Silent commit rewriting:** a script that fakes the clock, runs `git add .`, `commit --amend --no-verify` and force-pushes with credential prompts disabled, hiding the payload inside a legitimate commit | Ruleset A rejects force pushes to protected branches, and every change to `main` goes through a PR where all checks see the full diff. YARA `Guard_Git_History_Tampering` and the `.bat` ban block the script itself. |

Local git hooks (skipped by `--no-verify`) and editor settings aren't security controls. Everything here is enforced server-side.

## repo-policy

`checkers/repo_policy.py` walks every tracked file (`git ls-files`). Errors block; warnings appear as annotations for the reviewer.

| Area | Blocks (error) | Flags for review (warning) |
|------|----------------|----------------------------|
| **Fonts** | Header isn't a real font (JS text, `MZ`, ELF, Mach-O, ZIP, shebang); WOFF/WOFF2 declared length ≠ file size; TTF/OTF bytes after the last table; code markers inside the binary | — |
| **Images, media, PDF, wasm** | Not a recognised image; data after PNG `IEND`, JPEG `FFD9`, GIF trailer or RIFF size; code markers; PDF with `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile`; fake mp3/mp4/webm | Real image with the wrong extension; any committed `.wasm` |
| **SVG, HTML** | `<script>`, `on*=` handlers, `javascript:`, `foreignObject`, embedded documents, `data:` hrefs | External `<script src>` hosts |
| **Disguised and dangerous files** | ELF/PE/Mach-O/UPX/archive content under any extension; shebang scripts with non-script extensions; binary data in text-type files; double extensions (`logo.png.js`); control, zero-width or RTL characters, or trailing spaces/dots in paths; symlinks leaving the repo; `.exe .dll .so .dylib .node .bat .cmd .ps1 .vbs .jar .lnk .scr .hta .msi .vsix .zip .7z .rar .tar .gz .bin .dat …`; committed `node_modules/`, `.idea/`, `.yarn/releases\|plugins`, `.pnp.cjs`, `.gitpod.yml`, `.mcp.json`, `.envrc`, `.cursor/` (except `rules/`) | Executable bit on non-scripts; files over 5 MB; Office documents; `.DS_Store` |
| **Hidden code, Trojan Source** | In code, config and agent-instruction files: content after a 60+ whitespace gap or 200+ leading spaces, content after 30+ blank lines, bidi or zero-width Unicode; base64 blobs that decode to executables, scripts or fonts (the decoded font is checked too) | Giant lines (over 3,000 chars) without dangerous tokens; minified bundles or source maps in source dirs |
| **Network, exfiltration** | Paste sites, tunnels (ngrok, serveo, trycloudflare), webhook catchers, URL shorteners, dynamic DNS, `.onion`, IPFS gateways, blockchain-RPC payload hosts, Discord/Telegram bot endpoints; hardcoded public-IP URLs in a file that reads `os.userInfo()` or env | Hardcoded public-IP URLs |
| **Tool configs** (`*.config.*`, `.eslintrc*`, `.babelrc*`, `.prettierrc*`, `.mocharc*`, `tsconfig*`/`jsconfig*.json`, `nodemon.json`, gulp/Grunt files, esbuild scripts, jest/vitest setup) | Lines over 400 chars; any code execution or I/O (`eval`, `Function`, `vm`, `child_process`, `exec`/`spawn`, `fetch`, `http(s)`, `net`, `dns`, `atob`, base64 `Buffer.from`, `fromCharCode`, hex/unicode escapes, `global.x =`, dynamic `require`/`import`, `writeFile`, `rmSync`); JSON configs that aren't pure JSON/JSONC | — |
| **`.vscode/`, `*.code-workspace`** | Files other than `extensions/settings/launch/tasks.json` and `*.code-snippets`; `\u` escapes; `runOn: folderOpen` tasks; tasks running download/eval/destructive commands; settings for terminal profiles, automation profile, env or shell args, `task.*`, `security.workspace.*`, `extensions.*`, `npm.scriptRunner`, `git.path`, and any `*Path`/`*Command`/`*Executable`/`runtime`/`interpreter`/`tsdk` setting (except `typescript.tsdk` = `node_modules/typescript/lib`); launch configs with a non-standard `runtimeExecutable`, a `program` outside the workspace, or `NODE_OPTIONS`/`LD_PRELOAD`/`--require` injection | Hidden or background tasks; `preLaunchTask`; recommended extension IDs |
| **Dev containers** | `initializeCommand` (runs on the **host**); `privileged`, host `/` or `~` mounts, `docker.sock`, host network/PID, `SYS_ADMIN`; lifecycle commands that download or eval | Any other lifecycle command |
| **AI agent config** | `.claude/*.json` with `hooks`, `statusLine` or `apiKeyHelper`; `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `GEMINI.md` etc. containing `curl … \| sh`, "do not tell the user", "ignore previous instructions", `--dangerously-skip-permissions`, `--yolo` | Pre-approved agent permissions; agent command or skill files |
| **Git** | `.gitattributes` custom `filter`/`diff`/`merge` drivers (LFS allowed); `.gitmodules` URLs outside your org (from `GITHUB_REPOSITORY_OWNER`) | `.husky/`, `.pre-commit-config.yaml`, lefthook, `simple-git-hooks`/`lint-staged`/`husky` config |
| **`package.json`** | Lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepare`, `prepublish*`, `prepack`, …) other than `husky`/`patch-package`; any script with `curl`, `wget`, `node -e`, `base64`, `eval`, `\| sh`, `rm -rf /`, `sudo`, `npm i -g`, `code --install-extension`, `NODE_OPTIONS`, `LD_PRELOAD`; dependencies from git, GitHub, URLs, tarballs or `file:`/`link:` (except packages in this repo); `npm:` aliases; `*`/`latest`/`>=0` ranges; `overrides`/`resolutions` pointing anywhere but registry versions | Implicit `pre*`/`post*` hooks; `bin` entries |
| **`.npmrc`, `.yarnrc*`, `.env*`** | `script-shell`, `node-options`, `onload-script`, `ignore-scripts=false`, `strict-ssl=false`, custom registries, auth tokens, `yarnPath`, plugins, proxies; committed real `.env` files; templates that set `NODE_OPTIONS`/`LD_PRELOAD`/`BASH_ENV` | — |
| **Docker** | `privileged`, `docker.sock`, host network/PID, `cap_add`, host `/` or `~` mounts, `curl\|sh`, `ADD https://` | — |
| **GitHub workflows in the repo** | `pull_request_target`; third-party actions not pinned to a commit SHA; `curl\|bash`; untrusted PR/issue/comment text expanded inside a script (script injection); secrets passed to network commands or serialized wholesale | GitHub-owned actions not SHA-pinned; `workflow_run` triggers |

## yara

`rules/guard.yar` has 15 rules, run recursively over the checkout.

| Rule | Matches |
|------|---------|
| `Guard_JS_Eval_Of_Decoded_Payload` | `eval`/`Function`/`vm` of `atob`/`Buffer.from`/`fromCharCode`, `Function.constructor`, `%u` shellcode |
| `Guard_JS_Eval_Of_Remote_Response` | A downloaded response executed (`.then(eval)`, `new Function('require', res.data)`) |
| `Guard_JS_Executes_Asset_File` | Reading or requiring a font, image or other asset and executing it; `node something.woff2` |
| `Guard_NPM_Install_Hook_Downloads_Code` | `install`/`prepare`/`prepublish` hooks that download, pipe to a shell, `node -e` or base64 |
| `Guard_Remote_Script_Piped_To_Shell` | `child_process` with `curl\|wget … \| sh` |
| `Guard_Reverse_Shell` | `/dev/tcp`, `nc -e`, `bash -i >&`, `socat exec:`, `python -c import socket`, `net.Socket` piped into a shell |
| `Guard_Destructive_Command` | `rm -rf` of `/`, `~`, `$HOME` or `*`; `--no-preserve-root`; `dd of=/dev/…`; `mkfs`; fork bomb; Windows `rd /s /q C:\`, `Remove-Item -Recurse -Force C:\`, `format`; `chmod -R 777 /`; `rmSync`/`rimraf` of home or root |
| `Guard_Credential_Theft` | File reads combined with SSH keys, AWS/GCloud/Kube/Docker creds, `.git-credentials`, browser `Login Data`/`Local State`/extension storage, MetaMask/Phantom/… wallet IDs, `/etc/shadow`, keychains, `.npmrc` |
| `Guard_Persistence` | Writes to shell profiles, `authorized_keys`, `/etc/cron*`/`sudoers`/systemd/`ld.so.preload`, autostart, LaunchAgents, Windows Startup; `crontab`, `schtasks /create`, `reg add …\Run`, `systemctl enable`, `code --install-extension`, `npm i -g` |
| `Guard_Exfil_Webhook_Endpoint` | Discord webhooks, Telegram bot API |
| `Guard_Crypto_Miner` | Stratum URLs, xmrig, coinhive, cryptonight, cpuminer, known pools |
| `Guard_JS_Obfuscator_Output` | More than 100 `_0x…` identifiers in one file |
| `Guard_Anti_Analysis` | VM/sandbox checks, low-CPU/RAM bail-outs, `debugger` traps, locale/timezone gating |
| `Guard_Config_Injector_Family` | `global.i='…'`, `global.r=require`, `global.m=module`, `require("\u00..\u00..")` |
| `Guard_Git_History_Tampering` | `commit --amend` with force push, `--no-verify`, faked `date`/`time` or `GIT_*_DATE`; emptied `credential.helper` |

## dependency-audit

Runs last, because package-manager audits can load repo-controlled config (for example a Yarn Berry `yarnPath`).

- **Lockfile rules** (npm, Yarn v1 and Berry, pnpm):
  - exactly one lockfile kind per directory, and every `package.json` covered by a lockfile in its directory or a parent;
  - every package resolved from `registry.npmjs.org` or `registry.yarnpkg.com` with an integrity hash (npm, Yarn v1);
  - no git, http, file, portal or exec resolutions (Yarn Berry, pnpm);
  - `package.json` and `package-lock.json` must agree.
- **Install-script allowlist:** a locked package with `hasInstallScript` (npm) or `requiresBuild` (pnpm) fails unless it is on `INSTALL_SCRIPT_ALLOW` (esbuild, sharp, bcrypt, prisma, …). Most npm malware runs from install scripts.
- **New-package vetting:** every package version the PR adds or changes is checked against the npm registry, and the check fails closed if the registry can't be reached. A version fails if:
  - it was published less than **72 h** ago (a cooldown against hijacked releases);
  - the package was created less than **30 days** ago;
  - it isn't on the public registry (dependency confusion or typo);
  - it's a direct dependency with fewer than **1,000 downloads/week** (typosquat signal).

  Deprecated versions are warnings. The cooldown applies to transitive packages too. A lockfile made minutes after a popular package publishes a patch fails until that version is 72 h old; in testing this caught `qs` (pulled in by Express) 10 h after release. Developers avoid this by setting the same delay locally ([DEVELOPERS.md](DEVELOPERS.md)).
- **Advisories:** `npm audit`, `yarn audit` (v1), `yarn npm audit` (Berry) or `pnpm audit`, run per lockfile:

  | Severity | `dependencies` (production) | `devDependencies` (dev-only) |
  |----------|-----------------------------|------------------------------|
  | Critical (includes npm **malware** advisories) | **Block** | **Block** |
  | High | **Block** | Warning |
  | Moderate / low | Reported in the log | Reported in the log |

  The package manager decides what counts as dev-only. A package is dev-only when it's reachable *only* through `devDependencies` (npm marks it `"dev": true` in the lockfile). Dev-only packages still go through the install-script allowlist, cooldown, new-package checks, lockfile rules and the critical/malware gate. Only their high advisories are downgraded, because those are mostly build-time issues such as DoS in file watchers. Code owners should reject PRs that move runtime libraries into `devDependencies`.

## clamav, gitleaks, ai-coauthor

| Check | Fails when | Fix |
|-------|------------|-----|
| `clamav` | A known malware signature anywhere in the tree. Signatures are cached per PR and updated with `freshclam` on every run. | Treat it as an incident and tell the security owner |
| `gitleaks` | A secret appears in any PR commit, including reverted ones | **Rotate first**, then rewrite the feature branch and load the value from env or secret storage |
| `ai-coauthor` | Author, committer or message credits an AI tool: `noreply@anthropic.com`, `Claude Code`, `Claude Opus/Sonnet/Haiku/Fable`, `cursoragent`, `@cursor.com`, `Copilot@users.noreply.github.com`, `copilot-swe-agent`, `@openai.com`, `ChatGPT`, `OpenAI Codex`, `devin-ai-integration`, `aider@aider.chat`, `Codeium`, `Windsurf`, `Tabnine`, `gemini-code-assist`, `Amazon Q Developer` | Reword the feature branch's commits and turn off attribution in the tool ([recipe](AGENT-SKILL.md#removing-an-ai-trailer)) |

A human co-author named *Claude* with a normal email passes, and so do Dependabot and `github-actions[bot]`. If your org allows AI co-authors, remove the check ([CUSTOMIZING.md](CUSTOMIZING.md#removing-a-check)).

## False positives and exceptions

Exceptions live **only** in the central `security-workflows` copy, so a PR can't allowlist itself:

- `ALLOW` in `repo_policy.py` takes `"path"`, `"path:check"` or `"*:check:detail"`. An allowlisted error is downgraded to a warning, so it stays visible.
- `INSTALL_SCRIPT_ALLOW` and `ALLOW` in `deps_policy.py` take `"name"` (and `ALLOW` also `"name@version"`).
- YARA rule changes go through a reviewed PR.

Never "fix" a finding by disabling the check or bypassing the ruleset.

## The failure issue

When any check fails, the `report` job opens `⚠️ Security scan failed on PR #<n>` with the label `security-scan`. It runs in its own job, so the scan steps never hold `issues: write`.

- **Security owners:** every handle in `SECURITY_OWNER`. Handles are case-insensitive and a leading `@` is optional.
- **Pushed by:** whoever pushed the commit that triggered the failing run. If someone else opened the PR, the **PR author** is tagged on a separate line. A person in both groups is marked `(also a security owner)`.
- Bots (`dependabot[bot]`) are named without `@`. If `SECURITY_OWNER` is unset, the issue says so and the run logs a warning.
- The body lists the failed checks, the commit SHA and the run link. Later failures on the same PR add a comment instead of a new issue.

Who gets notified:
- everyone @mentioned;
- repo watchers, for new issues;
- the pusher also gets GitHub's own failed-run notification.

## Reading a failure

```bash
gh pr checks <PR>                     # which run failed
gh run view <RUN_ID> --log-failed     # ::error lines name the check, file and reason
gh issue list --label security-scan   # the auto-opened issue
```

Each finding prints as `::error file=<path>::[<check>] <message>`, which GitHub shows as an annotation on the file. The findings that mean **possible compromise** (stop, don't run the project, escalate) are listed in the agent skill's [STOP section](../skills/create-pr-guarded/SKILL.md#stop-possible-compromise).
