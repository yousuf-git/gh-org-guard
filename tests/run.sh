#!/usr/bin/env bash
# Regression suite for the rules and checkers. Needs python3 with fonttools and pillow, the Liberation and
# URW base35 fonts, node, git and (for the YARA cases) the yara CLI. CI runs it in .github/workflows/self-test.yml.
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; failures=$((failures + 1)); }
expect() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

python3 "$root/tests/mkfixtures.py" "$work" >/dev/null
python3 "$root/tests/extra_fixtures.py" "$work" >/dev/null
python3 "$root/tests/deps_fixtures.py" "$work" >/dev/null
export GITHUB_REPOSITORY_OWNER=acme

echo "== repo-policy"
(cd "$work/clean" && python3 -I "$root/checkers/repo_policy.py") > "$work/clean.log"
expect "clean MERN repo has 0 blocking findings" '[ $? -eq 0 ] && ! grep -q "::error" "$work/clean.log"'
(cd "$work/attack" && python3 -I "$root/checkers/repo_policy.py") > "$work/attack.log"
expect "attack repo fails" '[ $? -eq 1 ]'
echo "      $(tail -1 "$work/attack.log")"
# loader.js is YARA's job; the other three are placeholders or warning-only cases.
not_policy="src/loader.js src/giant.js src/install.js src/obf.min.js"
missed=""
for f in $(git -C "$work/attack" ls-files); do
  case " $not_policy " in *" $f "*) continue ;; esac
  grep -qF "::error file=$f::" "$work/attack.log" || grep -qF "::error file=$f (" "$work/attack.log" || missed="$missed $f"
done
expect "every attack file is blocked${missed:+ (missed:$missed)}" '[ -z "$missed" ]'
sub="$work/submodule"
git init -q "$sub"
printf '[submodule "ui"]\n\tpath = ui\n\turl = https://github.com/ACME/ui.git\n' > "$sub/.gitmodules"
git -C "$sub" add .gitmodules
(cd "$sub" && python3 -I "$root/checkers/repo_policy.py") > "$work/submodule.log"
expect "submodule inside the org passes" '[ $? -eq 0 ]'
(cd "$sub" && GITHUB_REPOSITORY_OWNER= python3 -I "$root/checkers/repo_policy.py") > "$work/submodule.log"
expect "submodule with unknown org fails closed" '[ $? -eq 1 ]'

echo "== dependency policy (lockfile rules, no network)"
deps() { (cd "$work/$1" && python3 -I "$root/checkers/deps_policy.py") > "$work/$1.log" 2>&1; }
deps deps-clean; expect "clean npm lockfile passes" '[ $? -eq 0 ]'
for case in "deps-install-script:runs an install script" "deps-resolved:resolves outside the npm registry" \
            "deps-integrity:has no integrity hash" "deps-drift:lockfile disagree" \
            "deps-two-locks:multiple lockfiles" "deps-no-lock:no lockfile"; do
  name=${case%%:*}; msg=${case#*:}
  deps "$name"
  expect "$name fails with '$msg'" '[ $? -eq 1 ] && grep -q "$msg" "$work/$name.log"'
done

echo "== ai-coauthor"
pattern=$(sed -n "s/^ *pattern='\(.*\)'$/\1/p" "$root/workflow/security-scan.template.yml")
expect "pattern found in the workflow" '[ -n "$pattern" ]'
g="$work/commits"
git init -q "$g"
commit() { git -C "$g" -c user.name="$1" -c user.email="$2" commit -q --allow-empty -m "$3"; }
commit Dev dev@acme.test "base"
base=$(git -C "$g" rev-parse HEAD)
commit Dev dev@acme.test $'Add health check\n\nCo-Authored-By: Claude <noreply@anthropic.com>'
commit Dev dev@acme.test $'Fix login\n\nGenerated with Claude Code'
commit "Cursor Agent" cursoragent@cursor.com "Refactor"
ai_base=$(git -C "$g" rev-parse HEAD)
commit Dev dev@acme.test $'Pair session\n\nCo-Authored-By: Claude Smith <claude.smith@acme.test>'
commit "dependabot[bot]" 49699333+dependabot[bot]@users.noreply.github.com "Bump express"
flagged() { for sha in $(git -C "$g" rev-list "$1..$2"); do git -C "$g" show -s --format='%an <%ae>%n%cn <%ce>%n%B' "$sha" | grep -qiE "$pattern" && echo "$sha"; done; }
expect "3 of 3 AI-credited commits flagged" '[ "$(flagged "$base" "$ai_base" | wc -l)" -eq 3 ]'
expect "human co-author named Claude and Dependabot pass" '[ -z "$(flagged "$ai_base" HEAD)" ]'

echo "== report job (issue text)"
node "$root/tests/report_test.mjs" "$root/workflow/security-scan.template.yml" > "$work/report.log" 2>&1
expect "report script runs" '[ $? -eq 0 ]'
expect "owners and pusher tagged" 'grep -q "Security owners:\*\* @carol" "$work/report.log" && grep -q "Pushed by:\*\* @carol (also a security owner)" "$work/report.log"'
expect "PR author tagged when someone else pushed" 'grep -q "PR author:\*\* @bob" "$work/report.log"'
expect "bot named without @" 'grep -q "Pushed by:\*\* dependabot\[bot\]" "$work/report.log"'
expect "missing SECURITY_OWNER warns" 'grep -q "SECURITY_OWNER is not set" "$work/report.log"'
expect "repeat failure comments on the open issue" 'grep -q "\[comment #3\]" "$work/report.log"'

echo "== yara"
if command -v yara >/dev/null; then
  rules="$root/rules/guard.yar"
  expect "rules compile" 'yara --no-warnings "$rules" /dev/null'
  missed=""
  for f in "$root"/tests/yara-samples/malicious/*; do
    [ -n "$(yara --no-warnings "$rules" "$f")" ] || missed="$missed $(basename "$f")"
  done
  expect "all $(ls "$root"/tests/yara-samples/malicious | wc -l) malicious samples match${missed:+ (missed:$missed)}" '[ -z "$missed" ]'
  expect "no benign sample matches" '[ -z "$(yara --recursive --no-warnings "$rules" "$root/tests/yara-samples/benign")" ]'
  expect "clean MERN repo has no matches" '[ -z "$(yara --recursive --no-warnings "$rules" "$work/clean")" ]'
  expect "attack repo loader.js matches" 'yara --no-warnings "$rules" "$work/attack/src/loader.js" | grep -q Guard_JS_Executes_Asset_File'
else
  echo "SKIP  yara not installed"
fi

echo
if [ "$failures" -gt 0 ]; then echo "$failures test(s) failed"; exit 1; fi
echo "all tests passed"
