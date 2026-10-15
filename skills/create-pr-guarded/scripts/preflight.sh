#!/usr/bin/env bash
# Local mirror of the gh-org-guard `security-scan` workflow.
# Run from the repository root on a feature branch, after committing.
# Usage: preflight.sh [base-ref]   (default: origin/main)
set -u

here=$(cd "$(dirname "$0")" && pwd)
base_ref=${1:-origin/main}

git rev-parse --show-toplevel >/dev/null 2>&1 || { echo "preflight: not inside a git repository" >&2; exit 2; }
cd "$(git rev-parse --show-toplevel)"
git fetch -q origin 2>/dev/null || echo "preflight: could not fetch origin; using local $base_ref"
base=$(git merge-base "$base_ref" HEAD) || { echo "preflight: no merge base with $base_ref" >&2; exit 2; }
# repo_policy.py checks submodule URLs against the org; in CI GitHub sets this variable.
origin=$(git remote get-url origin 2>/dev/null || true)
owner=$(printf '%s\n' "$origin" | sed -nE 's#^(https://github\.com/|git@github\.com:)([^/]+)/.*#\2#p')
export GITHUB_REPOSITORY_OWNER=${GITHUB_REPOSITORY_OWNER:-$owner}

failed=()
skipped=()
check() {
  local name=$1; shift
  echo "::group:: $name"
  if "$@"; then echo "-- $name: pass"; else echo "-- $name: FAIL"; failed+=("$name"); fi
  echo "::endgroup::"
}

files=$(mktemp)
trap 'rm -f "$files"' EXIT
git ls-files > "$files"

if command -v clamscan >/dev/null; then
  check clamav clamscan --infected --no-summary --file-list="$files"
else
  skipped+=(clamav)
fi

yara_scan() {
  local hits
  hits=$(yara --no-warnings --scan-list "$here/guard.yar" "$files") || return 1
  [ -z "$hits" ] || { echo "$hits"; return 1; }
}
if command -v yara >/dev/null; then check yara yara_scan; else skipped+=(yara); fi

if command -v gitleaks >/dev/null; then
  check gitleaks gitleaks git --log-opts="${base}..HEAD" --redact --no-banner --exit-code 1 .
else
  skipped+=(gitleaks)
fi

check repo-policy python3 -I "$here/repo_policy.py"

ai_coauthor() {
  local pattern='(noreply@anthropic\.com|@anthropic\.com|claude code|claude (opus|sonnet|haiku|fable)|cursoragent|@cursor\.(com|sh)|copilot@users\.noreply\.github\.com|copilot-swe-agent|@openai\.com|chatgpt|openai codex|devin-ai-integration|aider@aider\.chat|codeium|windsurf|tabnine|gemini-code-assist|amazon q developer)'
  local bad=0 sha hits
  for sha in $(git rev-list "${base}..HEAD"); do
    if hits=$(git show -s --format='%an <%ae>%n%cn <%ce>%n%B' "$sha" | grep -inE "$pattern"); then
      echo "Commit $sha credits an AI tool:"; printf '    %s\n' "$hits"; bad=1
    fi
  done
  return "$bad"
}
check ai-coauthor ai_coauthor

# Last, as in CI: package-manager audits can load repo-controlled config.
dependency_audit() {
  local fail=0 lock dir all_critical prod_high
  python3 -I "$here/deps_policy.py" "$base" || fail=1
  for lock in $(grep -E '(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$' "$files" | grep -v 'node_modules/'); do
    dir=$(dirname "$lock")
    case "$(basename "$lock")" in
      package-lock.json)
        all_critical="npm audit --audit-level=critical"
        prod_high="npm audit --omit=dev --audit-level=high" ;;
      yarn.lock)
        if grep -q '^__metadata:' "$lock"; then
          all_critical="yarn npm audit --all --recursive --severity critical"
          prod_high="yarn npm audit --all --recursive --environment production --severity high"
        else
          all_critical="npx --yes yarn@1.22.22 audit --level critical"
          prod_high="npx --yes yarn@1.22.22 audit --level high --groups dependencies"
        fi ;;
      pnpm-lock.yaml)
        all_critical="npx --yes pnpm@12.8.2 audit --audit-level critical"
        prod_high="npx --yes pnpm@12.8.2 audit --prod --audit-level high" ;;
    esac
    echo "$lock: critical advisories (any dependency)"
    (cd "$dir" && $all_critical) || fail=1
    echo "$lock: high advisories (production dependencies)"
    (cd "$dir" && $prod_high) || fail=1
  done
  return "$fail"
}
check dependency-audit dependency_audit

echo
[ ${#skipped[@]} -eq 0 ] || echo "Skipped (tool not installed; CI still runs them): ${skipped[*]}"
if [ ${#failed[@]} -gt 0 ]; then
  echo "FAILED: ${failed[*]}"
  echo "Read the messages above and follow 'When something fails' in SKILL.md. Do not push until they pass."
  exit 1
fi
echo "All local checks passed."
