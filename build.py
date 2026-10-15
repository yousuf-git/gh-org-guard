"""Assemble workflow/security-scan.yml from the template, the YARA rules and the two checkers."""
import os
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
PARTS = {
    "@@YARA@@": "rules/guard.yar",
    "@@REPO_POLICY@@": "checkers/repo_policy.py",
    "@@DEPS_POLICY@@": "checkers/deps_policy.py",
}


def indented(path):
    with open(os.path.join(HERE, path)) as f:
        lines = f.read().rstrip("\n").split("\n")
    return "\n".join(("          " + line) if line.strip() else "" for line in lines)


with open(os.path.join(HERE, "workflow/security-scan.template.yml")) as f:
    workflow = f.read()
for marker, path in PARTS.items():
    assert workflow.count(marker) == 1, marker
    workflow = workflow.replace(marker, indented(path))
with open(os.path.join(HERE, "workflow/security-scan.yml"), "w") as f:
    f.write(workflow)
print(f"built workflow/security-scan.yml ({len(workflow.splitlines())} lines)")

# The PR skill's local preflight must run the same rules and checkers as CI.
skill_scripts = os.path.join(HERE, "skills", "create-pr-guarded", "scripts")
for path in PARTS.values():
    shutil.copyfile(os.path.join(HERE, path), os.path.join(skill_scripts, os.path.basename(path)))
print(f"synced {len(PARTS)} files to skills/create-pr-guarded/scripts")
