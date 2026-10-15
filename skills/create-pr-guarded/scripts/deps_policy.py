import concurrent.futures
import datetime
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

# Packages whose install/build scripts the owner has reviewed. Edited only in security-workflows.
INSTALL_SCRIPT_ALLOW = {
    "esbuild", "sharp", "fsevents", "bcrypt", "@swc/core", "core-js", "core-js-pure", "es5-ext", "nodemon",
    "protobufjs", "@parcel/watcher", "msgpackr-extract", "unrs-resolver", "puppeteer", "cypress", "electron",
    "canvas", "sqlite3", "better-sqlite3", "bufferutil", "utf-8-validate", "@prisma/client", "prisma",
    "@prisma/engines", "argon2", "cpu-features", "ssh2", "lmdb", "@sentry/cli", "@tailwindcss/oxide", "nx",
    "@nestjs/core", "mongodb-memory-server", "@biomejs/biome", "@vercel/speed-insights", "styled-components",
}
ALLOW = set()  # "name" or "name@version" exceptions to the age/download gates
REGISTRY_URL = re.compile(r"^https://registry\.(npmjs\.org|yarnpkg\.com)/")
MIN_VERSION_AGE_HOURS = 72
MIN_PACKAGE_AGE_DAYS = 30
MIN_WEEKLY_DOWNLOADS = 1000
MAX_LOOKUPS = 400
LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")

errors = []


def fail(path, msg):
    errors.append(msg)
    print(f"::error file={path}::{msg}")


def warn(path, msg):
    print(f"::warning file={path}::{msg}")


def git_files():
    out = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True).stdout.decode()
    return [p for p in out.split("\0") if p and "node_modules/" not in p]


def git_show(ref, path):
    r = subprocess.run(["git", "show", f"{ref}:{path}"], capture_output=True)
    return r.stdout.decode("utf-8", "replace") if r.returncode == 0 else ""


def name_from_key(key):
    return key.rsplit("node_modules/", 1)[-1]


def npm_lock_packages(text):
    try:
        data = json.loads(text)
    except ValueError:
        return {}, None
    return data.get("packages") or {}, data


def check_npm_lock(path, text, manifest):
    packages, data = npm_lock_packages(text)
    if data is None:
        return fail(path, "lockfile is not valid JSON")
    if not packages:
        return fail(path, "lockfileVersion 1 is not supported; regenerate with npm 7+")
    for key, meta in packages.items():
        if not key or "node_modules/" not in key or meta.get("link"):
            continue
        name = name_from_key(key)
        resolved = meta.get("resolved", "")
        if resolved and not REGISTRY_URL.match(resolved):
            fail(path, f"{name} resolves outside the npm registry: {resolved}")
        if resolved and not meta.get("integrity"):
            fail(path, f"{name} has no integrity hash")
        if meta.get("hasInstallScript") and name not in INSTALL_SCRIPT_ALLOW:
            fail(path, f"{name}@{meta.get('version')} runs an install script and is not on the reviewed allowlist")
    if manifest is not None:
        root = packages.get("", {})
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            declared, locked = manifest.get(section) or {}, root.get(section) or {}
            if declared != locked:
                drift = sorted(set(declared.items()) ^ set(locked.items()))
                fail(path, f"package.json {section} and lockfile disagree (run npm install and commit the lockfile): {drift[:5]}")


def yarn_v1_entries(text):
    entries, header, block = [], None, {}
    for line in text.splitlines() + [""]:
        if line and not line.startswith(" ") and not line.startswith("#"):
            if header:
                entries.append((header, block))
            header, block = line.rstrip(":"), {}
        elif line.startswith("  ") and not line.startswith("    "):
            m = re.match(r'\s+(\w+)\s+"?([^"]*)"?', line)
            if m:
                block[m.group(1)] = m.group(2)
    if header:
        entries.append((header, block))
    return entries


def yarn_name(header):
    spec = header.split(",")[0].strip().strip('"')
    return spec[: spec.index("@", 1)] if "@" in spec[1:] else spec


def check_yarn_lock(path, text):
    if "__metadata:" in text:
        for m in re.finditer(r'resolution:\s*"([^"]+)"', text):
            res = m.group(1)
            proto = re.search(r"@(npm|workspace|patch|git|git\+\w+|https?|file|link|portal|exec|github):", res)
            if proto and proto.group(1) not in ("npm", "workspace", "patch"):
                fail(path, f"{res} resolves outside the npm registry ({proto.group(1)}:)")
            if proto and proto.group(1) == "patch" and "builtin<compat/" not in res:
                fail(path, f"{res} applies a local patch to a dependency; reviewer must read the .patch file")
        return
    for header, block in yarn_v1_entries(text):
        name = yarn_name(header)
        resolved = block.get("resolved", "")
        if resolved and not REGISTRY_URL.match(resolved):
            fail(path, f"{name} resolves outside the npm registry: {resolved}")
        if resolved and not block.get("integrity"):
            fail(path, f"{name} has no integrity hash")


def check_pnpm_lock(path, text):
    for m in re.finditer(r"tarball:\s*(\S+)", text):
        if not REGISTRY_URL.match(m.group(1)):
            fail(path, f"tarball outside the npm registry: {m.group(1)}")
    for m in re.finditer(r"(repo|commit):\s*(\S+)", text):
        fail(path, f"git dependency in lockfile: {m.group(2)}")
    for m in re.finditer(r"\n  '?/?(@?[^@\s'(]+)@[^:\n]+'?:\n(?:    [^\n]*\n)*?    requiresBuild: true", text):
        if m.group(1) not in INSTALL_SCRIPT_ALLOW:
            fail(path, f"{m.group(1)} runs a build/install script and is not on the reviewed allowlist")


def locked_versions(kind, text):
    found = set()
    if kind in ("package-lock.json", "npm-shrinkwrap.json"):
        packages, _ = npm_lock_packages(text)
        for key, meta in packages.items():
            if "node_modules/" in key and not meta.get("link") and meta.get("version"):
                found.add((name_from_key(key), meta["version"]))
    elif kind == "yarn.lock":
        if "__metadata:" in text:
            found |= set(re.findall(r'resolution:\s*"(@?[^@"]+)@npm:([^"]+)"', text))
        else:
            found |= {(yarn_name(h), b["version"]) for h, b in yarn_v1_entries(text) if b.get("version")}
    else:
        found |= set(re.findall(r"\n  '?/?(@?[^@\s'(]+)@(\d[^:(\s']*)", text))
    return found


def fetch_json(url):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "gh-org-guard"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def vet(pkg, direct, local_names):
    name, version = pkg
    if name in local_names or name in ALLOW or f"{name}@{version}" in ALLOW:
        return []
    problems = []
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        doc = fetch_json("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"))
    except urllib.error.HTTPError as e:
        return [f"{name}: not found on the public npm registry ({e.code}); possible dependency-confusion/typo"]
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        return [f"{name}: registry lookup failed ({e}); failing closed"]
    times = doc.get("time") or {}
    published, created = times.get(version), times.get("created")
    if published:
        age = now - datetime.datetime.fromisoformat(published.replace("Z", "+00:00"))
        if age < datetime.timedelta(hours=MIN_VERSION_AGE_HOURS):
            problems.append(f"{name}@{version} was published {int(age.total_seconds() // 3600)}h ago; wait {MIN_VERSION_AGE_HOURS}h (cooldown against hijacked releases)")
    if created:
        age = now - datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
        if age < datetime.timedelta(days=MIN_PACKAGE_AGE_DAYS):
            problems.append(f"{name} was created {age.days} day(s) ago; brand-new packages need owner review")
    if (doc.get("versions") or {}).get(version, {}).get("deprecated"):
        warn("package.json", f"{name}@{version} is deprecated: {doc['versions'][version]['deprecated']}")
    if direct:
        try:
            dl = fetch_json("https://api.npmjs.org/downloads/point/last-week/" + urllib.parse.quote(name, safe="@")).get("downloads", 0)
        except (urllib.error.URLError, TimeoutError, ValueError):
            dl = None
        if dl is not None and dl < MIN_WEEKLY_DOWNLOADS:
            problems.append(f"{name} has {dl} downloads/week; low-adoption direct dependencies need owner review (typosquat check)")
    return problems


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else None
    files = git_files()
    local_names, manifests = set(), {}
    for f in files:
        if os.path.basename(f) == "package.json":
            try:
                with open(f, encoding="utf-8") as fh:
                    manifests[os.path.dirname(f)] = json.load(fh)
                local_names.add(manifests[os.path.dirname(f)].get("name"))
            except (OSError, ValueError):
                fail(f, "package.json is not valid JSON")
    locks = {}
    for f in files:
        if os.path.basename(f) in LOCKFILES:
            locks.setdefault(os.path.dirname(f), []).append(f)
    for d, fs in locks.items():
        if len(fs) > 1:
            fail(fs[0], f"multiple lockfiles in {d or '.'}: {fs}; keep exactly one package manager")
    for d in manifests:
        parts = d.split("/") if d else []
        if not any("/".join(parts[:i]) in locks for i in range(len(parts), -1, -1)):
            fail(os.path.join(d, "package.json"), "no lockfile in this directory or any parent; commit the lockfile")
    new_pkgs, direct = set(), set()
    for d, fs in locks.items():
        for f in fs:
            kind = os.path.basename(f)
            with open(f, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            if kind in ("package-lock.json", "npm-shrinkwrap.json"):
                check_npm_lock(f, text, manifests.get(d))
            elif kind == "yarn.lock":
                check_yarn_lock(f, text)
            else:
                check_pnpm_lock(f, text)
            if base:
                added = locked_versions(kind, text) - locked_versions(kind, git_show(base, f))
                new_pkgs |= added
                for m in manifests.values():
                    for section in ("dependencies", "devDependencies", "optionalDependencies"):
                        direct |= set((m.get(section) or {}).keys())
    if new_pkgs:
        todo = sorted(new_pkgs)
        print(f"Vetting {len(todo)} new or changed package version(s) against the npm registry")
        if len(todo) > MAX_LOOKUPS:
            warn(".", f"{len(todo)} new package versions; vetting the first {MAX_LOOKUPS} (split large upgrades into smaller PRs)")
            todo = todo[:MAX_LOOKUPS]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for problems in pool.map(lambda p: vet(p, p[0] in direct, local_names), todo):
                for msg in problems:
                    fail("package.json", msg)
    if errors:
        print(f"deps-policy: {len(errors)} blocking finding(s)")
        sys.exit(1)
    print("deps-policy: all checks passed")


if __name__ == "__main__":
    main()
