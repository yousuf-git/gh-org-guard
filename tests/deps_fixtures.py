"""Lockfile cases for deps_policy.py that need no network: python3 deps_fixtures.py <out-dir>."""
import json
import os
import subprocess
import sys

out = sys.argv[1]


def repo(name, files):
    d = os.path.join(out, name)
    for path, content in files.items():
        p = os.path.join(d, path)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(content if isinstance(content, str) else json.dumps(content, indent=2))
    subprocess.run(["git", "init", "-q", d], check=True)
    subprocess.run(["git", "-C", d, "add", "-A"], check=True)


def lock(deps, packages):
    return {"name": "app", "lockfileVersion": 3, "packages": {"": {"name": "app", "dependencies": deps}, **packages}}


def pkg(version, **extra):
    return {"version": version, "resolved": f"https://registry.npmjs.org/x/-/x-{version}.tgz", "integrity": "sha512-x", **extra}


manifest = {"name": "app", "dependencies": {"express": "^5.1.0"}}
repo("deps-clean", {"package.json": manifest,
                    "package-lock.json": lock({"express": "^5.1.0"}, {"node_modules/express": pkg("5.1.0")})})
repo("deps-install-script", {"package.json": manifest,
                             "package-lock.json": lock({"express": "^5.1.0"}, {"node_modules/express": pkg("5.1.0"),
                                                                                "node_modules/deasync": pkg("0.1.30", hasInstallScript=True)})})
repo("deps-resolved", {"package.json": manifest,
                       "package-lock.json": lock({"express": "^5.1.0"}, {"node_modules/express": {
                           "version": "5.1.0", "resolved": "https://npm.evil.example/express.tgz", "integrity": "sha512-x"}})})
repo("deps-integrity", {"package.json": manifest,
                        "package-lock.json": lock({"express": "^5.1.0"}, {"node_modules/express": {
                            "version": "5.1.0", "resolved": "https://registry.npmjs.org/express/-/express-5.1.0.tgz"}})})
repo("deps-drift", {"package.json": {"name": "app", "dependencies": {"express": "^5.1.0", "left-pad": "^1.3.0"}},
                    "package-lock.json": lock({"express": "^5.1.0"}, {"node_modules/express": pkg("5.1.0")})})
repo("deps-two-locks", {"package.json": manifest,
                        "package-lock.json": lock({"express": "^5.1.0"}, {"node_modules/express": pkg("5.1.0")}),
                        "yarn.lock": "# yarn lockfile v1\n"})
repo("deps-no-lock", {"package.json": manifest})
print("deps fixtures ready")
