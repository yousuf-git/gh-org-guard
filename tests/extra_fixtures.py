import io
import json
import os
import subprocess
import sys
import zipfile

from PIL import Image

out = sys.argv[1]


def w(repo, path, content):
    p = os.path.join(out, repo, path)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb" if isinstance(content, bytes) else "w") as f:
        f.write(content)


jpeg = io.BytesIO()
Image.new("RGB", (8, 8)).save(jpeg, "JPEG")
docx = io.BytesIO()
with zipfile.ZipFile(docx, "w") as z:
    z.writestr("[Content_Types].xml", "<Types/>")

# false-positive regressions: must stay error-free
w("clean", "client/public/platform.png", jpeg.getvalue())
w("clean", "docs/SRS.docx", docx.getvalue())
w("clean", "docs/plan.md", "| a |" + " " * 120 + "| b |\n" + "\n" * 50 + "end\n")
w("clean", "client/src/Deep.jsx", "export const D = () => (\n" + " " * 80 + "<span>deep</span>\n);\n")
w("clean", "client/src/Svg.tsx", "export const S = () => <path d=\"" + "M1 2L3 4 " * 400 + "\" />;\n")
w("clean", "client/src/notify.ts", "toast.message('saved'); toast.me = 1;\n")
w("clean", "AGENTS.md", "Agents may auto-approve lint fixes but must ask before deploys.\n")
w("clean", "packages/ui/package.json", json.dumps({"name": "@acme/ui", "version": "1.0.0"}))
w("clean", "packages/web/package.json", json.dumps({"name": "@acme/web", "dependencies": {"@acme/ui": "*"}}))
w("clean", "packages/web/yarn.lock", "# yarn lockfile v1\n")
w("clean", ".vscode/settings.json", json.dumps({"editor.formatOnSave": True, "typescript.tsdk": "node_modules/typescript/lib",
                                                 "terminal.integrated.defaultProfile.windows": "Git Bash",
                                                 "terminal.integrated.inheritEnv": False}))
w("clean", ".DS_Store", b"\x00\x00\x00\x01Bud1" + b"\x00" * 32)
w("clean", ".yarnrc.yml", "nodeLinker: node-modules\nnpmRegistryServer: \"https://registry.npmjs.org\"\n")

# the incident family: payload after a gap, unicode-escaped requires, history-tampering script
w("attack", "web/postcss.config.js", "module.exports = { plugins: {} };" + " " * 200 +
  "global.i='A1-1';global.r=require;const h=require(\"\\u0068\\u0074\\u0074\\u0070\\u0073\");\n")
w("attack", "web/lead.js", " " * 500 + "require('child_process')\n")
w("attack", "tools/config.bat", "@echo off\r\ndate %LAST_COMMIT_DATE%\r\ngit add .\r\ngit commit --amend -m \"%T%\" --no-verify\r\n"
  "git -c credential.helper=\"\" push -uf origin %B% --no-verify\r\n")
w("attack", ".yarnrc.yml", "yarnPath: .yarn/releases/yarn-evil.cjs\n")

for repo in ("clean", "attack"):
    subprocess.run(["git", "-C", os.path.join(out, repo), "add", "-A"], check=True)
print("extra fixtures added")
