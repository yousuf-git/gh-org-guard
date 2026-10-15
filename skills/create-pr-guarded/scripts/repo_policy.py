import base64
import binascii
import json
import os
import re
import struct
import subprocess
import sys

# Owner-controlled exceptions: "path", "path:check" or "*:check:detail". Edited only in security-workflows.
ALLOW = set()

FONT_EXT = {".woff", ".woff2", ".ttf", ".otf", ".eot", ".ttc"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".avif"}
TEXT_ONLY_EXT = {".json", ".jsonc", ".map", ".txt", ".md", ".csv", ".xml", ".yml", ".yaml", ".css", ".scss",
                 ".html", ".svg", ".js", ".cjs", ".mjs", ".jsx", ".ts", ".cts", ".mts", ".tsx", ".env", ".lock"}
CODE_EXT = {".js", ".cjs", ".mjs", ".jsx", ".ts", ".cts", ".mts", ".tsx", ".json", ".jsonc", ".vue", ".svelte",
            ".astro", ".html", ".css", ".scss", ".sass", ".less", ".sh", ".yml", ".yaml", ".py", ".ps1", ".mdx"}
JS_EXT = {".js", ".cjs", ".mjs", ".jsx", ".ts", ".cts", ".mts", ".tsx", ".vue", ".svelte", ".astro"}
FORBIDDEN_EXT = {".exe", ".dll", ".so", ".dylib", ".node", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".wsf",
                 ".jar", ".class", ".desktop", ".command", ".lnk", ".scr", ".hta", ".msi", ".msix", ".app",
                 ".pkg", ".dmg", ".deb", ".rpm", ".apk", ".vsix", ".bin", ".dat", ".com", ".cpl", ".reg",
                 ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".xz", ".bz2", ".iso", ".img", ".docm", ".xlsm"}
FORBIDDEN_PATHS = re.compile(
    r"(^|/)(node_modules|\.idea|\.yarn/(releases|plugins|sdks)|\.codesandbox)(/|$)|(^|/)\.cursor/(?!rules/)"
    r"|(^|/)(\.pnp\.c?js|\.pnp\.loader\.mjs|\.gitpod\.ya?ml|\.mcp\.json|\.envrc)$")
ENV_FILE = re.compile(r"(^|/)\.env(\.[^/]*)?$")
ENV_TEMPLATE = re.compile(r"\.(example|sample|template|dist)$")
DOUBLE_EXT = re.compile(r"\.(png|jpe?g|gif|svg|webp|ico|ttf|otf|woff2?|eot|pdf|txt|json|css|md|docx?|xlsx?)"
                        r"\.(js|cjs|mjs|ts|exe|sh|bat|cmd|ps1|scr|com|vbs|hta|lnk|py|jar)$", re.I)
CONFIG_NAME = re.compile(
    r"^(.+\.config\.[cm]?[jt]s|\.(eslint|prettier|babel|swc|postcss|lintstaged|mocha)rc(\..+)?"
    r"|[jt]sconfig(\..+)?\.json|nodemon\.json|gulpfile\.[cm]?[jt]s|gruntfile\.[cm]?[jt]s|\.mocharc\..+"
    r"|esbuild\.[cm]?[jt]s|setupTests\.[cm]?[jt]s|(jest|vitest)\.setup\.[cm]?[jt]s)$", re.I)
CONFIG_CODE = re.compile(
    r"child_process|\beval\s*\(|new\s+Function\b|Function\.constructor|\bvm\.[a-zA-Z]|\batob\s*\("
    r"|Buffer\.from\s*\([^)]*(base64|hex)|String\.fromCharCode|(\\x[0-9a-fA-F]{2}){8}|\bfetch\s*\("
    r"|\bhttps?\.(get|request)\s*\(|\baxios\b|\bnet\.(connect|createConnection|Socket)\b|\bdns\.(resolve|lookup)"
    r"|require\s*\(\s*['\"](node:)?(https?|net|dgram|tls|child_process|vm|dns|os)['\"]"
    r"|from\s+['\"](node:)?(https?|net|dgram|tls|child_process|vm|dns|os)['\"]"
    r"|require\s*\(\s*[^'\"`)\s]|import\s*\(\s*[^'\"`)\s]|process\.(mainModule|binding)"
    r"|\b(exec|execSync|spawn|spawnSync|execFile|fork)\s*\(|\bwriteFile(Sync)?\s*\(|\bunlink(Sync)?\s*\(|\brmSync\s*\("
    r"|\bglobal\.\w+\s*=|globalThis\.\w+\s*=|(\\u00[0-9a-fA-F]{2}){3}")
CODE_MARKERS = [b"child_process", b"require(", b"eval(", b"module.exports", b"process.env", b"new Function",
                b"<script", b"#!/bin/", b"#!/usr/bin/env", b"powershell", b"import(", b"fromCharCode"]
EXEC_MAGIC = [(b"\x7fELF", "ELF executable"), (b"MZ", "Windows PE executable"), (b"\xfe\xed\xfa\xce", "Mach-O"),
              (b"\xfe\xed\xfa\xcf", "Mach-O"), (b"\xce\xfa\xed\xfe", "Mach-O"), (b"\xcf\xfa\xed\xfe", "Mach-O"),
              (b"\xca\xfe\xba\xbe", "Mach-O/Java class"), (b"PK\x03\x04", "ZIP/JAR archive"),
              (b"\x1f\x8b", "gzip archive"), (b"7z\xbc\xaf\x27\x1c", "7z archive"), (b"Rar!", "RAR archive"),
              (b"\x00asm", "WebAssembly"), (b"#!", "script with shebang")]
SHEBANG_OK_EXT = {".sh", ".bash", ".zsh", ".py", ".js", ".cjs", ".mjs", ".ts", ""}
OFFICE_EXT = {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}
IMAGE_SIG = [(b"\x89PNG\r\n\x1a\n", ".png"), (b"\xff\xd8\xff", ".jpg"), (b"GIF87a", ".gif"), (b"GIF89a", ".gif"),
             (b"BM", ".bmp"), (b"\x00\x00\x01\x00", ".ico")]
VSCODE_ALLOWED = re.compile(r"^(extensions|settings|launch|tasks)\.json$|\.code-snippets$")
VSCODE_RISKY_KEY = re.compile(
    r"^(terminal\.integrated\.(profiles|automationProfile|env|shell|shellArgs|cwd)|task\.|security\.workspace\.|extensions\."
    r"|npm\.scriptRunner|npm\.packageManager"
    r"|git\.(path|hooks)|remote\.|http\.proxy)"
    r"|\.((?i:path|executable|runtime|runtimeExecutable|runtimeArgs|tsdk|command|commandLine|interpreter|shell|shellArgs"
    r"|env|args|nodeOptions|execArgv)|[a-zA-Z]*(Path|Command|CommandLine|Executable))$")
VSCODE_SAFE_RUNTIME = {"node", "npm", "npx", "yarn", "pnpm", "bun", "deno", "nodemon", "ts-node", "tsx"}
DEVCONTAINER_CMDS = ["onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand"]
LIFECYCLE = {"preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare",
             "prepublishOnly", "prepack", "postpack", "dependencies"}
LIFECYCLE_SAFE = re.compile(r"^(husky( install)?|husky \|\| true|npx husky( install)?|patch-package|ngcc)$")
SCRIPT_DANGER = re.compile(
    r"\b(curl|wget|iwr|Invoke-WebRequest|Invoke-Expression|iex|certutil|bitsadmin|nc|ncat|socat)\b|\|\s*(ba|z)?sh\b"
    r"|node\s+(-e|--eval|-p|--print)\b|base64|\beval\b|rm\s+-[a-z]*r[a-z]*f?\s+[/~$*]|--no-preserve-root"
    r"|chmod\s+(-R\s+)?[0-7]*7[0-7]*\s+/|>\s*/dev/|\bsudo\b|npm\s+(i|install)\s+-g|code\s+--install-extension"
    r"|NODE_OPTIONS|LD_PRELOAD", re.I)
DEP_BAD_SPEC = re.compile(r"^(git\+|git:|github:|gitlab:|bitbucket:|https?:|file:|link:|portal:|workspace:)|\.tgz$|\.tar\.gz$|^[\w.-]+/[\w.-]+(#.*)?$")
DEP_ALIAS = re.compile(r"^npm:")
DEP_LOOSE = re.compile(r"^(\*|latest|next|x|)$|^>=?\s*0")
NPMRC_RISKY = re.compile(r"^\s*(script-shell|node-options|shell|git|onload-script|init-module|globalconfig|userconfig"
                         r"|prefix|cache|tmp|ca|cafile|strict-ssl\s*=\s*false|ignore-scripts\s*=\s*false|.*:_authToken"
                         r"|_auth|_password|.*registry\s*=)", re.I)
NPMRC_REGISTRY_OK = re.compile(r"registry\s*=\s*https://registry\.npmjs\.org/?\s*$", re.I)
C2_HOSTS = re.compile(
    r"(?<![\w.-])(pastebin\.com|paste\.ee|hastebin|ghostbin|rentry\.co|ngrok(-free)?\.(io|app|dev)|serveo\.net|trycloudflare\.com"
    r"|loca\.lt|localtunnel\.me|[a-z2-7]{16,56}\.onion\b|ipfs\.io/ipfs|cloudflare-ipfs|dweb\.link|transfer\.sh"
    r"|webhook\.site|requestbin|pipedream\.net|interact\.sh|oast\.(pro|live|site|online|fun|me)|burpcollaborator"
    r"|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|bit\.ly/|tinyurl\.com/|is\.gd/|t\.ly/|cutt\.ly/"
    r"|duckdns\.org|no-ip\.(com|org)|ddns\.net|hopto\.org|zapto\.org|gist\.githubusercontent\.com"
    r"|api\.trongrid\.io|bsc-dataseed|api\.aptoslabs\.com|fullnode\.mainnet)", re.I)
PUBLIC_IP_URL = re.compile(
    r"\b(?:https?|wss?)://(?!(?:127\.|10\.|0\.0\.0\.0|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.))"
    r"\d{1,3}(?:\.\d{1,3}){3}")
HOST_DATA = re.compile(r"os\.(userInfo|homedir|hostname|networkInterfaces|platform)\s*\(|process\.env\b(?!\.)|"
                       r"JSON\.stringify\(\s*process\.env|Object\.(keys|entries)\(\s*process\.env")
AGENT_FILE = re.compile(r"(^|/)(CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|copilot-instructions\.md)$|(^|/)\.cursor/rules/")
TROJAN_UNICODE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿]")
BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
WORKFLOW_UNTRUSTED = re.compile(
    r"\$\{\{\s*github\.(event\.(pull_request\.(title|body|head\.ref|head\.label)|issue\.(title|body)|comment\.body"
    r"|review\.body|review_comment\.body|pages\.[^}]*page_name|commits\.[^}]*\.message|head_commit\.message"
    r"|head_commit\.author\.(name|email))|head_ref)\s*\}\}")

findings = {"error": 0}
LOCAL_PACKAGES = set()


def report(level, path, check, msg):
    keys = {path, f"{path}:{check}", f"*:{check}:{msg.split(':', 1)[0]}"}
    if level == "error" and keys & ALLOW:
        level, msg = "warning", f"allowlisted: {msg}"
    if level == "error":
        findings["error"] += 1
    print(f"::{level} file={path}::[{check}] {msg}")


def fail(path, check, msg):
    report("error", path, check, msg)


def warn(path, check, msg):
    report("warning", path, check, msg)


def strip_jsonc(text):
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        else:
            out.append(c)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def parse_jsonc(path, text):
    try:
        return json.loads(strip_jsonc(text))
    except ValueError as e:
        fail(path, "jsonc", f"not valid JSON/JSONC ({e}); this file must contain data only")
        return None


def sniff_exec(data):
    for magic, label in EXEC_MAGIC:
        if data.startswith(magic):
            return label
    if b"UPX!" in data[:4096]:
        return "UPX-packed executable"
    return None


def check_font(path, data, label=None):
    where = label or path
    ext = os.path.splitext(path)[1].lower()
    size = len(data)
    if ext in (".woff", ".woff2"):
        magic = b"wOFF" if ext == ".woff" else b"wOF2"
        if data[:4] != magic:
            return fail(where, "font", f"not a real {ext} font (starts with {data[:8]!r}{', ' + sniff_exec(data) if sniff_exec(data) else ''})")
        declared = struct.unpack(">I", data[8:12])[0]
        if declared != size:
            return fail(where, "font", f"header length {declared} != file size {size}; data appended or truncated")
    elif ext in (".ttf", ".otf"):
        if data[:4] not in (b"\x00\x01\x00\x00", b"OTTO", b"true", b"typ1"):
            return fail(where, "font", f"not a real {ext} font (starts with {data[:8]!r}{', ' + sniff_exec(data) if sniff_exec(data) else ''})")
        num_tables = struct.unpack(">H", data[4:6])[0]
        end = 12 + 16 * num_tables
        if size < end:
            return fail(where, "font", "truncated table directory")
        for t in range(num_tables):
            off, length = struct.unpack(">II", data[12 + 16 * t + 8:12 + 16 * t + 16])
            end = max(end, off + length)
        if end > size:
            return fail(where, "font", "font tables extend past the end of the file (corrupt or crafted)")
        if size > ((end + 3) & ~3):
            return fail(where, "font", f"{size - end} bytes after the last font table; data appended")
    elif ext == ".ttc":
        if data[:4] != b"ttcf":
            return fail(where, "font", "not a real .ttc font")
    elif ext == ".eot":
        if size < 36 or data[34:36] != b"LP" or struct.unpack("<I", data[:4])[0] != size:
            return fail(where, "font", "not a real .eot font or size mismatch")
    check_code_markers(where, data, "font")


def real_image_ext(data):
    for sig, ext in IMAGE_SIG:
        if data.startswith(sig):
            return ext
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ".webp"
    if data[4:8] == b"ftyp" and data[8:12] in (b"avif", b"avis", b"heic", b"heix", b"mif1"):
        return ".avif"
    return None


def check_image(path, data):
    ext = os.path.splitext(path)[1].lower()
    real = real_image_ext(data)
    if real and real != {".jpeg": ".jpg"}.get(ext, ext):
        warn(path, "image", f"image is really {real}; rename it")
        ext = real
    ok = {
        ".png": data[:8] == b"\x89PNG\r\n\x1a\n",
        ".jpg": data[:3] == b"\xff\xd8\xff", ".jpeg": data[:3] == b"\xff\xd8\xff",
        ".gif": data[:6] in (b"GIF87a", b"GIF89a"),
        ".webp": data[:4] == b"RIFF" and data[8:12] == b"WEBP",
        ".ico": data[:4] in (b"\x00\x00\x01\x00", b"\x00\x00\x02\x00"),
        ".bmp": data[:2] == b"BM",
        ".avif": data[4:12] in (b"ftypavif", b"ftypavis"),
    }[ext]
    if not ok:
        kind = sniff_exec(data)
        return fail(path, "image", f"not a real {ext} image (starts with {data[:8]!r}{', ' + kind if kind else ''})")
    if ext == ".png" and not data.endswith(b"IEND\xaeB`\x82"):
        return fail(path, "image", "data after the PNG IEND chunk (polyglot/appended payload)")
    if ext in (".jpg", ".jpeg") and b"\xff\xd9" not in data[-32:]:
        return fail(path, "image", "data after the JPEG end marker (polyglot/appended payload)")
    if ext == ".gif" and not data.rstrip(b"\x00").endswith(b";"):
        return fail(path, "image", "data after the GIF trailer")
    if ext == ".webp" and struct.unpack("<I", data[4:8])[0] + 8 != len(data):
        return fail(path, "image", "RIFF size mismatch; data appended")
    check_code_markers(path, data, "image")


def check_code_markers(path, data, check):
    found = [m.decode() for m in CODE_MARKERS if m in data]
    if found:
        fail(path, check, f"binary asset contains code markers {found}")


def check_media(path, data):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".pdf":
        if not data.startswith(b"%PDF-"):
            return fail(path, "pdf", "not a real PDF")
        active = [k.decode() for k in (b"/JavaScript", b"/JS", b"/OpenAction", b"/Launch", b"/EmbeddedFile", b"/AA", b"/RichMedia")
                  if re.search(re.escape(k) + rb"[\s/<(\[]", data)]
        if active:
            fail(path, "pdf", f"PDF contains active content {active}")
    elif ext in (".mp4", ".m4a", ".mov") and data[4:8] != b"ftyp":
        fail(path, "media", f"not a real {ext} file")
    elif ext == ".mp3" and not (data[:3] == b"ID3" or data[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2")):
        fail(path, "media", "not a real .mp3 file")
    elif ext == ".webm" and data[:4] != b"\x1a\x45\xdf\xa3":
        fail(path, "media", "not a real .webm file")
    elif ext == ".wasm":
        if not data.startswith(b"\x00asm"):
            fail(path, "wasm", "not a real WebAssembly module")
        else:
            warn(path, "wasm", "committed WebAssembly binary; reviewer must confirm its source")


def check_svg(path, text):
    m = re.search(r"<script|\bon[a-z]+\s*=|javascript:|<foreignObject|<iframe|<embed|<object|xlink:href\s*=\s*['\"]data:|href\s*=\s*['\"]data:", text, re.I)
    if m:
        fail(path, "svg", f"SVG contains active content ({m.group(0)!r})")


def check_html(path, text):
    for m in re.finditer(r"<script[^>]*\bsrc\s*=\s*['\"](https?:)?//([^/'\"]+)", text, re.I):
        warn(path, "html", f"external script from {m.group(2)}")


def check_text(path, text, lines, ext):
    if ext in CODE_EXT or AGENT_FILE.search(path):
        check_hidden(path, lines)
    m = TROJAN_UNICODE.search(text, 1)
    if m:
        no = text.count("\n", 0, m.start()) + 1
        fail(path, "trojan-source", f"line {no}: invisible/bidirectional Unicode U+{ord(m.group(0)):04X}")
    if ext in JS_EXT and not re.search(r"\.min\.[cm]?js$", path):
        for no, line in enumerate(lines, 1):
            if len(line) > 3000:
                (fail if CONFIG_CODE.search(line) or "_0x" in line else warn)(
                    path, "giant-line", f"line {no} is {len(line)} chars; minified/obfuscated code is not allowed in source")
                break
    if re.search(r"\.min\.[cm]?js$|\.map$", path) and re.match(r"(src|server|client|app|api|lib|routes|controllers|models|middleware)/", path):
        warn(path, "bundle", "minified bundle or source map committed inside a source directory")
    check_base64(path, text)
    if ext in JS_EXT or ext in (".json", ".html", ".sh", ".py", ".yml", ".yaml"):
        check_network(path, text)


def check_hidden(path, lines):
    for no, line in enumerate(lines, 1):
        gap = re.search(r"\S[ \t]{60,}\S", line)
        lead = len(line) - len(line.lstrip(" \t"))
        if gap or (lead >= 200 and line.strip()):
            n = gap.end() - gap.start() - 2 if gap else lead
            fail(path, "hidden-code", f"line {no}: content pushed off-screen after {n} whitespace chars")
            break
    blank = 0
    for no, line in enumerate(lines, 1):
        if line.strip():
            if blank >= 30:
                fail(path, "hidden-code", f"line {no}: content after {blank} blank lines")
                break
            blank = 0
        else:
            blank += 1


def check_base64(path, text):
    for m in BASE64_BLOB.finditer(text):
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        no = text.count("\n", 0, m.start()) + 1
        kind = sniff_exec(raw)
        if kind and kind != "script with shebang":
            fail(path, "base64-payload", f"line {no}: base64 blob decodes to {kind}")
        elif raw.startswith(b"#!") or any(k in raw for k in (b"child_process", b"require(", b"eval(", b"new Function", b"powershell", b"/bin/sh", b"/bin/bash")):
            fail(path, "base64-payload", f"line {no}: base64 blob decodes to executable script/code")
        elif raw[:4] in (b"wOFF", b"wOF2", b"OTTO", b"\x00\x01\x00\x00"):
            ext = {b"wOFF": ".woff", b"wOF2": ".woff2", b"OTTO": ".otf", b"\x00\x01\x00\x00": ".ttf"}[raw[:4]]
            check_font("embedded" + ext, raw, label=f"{path} (line {no}, embedded font)")


def check_network(path, text):
    m = C2_HOSTS.search(text)
    if m:
        no = text.count("\n", 0, m.start()) + 1
        fail(path, "c2-endpoint", f"line {no}: reference to {m.group(0)!r} (paste/tunnel/webhook/shortener/dynamic-DNS/blockchain-RPC host)")
    m = PUBLIC_IP_URL.search(text)
    if m:
        no = text.count("\n", 0, m.start()) + 1
        if HOST_DATA.search(text):
            fail(path, "exfil", f"line {no}: hardcoded IP endpoint {m.group(0)!r} in a file that reads host data/env")
        else:
            warn(path, "exfil", f"line {no}: hardcoded IP endpoint {m.group(0)!r}; use a hostname from config")


def check_config(path, text, lines):
    for no, line in enumerate(lines, 1):
        if len(line) > 400:
            fail(path, "config", f"line {no} is {len(line)} chars; config files must not contain long/minified lines")
            break
    base = os.path.basename(path)
    if base.endswith((".json", ".jsonc")) or base in (".babelrc", ".swcrc"):
        parse_jsonc(path, text)
        return
    m = CONFIG_CODE.search(text)
    if m:
        no = text.count("\n", 0, m.start()) + 1
        fail(path, "config", f"line {no}: build/tool config runs code ({m.group(0).strip()!r}); configs may only import plugins and export settings")


def check_vscode(path, text):
    name = path.split(".vscode/", 1)[1]
    if "/" in name or not VSCODE_ALLOWED.search(name):
        return fail(path, "vscode", "only extensions.json, settings.json, launch.json, tasks.json and *.code-snippets may live in .vscode/")
    if re.search(r"\\u[0-9a-fA-F]{4}", text):
        return fail(path, "vscode", "\\u escapes are not allowed in .vscode files (used to hide keys)")
    data = parse_jsonc(path, text)
    if not isinstance(data, dict):
        return
    if name == "tasks.json":
        check_tasks(path, data.get("tasks", []))
    elif name == "settings.json":
        risky = [k for k in data if VSCODE_RISKY_KEY.search(k)
                 and not (k.endswith("tsdk") and re.fullmatch(r"(\./)?node_modules/typescript/lib/?", str(data[k])))]
        if risky:
            fail(path, "vscode", f"settings that run programs, change shells/env or weaken trust are not allowed: {risky}")
    elif name == "launch.json":
        for cfg in data.get("configurations", []) or []:
            rt = str(cfg.get("runtimeExecutable", ""))
            if rt and (rt not in VSCODE_SAFE_RUNTIME or "/" in rt or "\\" in rt):
                fail(path, "vscode", f"launch runtimeExecutable {rt!r} is not a standard runtime")
            prog = str(cfg.get("program", ""))
            if prog and not prog.startswith("${workspaceFolder}"):
                fail(path, "vscode", f"launch program {prog!r} is outside the workspace")
            for key in ("env", "runtimeArgs"):
                if re.search(r"NODE_OPTIONS|LD_PRELOAD|--require|--import|-r\b", json.dumps(cfg.get(key, ""))):
                    fail(path, "vscode", f"launch {key} injects code (NODE_OPTIONS/LD_PRELOAD/--require)")
            if cfg.get("preLaunchTask"):
                warn(path, "vscode", f"preLaunchTask {cfg['preLaunchTask']!r} runs before debugging; reviewer must read tasks.json")
    elif name == "extensions.json":
        recs = data.get("recommendations", []) or []
        if recs:
            warn(path, "vscode", f"recommended extensions (reviewer must confirm exact publisher IDs): {recs}")


def check_tasks(path, tasks):
    for task in tasks or []:
        label = task.get("label", "?")
        blob = json.dumps(task)
        if re.search(r'"runOn"\s*:\s*"folderOpen"', blob):
            fail(path, "vscode", f"task {label!r} auto-runs on folder open (runOptions.runOn: folderOpen)")
        if re.search(r'"reveal"\s*:\s*"never"', blob) or task.get("isBackground"):
            warn(path, "vscode", f"task {label!r} is hidden/background")
        if SCRIPT_DANGER.search(blob):
            fail(path, "vscode", f"task {label!r} runs network/encoded/destructive commands")


def check_workspace_file(path, text):
    data = parse_jsonc(path, text)
    if not isinstance(data, dict):
        return
    check_tasks(path, (data.get("tasks") or {}).get("tasks", []))
    risky = [k for k in (data.get("settings") or {}) if VSCODE_RISKY_KEY.search(k)]
    if risky:
        fail(path, "vscode", f"risky workspace settings: {risky}")


def check_devcontainer(path, text):
    data = parse_jsonc(path, text)
    if not isinstance(data, dict):
        return
    if "initializeCommand" in data:
        fail(path, "devcontainer", "initializeCommand runs on the developer's HOST machine")
    blob = json.dumps(data)
    if data.get("privileged") or re.search(r"--privileged|docker\.sock|source=(/|\$\{localEnv:HOME\}|~)[,\"]|--pid=host|--network=host|SYS_ADMIN", blob):
        fail(path, "devcontainer", "privileged container, host root/home mount, docker.sock or host namespaces")
    for key in DEVCONTAINER_CMDS:
        if key in data:
            (fail if SCRIPT_DANGER.search(json.dumps(data[key])) else warn)(path, "devcontainer", f"{key} runs automatically: {data[key]!r}")


def check_claude(path, text):
    if path.endswith(".json"):
        data = parse_jsonc(path, text)
        if isinstance(data, dict) and ("hooks" in data or "statusLine" in data or "apiKeyHelper" in data):
            fail(path, "agent-config", "committed Claude Code settings define hooks/statusLine/apiKeyHelper (auto-executing commands)")
        if isinstance(data, dict) and (data.get("permissions") or {}).get("allow"):
            warn(path, "agent-config", f"pre-approved agent permissions: {data['permissions']['allow']}")
    else:
        warn(path, "agent-config", "agent command/skill definition; reviewer must read it")


def check_agent_instructions(path, text):
    m = re.search(r"(curl|wget|iwr)[^\n]{0,200}\|\s*(ba|z)?sh|run (this|the following) (silently|without (asking|telling))"
                  r"|do not (tell|inform|mention)[^\n]{0,40}user|ignore (all |any )?(previous|prior) instructions"
                  r"|dangerously-skip-permissions|--yolo\b", text, re.I)
    if m:
        fail(path, "agent-config", f"agent instructions contain command/concealment directive {m.group(0)!r}")


def check_git_files(path, text, base):
    if base == ".gitattributes":
        for no, line in enumerate(text.splitlines(), 1):
            m = re.search(r"\b(filter|diff|merge)=(?!lfs\b)(\S+)", line)
            if m:
                fail(path, "git", f"line {no}: custom {m.group(1)} driver {m.group(2)!r} (executes local commands when configured)")
    elif base == ".gitmodules":
        # Set by GitHub Actions; the skill's preflight derives it from the origin remote.
        org = os.environ.get("GITHUB_REPOSITORY_OWNER", "")
        for url in re.findall(r"url\s*=\s*(\S+)", text):
            if not org or not re.match(r"(https://github\.com/|git@github\.com:)" + re.escape(org) + "/", url, re.I):
                fail(path, "git", f"submodule points outside the {org or 'unknown'} organization: {url}")
    else:
        warn(path, "git-hooks", "git hook configuration; runs on developers' machines, reviewer must read it")


def check_npmrc(path, text):
    for no, line in enumerate(text.splitlines(), 1):
        if line.strip().startswith(("#", ";")) or not line.strip():
            continue
        if NPMRC_RISKY.match(line) and not NPMRC_REGISTRY_OK.search(line):
            fail(path, "npmrc", f"line {no}: risky npm setting {line.strip().split('=')[0]!r} (shell/node-options/registry/auth/ssl)")


def check_yarnrc(path, text):
    for no, line in enumerate(text.splitlines(), 1):
        m = re.match(r"\s*[\"']?(yarnPath|yarn-path|npmRegistryServer|registry|npmAuthToken|npmAuthIdent|_authToken"
                     r"|unsafeHttpWhitelist|enableStrictSsl|httpsProxy|httpProxy|injectEnvironmentFiles|plugins)\b", line)
        if m and not re.search(r"https://registry\.(npmjs\.org|yarnpkg\.com)", line):
            fail(path, "yarnrc", f"line {no}: risky yarn setting {m.group(1)!r} (binary path/registry/auth/ssl/plugins)")


def check_env(path, text):
    if not ENV_TEMPLATE.search(path):
        return fail(path, "env-file", "real .env files must not be committed; commit .env.example with placeholders")
    if re.search(r"^\s*(NODE_OPTIONS|LD_PRELOAD|DYLD_INSERT_LIBRARIES|BASH_ENV|ENV|PROMPT_COMMAND)\s*=", text, re.M):
        fail(path, "env-file", "env template sets a code-loading variable (NODE_OPTIONS/LD_PRELOAD/…)")


def check_package_json(path, text):
    data = parse_jsonc(path, text)
    if not isinstance(data, dict):
        return
    scripts = data.get("scripts") or {}
    for name, cmd in scripts.items():
        cmd = str(cmd)
        if name in LIFECYCLE and not LIFECYCLE_SAFE.match(cmd.strip()):
            fail(path, "npm-scripts", f"lifecycle script {name!r} runs automatically on install: {cmd!r}")
        elif SCRIPT_DANGER.search(cmd):
            fail(path, "npm-scripts", f"script {name!r} downloads/evals/deletes or injects code: {cmd!r}")
        elif (name.startswith("pre") and name[3:] in scripts) or (name.startswith("post") and name[4:] in scripts):
            warn(path, "npm-scripts", f"hook {name!r} runs implicitly: {cmd!r}")
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "bundleDependencies"):
        deps = data.get(section) or {}
        if isinstance(deps, list):
            fail(path, "npm-deps", f"{section} bundles packages into the tarball: {deps}")
            continue
        for dep, spec in deps.items():
            spec = str(spec).strip()
            if dep in LOCAL_PACKAGES and (spec == "*" or re.match(r"(file|link|workspace):", spec)):
                if spec.startswith("file:"):
                    warn(path, "npm-deps", f"{section}.{dep} = {spec!r} is a vendored/local package; it is scanned as part of this repo")
                continue
            if DEP_BAD_SPEC.search(spec):
                fail(path, "npm-deps", f"{section}.{dep} = {spec!r} installs from git/url/file instead of the npm registry")
            elif DEP_ALIAS.match(spec):
                fail(path, "npm-deps", f"{section}.{dep} = {spec!r} is an npm alias (package name differs from import name)")
            elif DEP_LOOSE.match(spec):
                fail(path, "npm-deps", f"{section}.{dep} = {spec!r} is an unpinned/wildcard range")
    for section in ("overrides", "resolutions", "pnpm"):
        for dep, spec in flatten(data.get(section) or {}):
            if DEP_BAD_SPEC.search(spec) or DEP_ALIAS.match(spec) or DEP_LOOSE.match(spec):
                fail(path, "npm-deps", f"{section} redirects {dep} to {spec!r}")
    if data.get("bin"):
        warn(path, "npm-bin", f"package declares bin entries: {data['bin']}")
    for hook in ("simple-git-hooks", "husky", "lint-staged", "pre-commit"):
        if hook in data:
            warn(path, "git-hooks", f"{hook} config in package.json runs on developers' machines")


def flatten(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from flatten(v, f"{prefix}{k}>")
    else:
        yield prefix.rstrip(">"), str(obj)


def check_docker(path, text):
    for no, line in enumerate(text.splitlines(), 1):
        m = re.search(r"privileged:\s*true|--privileged|/var/run/docker\.sock|network_mode:\s*[\"']?host|pid:\s*[\"']?host"
                      r"|cap_add:|SYS_ADMIN|^\s*-\s*[\"']?(/|~|\$\{?HOME\}?)(:|/:)|--mount[^\n]*source=/[ ,]"
                      r"|(curl|wget)[^\n]*\|\s*(ba|z)?sh|ADD\s+https?://", line)
        if m:
            fail(path, "docker", f"line {no}: {m.group(0).strip()!r} (privileged/host access/remote script)")


def check_workflow(path, text):
    if re.search(r"^\s*pull_request_target\s*:|^on:\s*\[?[^\n]*pull_request_target", text, re.M):
        fail(path, "workflow", "pull_request_target runs untrusted PR code with secrets")
    if re.search(r"^\s*workflow_run\s*:", text, re.M):
        warn(path, "workflow", "workflow_run trigger runs with secrets after other workflows; reviewer must check artifacts handling")
    for no, line in enumerate(text.splitlines(), 1):
        m = re.search(r"uses:\s*['\"]?([^@\s'\"]+)@([^\s'\"#]+)", line)
        if m and not m.group(1).startswith("./") and not re.fullmatch(r"[0-9a-f]{40}", m.group(2)):
            (warn if m.group(1).split("/")[0] in ("actions", "github") else fail)(
                path, "workflow", f"line {no}: {m.group(1)}@{m.group(2)} is not pinned to a full commit SHA")
        if re.search(r"(curl|wget)[^\n]*\|\s*(sudo\s+)?(ba|z)?sh", line):
            fail(path, "workflow", f"line {no}: pipes a remote script into a shell")
        if WORKFLOW_UNTRUSTED.search(line):
            fail(path, "workflow", f"line {no}: untrusted event text (PR title/body, branch name, comment) expanded inside a script (script injection); pass it via env")
    if re.search(r"secrets\.[A-Z_]+[^\n]*(curl|wget|http)|toJSON\(\s*secrets\s*\)", text):
        fail(path, "workflow", "secrets passed to a network command or serialized wholesale")


def check_path(path, mode):
    base = os.path.basename(path)
    ext = os.path.splitext(base)[1].lower()
    if re.search(r"[\x00-\x1f\x7f​-‏‪-‮⁦-⁩]", path):
        fail(path, "filename", "control, zero-width or right-to-left-override characters in the path")
    if any(part != part.rstrip(" .") or part != part.lstrip(" ") for part in path.split("/")):
        fail(path, "filename", "path segment with leading/trailing space or trailing dot")
    if DOUBLE_EXT.search(base):
        fail(path, "filename", "double extension disguising an executable/script")
    if ext in FORBIDDEN_EXT:
        fail(path, "forbidden-file", f"{ext} files (executables, installers, archives, native addons, extensions) may not be committed")
    if FORBIDDEN_PATHS.search(path):
        fail(path, "forbidden-file", "committed IDE/run-config, vendored node_modules, yarn binaries/PnP or non-npm lockfile")
    if mode == "100755" and ext not in (".sh", ".py", ".js", ".mjs", ".cjs", "") and not path.startswith(".husky/"):
        warn(path, "exec-bit", "executable bit set on a non-script file")


def main():
    listing = subprocess.run(["git", "ls-files", "-s", "-z"], capture_output=True, check=True).stdout.decode("utf-8", "surrogateescape")
    root = os.path.realpath(".")
    entries = list(filter(None, listing.split("\0")))
    for entry in entries:
        rel = entry.split("\t", 1)[1]
        if os.path.basename(rel) == "package.json" and "node_modules/" not in rel and os.path.isfile(rel):
            try:
                with open(rel, encoding="utf-8") as f:
                    LOCAL_PACKAGES.add(json.loads(strip_jsonc(f.read())).get("name"))
            except (ValueError, AttributeError):
                pass
    for entry in entries:
        meta, path = entry.split("\t", 1)
        mode = meta.split()[0]
        check_path(path, mode)
        if mode == "120000":
            target = os.readlink(path)
            resolved = os.path.realpath(os.path.join(os.path.dirname(path), target))
            if os.path.isabs(target) or not (resolved == root or resolved.startswith(root + os.sep)):
                fail(path, "symlink", f"symlink points outside the repository: {target}")
            continue
        if mode == "160000" or not os.path.isfile(path):
            continue
        with open(path, "rb") as f:
            data = f.read()
        base = os.path.basename(path)
        ext = os.path.splitext(base)[1].lower()
        if len(data) > 5 * 1024 * 1024:
            warn(path, "large-file", f"{len(data) // 1024 // 1024} MB file; reviewer must confirm what it is")
        if ext in FONT_EXT:
            check_font(path, data)
            continue
        if ext in IMAGE_EXT:
            check_image(path, data)
            continue
        if ext in (".pdf", ".mp4", ".m4a", ".mov", ".mp3", ".webm", ".wasm"):
            check_media(path, data)
            continue
        if base == ".DS_Store":
            warn(path, "junk", "macOS .DS_Store committed; delete it and add it to .gitignore")
            continue
        kind = sniff_exec(data)
        if kind == "ZIP/JAR archive" and ext in OFFICE_EXT:
            warn(path, "office-doc", "Office document committed; keep documents outside code repos")
            continue
        if kind and not (kind == "script with shebang" and ext in SHEBANG_OK_EXT):
            fail(path, "disguised-file", f"content is a {kind} regardless of its {ext or 'missing'} extension")
            continue
        if b"\x00" in data[:8192]:
            if ext in TEXT_ONLY_EXT or ext == "" or ext in CODE_EXT:
                fail(path, "disguised-file", f"binary content in a {ext or 'extensionless'} file that should be text")
            else:
                warn(path, "binary", f"unrecognised binary file type {ext}")
            continue
        text = data.decode("utf-8", errors="replace")
        lines = text.splitlines()
        in_vscode = path.startswith(".vscode/") or "/.vscode/" in path
        if base != "package-lock.json":
            check_text(path, text, lines, ext)
        if ext == ".svg":
            check_svg(path, text)
        if ext in (".html", ".htm"):
            check_html(path, text)
        if CONFIG_NAME.match(base):
            check_config(path, text, lines)
        if in_vscode:
            check_vscode(path, text)
        if ext == ".code-workspace":
            check_workspace_file(path, text)
        if base in ("devcontainer.json", ".devcontainer.json"):
            check_devcontainer(path, text)
        if path.startswith(".claude/") or "/.claude/" in path:
            check_claude(path, text)
        if AGENT_FILE.search(path):
            check_agent_instructions(path, text)
        if base in (".gitattributes", ".gitmodules", ".pre-commit-config.yaml", "lefthook.yml", "lefthook.yaml", ".lefthook.yml") or path.startswith(".husky/"):
            check_git_files(path, text, base)
        if base == ".npmrc":
            check_npmrc(path, text)
        if base in (".yarnrc", ".yarnrc.yml"):
            check_yarnrc(path, text)
        if ENV_FILE.search(path):
            check_env(path, text)
        if base == "package.json" and "node_modules/" not in path:
            check_package_json(path, text)
        if re.match(r"(Dockerfile|Containerfile)(\..+)?$|.*\.dockerfile$|(docker-)?compose(\.[\w-]+)?\.ya?ml$", base, re.I):
            check_docker(path, text)
        if re.match(r"\.github/workflows/[^/]+\.ya?ml$", path):
            check_workflow(path, text)
    if findings["error"]:
        print(f"repo-policy: {findings['error']} blocking finding(s)")
        sys.exit(1)
    print("repo-policy: all checks passed")


if __name__ == "__main__":
    main()
