rule Guard_JS_Eval_Of_Decoded_Payload
{
  meta:
    description = "eval/Function/vm executing a base64-, hex- or charcode-decoded string"
  strings:
    $a = /\beval\s*\(\s*(atob|Buffer\.from|unescape|decodeURIComponent|String\.fromCharCode)\s*\(/
    $b = /new\s+Function\s*\(\s*(atob|Buffer\.from|String\.fromCharCode)\s*\(/
    $c = /vm\.runIn(New|This)?Context\s*\(\s*(atob|Buffer\.from)\s*\(/
    $d = /Function\.constructor\s*\(/
    $e = /unescape\s*\(\s*['"]%u[0-9a-fA-F]{4}%u/
  condition:
    any of them
}

rule Guard_JS_Eval_Of_Remote_Response
{
  meta:
    description = "code downloaded at runtime and executed (BeaverTail / loader pattern)"
  strings:
    $a = /(eval|new\s+Function|Function)\s*\(\s*[a-zA-Z_$][\w$]*\.(data|body|text)\b/
    $b = /\.then\s*\(\s*(eval|Function)\s*\)/
    $c = /new\s+Function\s*\(\s*['"]require['"]\s*,/
  condition:
    any of them
}

rule Guard_JS_Executes_Asset_File
{
  meta:
    description = "reads a font/image/asset file and executes or requires it as code"
  strings:
    $read = /(readFileSync|readFile|createReadStream)\s*\([^)]{0,200}\.(woff2?|ttf|otf|eot|png|jpe?g|gif|ico|svg|webp|mp3|mp4|pdf|txt|dat|bin)\b/
    $req = /require\s*\(\s*['"`][^'"`]+\.(woff2?|ttf|otf|eot|png|jpe?g|gif|ico|webp|txt|dat|bin)['"`]\s*\)/
    $exec1 = /\beval\s*\(/
    $exec2 = /new\s+Function\b/
    $exec3 = /vm\.(runIn|Script|compileFunction)/
    $exec4 = "child_process"
    $exec5 = /\bnode\s+[^\n'"]+\.(woff2?|ttf|otf|eot|png|jpe?g|gif|ico|svg|webp)\b/
  condition:
    ($read and any of ($exec1, $exec2, $exec3, $exec4)) or $exec5 or ($req and any of ($exec1, $exec2, $exec3, $exec4))
}

rule Guard_NPM_Install_Hook_Downloads_Code
{
  meta:
    description = "package.json lifecycle hook that fetches, pipes or evals code"
  strings:
    $hook = /"(pre|post)?(install|prepare|prepublish)"\s*:\s*"[^"]*(curl |wget |Invoke-WebRequest|iwr |powershell|node -e|node --eval|\| *(ba)?sh|base64)[^"]*"/
  condition:
    $hook
}

rule Guard_Remote_Script_Piped_To_Shell
{
  meta:
    description = "child_process running a downloaded script through a shell"
  strings:
    $cp = "child_process"
    $pipe = /(curl|wget)[^\n'"`]{0,200}\|\s*(ba|z)?sh\b/
  condition:
    $cp and $pipe
}

rule Guard_Reverse_Shell
{
  meta:
    description = "reverse shell constructs"
  strings:
    $devtcp = /\/dev\/tcp\/[0-9a-zA-Z.\-]+\/[0-9]{2,5}/
    $nc = /\bnc(at)?\s+(-[a-z]*e\s+\/bin\/(ba)?sh|[^\n]{0,80}-e\s+\/bin\/(ba)?sh)/
    $bashi = /bash\s+-i\s*>&/
    $socat = /socat\s+[^\n]{0,80}exec:/ nocase
    $pysock = /python[0-9.]*\s+-c\s+['"][^'"]{0,200}import\s+socket/
    $sock = "net.Socket"
    $spawnsh = /spawn\s*\(\s*['"`](\/bin\/)?(ba)?sh['"`]/
    $pipe = /\.pipe\s*\(\s*[a-zA-Z_$][\w$]*\.stdin\s*\)/
  condition:
    $devtcp or $nc or $bashi or $socat or $pysock or ($sock and ($spawnsh or $pipe))
}

rule Guard_Destructive_Command
{
  meta:
    description = "wipes disks, root, home, or forks the machine to death"
  strings:
    $rm = /rm\s+-(rf|fr|r\s+-f|f\s+-r|-recursive\s+--force)\s+(--no-preserve-root\s+)?["']?(\/\*?|~\/?\*?|\$HOME\/?\*?|\$\{HOME\}|\*)["']?(\s|$|;|&|\|)/
    $npr = "--no-preserve-root"
    $dd = /dd\s+if=[^\n]{0,80}of=\/dev\/(sd|nvme|hd|xvd|vd|disk)/
    $mkfs = /\bmkfs(\.[a-z0-9]+)?\s+\/dev\//
    $fork = /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/
    $win1 = /(rd|rmdir|del)\s+\/s\s+\/q\s+[a-zA-Z]:\\/ nocase
    $win2 = /Remove-Item\s+[^\n]{0,60}-Recurse[^\n]{0,30}-Force[^\n]{0,30}[a-zA-Z]:\\/ nocase
    $win3 = /format\s+[a-zA-Z]:\s*\/[qy]/ nocase
    $chmod = /chmod\s+-R\s+0?777\s+\/(\s|$)/
    $jsrm = /(rmSync|rimraf(\.sync)?|removeSync|emptyDirSync)\s*\(\s*(os\.homedir\(\)|process\.env\.(HOME|USERPROFILE)|['"`](\/|~|[A-Za-z]:\\\\)['"`])/
  condition:
    any of them
}

rule Guard_Credential_Theft
{
  meta:
    description = "reads credential stores, browser profiles or crypto wallets"
  strings:
    $read = /(readFileSync|readFile|readdirSync|readdir|createReadStream|copyFileSync|copyFile|existsSync|globSync|fs\.promises)\b/
    $p1 = /\.ssh\/(id_[a-z0-9]+|authorized_keys|known_hosts)/
    $p2 = /\.aws\/credentials/
    $p3 = /\.config\/gcloud/
    $p4 = /\.kube\/config/
    $p5 = /\.docker\/config\.json/
    $p6 = /\.git-credentials/
    $p7 = "Login Data"
    $p8 = "Local State"
    $p9 = /Local Extension Settings/
    $p10 = "nkbihfbeogaeaoehlefnkodbefgpgknn"
    $p11 = "bfnaelmomeimhlpmgjnjophhpkkoljpa"
    $p12 = "ibnejdfjmmkpcnlpebklmnkoeoihofec"
    $p13 = /\/etc\/(shadow|passwd)/
    $p14 = /Library\/Keychains|login\.keychain/
    $p15 = /\.mozilla\/firefox|Firefox\/Profiles/
    $p16 = /(Google\/Chrome|BraveSoftware|Microsoft\/Edge)\/(User Data|Default)/
    $p17 = /\.npmrc['"`]/
    $p18 = /Exodus|Electrum|atomic\/Local Storage|solana\/id\.json/
  condition:
    $read and any of ($p*)
}

rule Guard_Persistence
{
  meta:
    description = "installs itself to run again: shell profiles, cron, services, autostart, registry"
  strings:
    $write = /(writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|>>\s*~|>>\s*\$HOME|tee\s+-a)/
    $t1 = /\.(bashrc|zshrc|bash_profile|profile|zprofile)\b/
    $t2 = /authorized_keys/
    $t3 = /\/etc\/(cron|sudoers|systemd|rc\.local|ld\.so\.preload)/
    $t4 = /\.config\/(autostart|systemd\/user)/
    $t5 = /Library\/LaunchAgents|Library\/LaunchDaemons/
    $t6 = /Start Menu\\\\Programs\\\\Startup|AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu/ nocase
    $c1 = /crontab\s+(-l|-)/
    $c2 = /schtasks\s+\/create/ nocase
    $c3 = /reg\s+add\s+[^\n]{0,80}\\Run\b/ nocase
    $c4 = /systemctl\s+(--user\s+)?enable/
    $c5 = /code\s+--install-extension/
    $c6 = /npm\s+(i|install)\s+(-g|--global)\b/
  condition:
    ($write and any of ($t*)) or any of ($c*)
}

rule Guard_Exfil_Webhook_Endpoint
{
  meta:
    description = "hardcoded Discord/Telegram endpoints commonly used for credential exfiltration"
  strings:
    $discord = /discord(app)?\.com\/api\/webhooks\/[0-9]{10,}/
    $telegram = /api\.telegram\.org\/bot[0-9]{6,}:/
  condition:
    any of them
}

rule Guard_Crypto_Miner
{
  meta:
    description = "cryptocurrency miner indicators"
  strings:
    $s1 = "stratum+tcp://" nocase
    $s2 = "stratum+ssl://" nocase
    $s3 = "xmrig" nocase
    $s4 = "coinhive" nocase
    $s5 = "cryptonight" nocase
    $s6 = "cpuminer" nocase
    $s7 = /(nanopool|minexmr|supportxmr|hashvault|2miners|f2pool|nicehash)\.(org|com|pro|net)/ nocase
  condition:
    any of them
}

rule Guard_JS_Obfuscator_Output
{
  meta:
    description = "heavy javascript-obfuscator style _0x identifiers in a source file"
  strings:
    $hex = /_0x[a-f0-9]{4,6}/
  condition:
    #hex > 100
}

rule Guard_Anti_Analysis
{
  meta:
    description = "sandbox/VM/debugger evasion typical of malware droppers"
  strings:
    $vm1 = /(VBOX|VirtualBox|VMware|QEMU|Xen|sandbox)['"`][^\n]{0,80}(includes|indexOf|test|match)/ nocase
    $vm2 = /(os\.cpus\(\)\.length\s*<\s*[1-3]\b|os\.totalmem\(\)\s*<)/
    $dbg = /setInterval\s*\(\s*(function\s*\(\)\s*\{|\(\)\s*=>\s*\{?)\s*debugger/
    $geo = /(Intl\.DateTimeFormat\(\)\.resolvedOptions\(\)\.timeZone|process\.env\.LANG)[^\n]{0,80}(===|!==|includes)\s*\(?['"`](ru|uk|by|kz|Europe\/Moscow)/ nocase
  condition:
    any of them
}

rule Guard_Config_Injector_Family
{
  meta:
    description = "config-file injector seen in real incidents: global.i/global.r markers, unicode-escaped core modules"
  strings:
    $g1 = /global\.i\s*=\s*['"][A-Za-z0-9-]{2,16}['"]/
    $g2 = /global\.r\s*=\s*require\b/
    $g3 = /global\.m\s*=\s*module\b/
    $u = /require\s*\(\s*["'](\\u00[0-9a-fA-F]{2}){3,}["']\s*\)/
  condition:
    any of them
}

rule Guard_Git_History_Tampering
{
  meta:
    description = "script that silently amends and force-pushes commits, disables hooks/credential prompts or fakes commit time"
  strings:
    $amend = /commit\s+[^\n]{0,40}--amend/
    $noverify = "--no-verify"
    $force = /push\s+[^\n]{0,60}(\s-[a-zA-Z]*f[a-zA-Z]*\b|--force)/
    $cred = /credential\.helper\s*=?\s*["']{2}/
    $date = /(^|\n)\s*(date|time)\s+%[A-Za-z_]+%/
    $fake = /GIT_(AUTHOR|COMMITTER)_DATE\s*=/
  condition:
    ($amend and ($force or $noverify or $date or $fake)) or $cred
}
