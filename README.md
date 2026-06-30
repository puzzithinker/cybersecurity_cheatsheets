# Cybersecurity Cheatsheets

A practical, well-organized collection of cheatsheets for penetration testers, red teamers, and security enthusiasts. Covers reconnaissance, web attacks, exploitation, privilege escalation, pivoting, password attacks, and more.

**Updated for 2026**: Modern tools (Nuclei, Ligolo-ng, ffuf enhancements, current Hashcat v7+, updated bypasses), latest techniques, and references to current best practices, CVEs, and tooling trends as of mid-2026.

## Quick Start

```bash
# Clone
git clone https://github.com/your-org/cybersecurity_cheatsheets.git
cd cybersecurity_cheatsheets

# Setup a Kali environment (recommended)
chmod +x kali-pentest-setup.sh
sudo ./kali-pentest-setup.sh
```

Common wordlists live at:
- `/usr/share/seclists/` (or `/opt/SecLists` after setup)
- `/usr/share/wordlists/rockyou.txt` (often gzipped: `gunzip rockyou.txt.gz`)

## Index

### Reconnaissance & Information Gathering
- [web-information-gathering.md](web-information-gathering.md) — WHOIS, DNS, subdomain enum (passive + active), cert transparency, crawling, virtual hosts.

### Web Application Testing
- [ffuf-web-attacks.md](ffuf-web-attacks.md) — Fast web fuzzing with ffuf (dirs, params, vhosts, subdomains, recursion). Wordlists and tips.
- [web-attacks.md](web-attacks.md) — HTTP verb tampering, IDOR, XXE, and other common web vulns.
- [web-requests.md](web-requests.md) — cURL, APIs, browser devtools.
- [cross-site-scripting-xss.md](cross-site-scripting-xss.md) — XSS payloads (reflected, stored, DOM), bypasses, tools (Dalfox, etc.).
- [authentication-attacks.md](authentication-attacks.md) — Broken authentication, fuzzing logins, session issues.
- [file-upload-attacks.md](file-upload-attacks.md) — Upload bypasses, web shells, restricted uploads.
- [command-injection.md](command-injection.md) — OS command injection, filter & blacklist bypasses (Linux/Windows).

### Exploitation Frameworks & Tools
- [metasploit-framework.md](metasploit-framework.md) — msfconsole basics, Meterpreter, common workflows.
- [sqlmap-essentials.md](sqlmap-essentials.md) — SQLMap usage for automated SQLi.
- [sql-injection-fundamentals.md](sql-injection-fundamentals.md) — Manual SQLi techniques (UNION, blind, time-based, etc.).

### Post-Exploitation & Pivoting
- [pivoting-tunneling-port-forwarding.md](pivoting-tunneling-port-forwarding.md) — SSH tunnels, SOCKS, chisel, **Ligolo-ng** (2026 preferred for transparent pivots), Metasploit, Socat, rpivot legacy notes, dnscat2.
- [file-transfers.md](file-transfers.md) — Download/upload methods across Windows, Linux, web (certutil, bitsadmin, PowerShell, curl, wget, php, scp, etc.).

### Active Directory & Lateral Movement
- [active-directory-attacks.md](active-directory-attacks.md) — Kerberoasting, AS-REP roasting, Pass-the-Hash/Ticket, Golden/Silver tickets, DCSync, ACL abuse, BloodHound workflows, lateral movement (WMI, WinRM, SMB), persistence.

### Privilege Escalation
- [linux-privilege-escalation.md](linux-privilege-escalation.md) — Enumeration, SUID, sudo misconfigs, cron, PATH hijack, kernel exploits (incl. recent 2025 CVEs notes), containers (docker/LXD), LinPEAS/pspy.
- [windows-privilege-escalation.md](windows-privilege-escalation.md) — Initial enum, token impersonation, service exploits, credential theft, AD-specific.
- [powershell-redteam.md](powershell-redteam.md) — PowerShell for recon (BloodHound, PowerView), priv esc, C2.

### Password Attacks & Cracking
- [password-attacks.md](password-attacks.md) — Online attacks (hydra, medusa), mutations, SMB/WinRM/RDP, local attacks.
- [hashcat-password-cracking.md](hashcat-password-cracking.md) — Hash identification, modes, attacks (dict, mask, rules, hybrid), wordlist gen (cewl, crunch), 2026 hardware notes (RTX 50-series), rules.

### Fundamentals & Misc
- [linux-fundamentals.md](linux-fundamentals.md) — Essential Linux commands for pentesters.
- [web-proxies.md](web-proxies.md) — Burp Suite, OWASP ZAP, Firefox shortcuts.
- [javascript-deobfuscation.md](javascript-deobfuscation.md) — Common encodings, beautifiers, JS analysis tips (malware/web).
- [attacking-common-applications.md](attacking-common-applications.md) — CMS (WordPress, Joomla, Drupal), Tomcat, Jenkins, Splunk, etc.
- [attacking-common-services.md](attacking-common-services.md) — FTP, SMB, SQL, RDP, DNS, Email, SNMP.

## 2026 Updates & Trends Highlighted
- **Pivoting**: Ligolo-ng (TUN-based transparent networking) now recommended alongside/ over older chisel for most internal network work.
- **Web**: Heavy use of `nuclei` for fast vuln scanning alongside ffuf + Burp. Focus on API security, GraphQL (where relevant), parser differentials, modern auth bypasses.
- **Cracking**: Hashcat 7.x, rule chaining, PassGAN/AI hybrids + traditional. Always start with rockyou.txt + custom rules. Updated Hive-style timing tables reflect faster GPUs.
- **PrivEsc**: Continued emphasis on enumeration automation (linPEAS, pspy). Watch for kernel + sudo CVEs (e.g., 2025 chroot-related issues). Container escapes remain hot.
- **General**: SecLists still king. Add `nuclei`, `ffuf`, Go-based tools, `httpx`, `katana` to recon pipelines.

## Contributing
Pull requests welcome. Focus on:
- Accurate, tested commands
- Adding 2026-relevant techniques/bypasses (cite sources)
- Consistent formatting (tables preferred for commands)
- References and further reading

## References & Inspiration
- HackTheBox Academy / HTB
- HackTricks (https://book.hacktricks.xyz)
- PayloadsAllTheThings
- PortSwigger Web Security Academy & Research (top web hacking techniques)
- PEASS-ng / LinPEAS
- Official tool docs (Hashcat, sqlmap, ffuf, Nuclei, Ligolo-ng)
- Community notes from OSCP, CRTP, etc.

**Use responsibly and only on systems you own or have explicit authorization to test.**

---

*Maintained as a living reference — contributions keep it current.*
