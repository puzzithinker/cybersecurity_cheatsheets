# Hashcat Password Cracking (Updated 2026)

World's fastest password cracker. Hashcat 7.1+ as of late 2025.

## Identification & Setup

```bash
pipx install hashid   # or apt
hashid '$1$abc$def'   # or hashid hashes.txt
hashcat --example-hashes | grep -i bcrypt
```

```bash
hashcat -b -m 0          # benchmark specific mode (MD5 here)
hashcat -b               # full benchmark
```

## Attack Modes

| Mode (`-a`) | Name | Example |
|-------------|------|---------|
| 0 | Dictionary | `hashcat -a 0 -m 1000 hashes rockyou.txt` |
| 1 | Combination | `hashcat -a 1 hashes wl1.txt wl2.txt` |
| 3 | Mask | `hashcat -a 3 -m 0 hashes ?u?l?l?l?l?d?d?d` |
| 6 | Hybrid (word + mask) | `hashcat -a 6 hashes rockyou.txt ?d?d?d` |
| 7 | Hybrid (mask + word) | `hashcat -a 7 hashes ?d?d?d rockyou.txt` |

## Common Optimizations

```bash
hashcat -O               # Optimize (shorter passwords)
hashcat -w 3             # Workload profile: 3 = high (dedicated rig); 1 = desktop
hashcat --status --status-timer 10
hashcat -S               # Old slow candidates (rarely needed)
```

## Wordlist Generation (2026)

```bash
# CeWL (crawl site)
cewl -d 3 -m 5 -w custom.txt https://target.com

# Crunch
crunch 8 10 -f charset.lst mixalpha-numeric-symbol14 -o list.txt

# CUPP (personal profiling)
python3 cupp.py -i

# kwProcessor (keyboard walks)
kwp -s 1 basechars/full.base keymaps/en-us.keymap routes/2-to-10-max-3-direction-changes.route > walks.txt
```

## Rules (Extremely Powerful)

```bash
hashcat -a 0 -m 1000 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat ... -r rules/rockyou-30000.rule
# Chain: -r rule1.rule -r rule2.rule
```

Popular rule files in SecLists / hashcat: best64, rockyou-30000, d3ad0ne, T0XIC, etc.

## Wireless (WPA/WPA2)

```bash
hcxpcapngtool -o handshake.hc22000 capture.pcapng
hashcat -m 22000 -a 0 handshake.hc22000 wordlist.txt
# PMKID
hcxpcapngtool -o pmkid.hc22000 capture.pcapng --pmkid
```

## 2026 Practical Advice

- **Always** start with `rockyou.txt` (or rockyou2024+ variants if available).
- Use rules heavily before moving to masks or huge lists.
- Hardware: modern high-end (RTX 5090 class) dramatically faster per the Hive Systems password table updates. 12x GPU rigs common in serious cracking.
- AI-assisted: PassGAN or similar can generate candidate lists; combine with traditional.
- Sanitize wordlists: remove too-short or irrelevant entries.
- Use `--show` and potfile management for efficiency.
- For NTLM/AD: prefer hashcat over JtR for speed on GPU.

```bash
# Resume
hashcat -a 0 hashes rockyou.txt --restore
```

Example full simple run:
```bash
hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule -w 3 -O --status
```

## More Real-World Examples

### Hash Identification + Cracking Flow
```bash
hashid '$2b$12$...'          # bcrypt
hashcat --example-hashes | grep -B2 bcrypt
hashcat -m 3200 hashes.txt rockyou.txt -r rules/best64.rule
```

### Mask Attacks (very effective)
```bash
# Company-style passwords
hashcat -a 3 -m 1000 hashes.txt ?u?l?l?l?l?d?d?d?d   # Summer2024 style
hashcat -a 3 -m 1000 hashes.txt -1 ?u?l ?u?l?l?l?d?d?d?1   # custom charset

# Hybrid
hashcat -a 6 -m 0 hashes.txt rockyou.txt ?d?d?d
```

### Rule Chaining + Generating Candidates
```bash
# Generate candidates only (no cracking)
hashcat -a 0 wordlist.txt -r rules/rockyou-30000.rule --stdout > mutated.txt

# Two rule files
hashcat -a 0 hashes rockyou.txt -r rules/best64.rule -r rules/append_special.rule
```

### Cracking Specific Formats
```bash
# NTLM (Windows)
hashcat -m 1000 ntlm.hash rockyou.txt

# SHA256 (Linux)
hashcat -m 1400 sha256.hash rockyou.txt

# WPA2 / PMKID
hcxpcapngtool -o handshake.hc22000 capture.pcapng
hashcat -m 22000 handshake.hc22000 rockyou.txt -w 3

# ZIP / 7z / Office
zip2john file.zip > zip.hash
hashcat -m 13600 zip.hash rockyou.txt
```

### Performance & Management
```bash
# Show cracked so far
hashcat -m 1000 hashes.txt --show

# Restore session
hashcat --restore

# Benchmark your hardware
hashcat -b -m 22000
```

References: hashcat.net, Hive Systems Password Table 2025/2026, Reddit r/netsec / r/hacking cracking guides.
