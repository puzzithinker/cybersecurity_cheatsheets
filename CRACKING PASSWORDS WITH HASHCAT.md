| **Command** | **Description** |
| --------------|-------------------|
| `pip install hashid` | Install the `hashid` tool |
| `hashid <hash>` OR `hashid <hashes.txt>` | Identify a hash with the `hashid` tool |
| `hashcat --example-hashes` | View a list of `Hashcat` hash modes and example hashes |
| `hashcat -b -m <hash mode>` | Perform a `Hashcat` benchmark test of a specific hash mode |
| `hashcat -b` | Perform a benchmark of all hash modes |
| `hashcat -O` | Optimization: Increase speed but limit potential password length |
| `hashcat -w 3` | Optimization: Use when Hashcat is the only thing running, use 1 if running hashcat on your desktop.  Default is 2 |
| `hashcat -a 0 -m <hash type> <hash file> <wordlist>` | Dictionary attack |
| `hashcat -a 1 -m <hash type> <hash file> <wordlist1> <wordlist2>` | Combination attack |
| `hashcat -a 3 -m 0 <hash file> -1 01 'ILFREIGHT?l?l?l?l?l20?1?d'` | Sample Mask attack |
| `hashcat -a 7 -m 0 <hash file> -1=01 '20?1?d' rockyou.txt` | Sample Hybrid attack |
| `crunch <minimum length> <maximum length> <charset> -t <pattern> -o <output file>` | Make a wordlist with `Crunch` |
| `python3 cupp.py -i` | Use `CUPP` interactive mode |
| `kwp -s 1 basechars/full.base keymaps/en-us.keymap  routes/2-to-10-max-3-direction-changes.route` | `Kwprocessor` example |
| `cewl -d <depth to spider> -m <minimum word length> -w <output wordlist> <url of website>` | Sample `CeWL` command |
| `hashcat -a 0 -m 100 hash rockyou.txt -r rule.txt` | Sample `Hashcat` rule syntax |
| `./cap2hccapx.bin input.cap output.hccapx` | `cap2hccapx` syntax |
| `hcxpcaptool -z pmkidhash_corp cracking_pmkid.cap ` | `hcxpcaptool`syntax |