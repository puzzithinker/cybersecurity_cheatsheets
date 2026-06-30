# ffuf — Fast Web Fuzzer (2026 Edition)

ffuf remains one of the fastest and most flexible web fuzzers. Use it for content discovery, parameter discovery, virtual host, and more.

## Core Commands

```bash
ffuf -h
```

### Directory & File Discovery
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ \
  -u https://target/FUZZ -mc 200,204,301,302,401,403 -t 50
```

### Extensions
```bash
ffuf -w wordlist.txt:FUZZ -u https://target/indexFUZZ -e .php,.asp,.aspx,.jsp
```

### Recursive
```bash
ffuf -w dirs.txt:FUZZ -u https://target/FUZZ -recursion -recursion-depth 2 -e .php,.html
```

### Subdomain
```bash
ffuf -w subdomains.txt:FUZZ -u https://FUZZ.target.com/ -H "Host: FUZZ.target.com" -mc 200,301
```

### Virtual Host
```bash
ffuf -w vhosts.txt:FUZZ -u http://target/ -H "Host: FUZZ.target.com" -fs 0
```

### Parameter Discovery (GET)
```bash
ffuf -w params.txt:FUZZ -u "https://target/search?FUZZ=test" -mc all -fr "error|invalid"
```

### POST Parameter / Value
```bash
ffuf -w values.txt:FUZZ -u https://target/login -X POST \
  -d "user=admin&pass=FUZZ" -H "Content-Type: application/x-www-form-urlencoded" \
  -mc 302 -fs 0
```

## Important Flags (2026 Usage)

| Flag | Use |
|------|-----|
| `-mc 200,301,302,403` | Match these status codes |
| `-fc 404` | Filter (exclude) codes |
| `-fs 1234` | Filter by response size (bytes) |
| `-fr "not found\|error"` | Regex filter on body |
| `-t 100` | Threads (be nice to targets) |
| `-p 0.2` | Delay between requests (seconds) |
| `-rate 50` | Limit req/s |
| `-recursion -recursion-depth 3` | Depth limited recursion |
| `-e .php,.txt` | Extensions |
| `-H "X-Forwarded-For: 127.0.0.1"` | Custom headers |
| `-b "session=abc"` | Cookies |
| `-o results.html -of html` | Output formats (json, csv, html, md) |
| `-v` | Verbose (shows full URL on hit) |

## Wordlists (Common 2026 Locations)

```bash
/usr/share/seclists/Discovery/Web-Content/
  directory-list-2.3-small.txt
  common.txt
  raft-*.txt
/usr/share/seclists/Discovery/Web-Content/api/
  api-endpoints.txt
  api-keys.txt
/usr/share/seclists/Discovery/DNS/
  subdomains-top1million-5000.txt
```

Generate numbers:
```bash
seq 1 1000 > ids.txt
```

## Tips & Best Practices

- Always filter noise first (baseline a known 404).
- Combine with `nuclei` for vuln detection after discovery.
- Use `-ac` (autocalibrate) to reduce false positives.
- For APIs: fuzz JSON keys with `-H "Content-Type: application/json" -d '{"FUZZ":"test"}'`
- Rate limit + jitter when testing production.
- Pipe ffuf output to other tools: `ffuf ... -o /dev/stdout -of json | jq ...`

## Example Full Recon Pipeline Snippet

```bash
# sub + dir + params
ffuf -w subs.txt:FUZZ -u https://FUZZ.example.com/
ffuf -w dirs.txt:FUZZ -u https://example.com/FUZZ
ffuf -w params.txt:FUZZ -u 'https://example.com/api?FUZZ=1'
nuclei -u https://example.com -t http/ -silent
```

## More Practical Examples

### API Endpoint Discovery
```bash
# Fuzz common API paths + versions
ffuf -w api-endpoints.txt:FUZZ -u https://api.target.com/v1/FUZZ \
  -H "Authorization: Bearer $TOKEN" \
  -mc 200,201,204 -fs 0 -o api.json -of json

# JSON body parameter fuzzing (POST)
ffuf -w params.txt:FUZZ -u https://target.com/api/search \
  -X POST -H "Content-Type: application/json" \
  -d '{"query":"test","FUZZ":"admin"}' \
  -mr "results|data" -t 20
```

### Header & Virtual Host Fuzzing with Filters
```bash
# Host header bypass + internal routing
ffuf -w internal-hosts.txt:FUZZ -u http://target.com/ \
  -H "Host: FUZZ.internal.corp" -H "X-Forwarded-For: 127.0.0.1" \
  -fs 0 -mc 200,301

# Custom header injection testing
ffuf -w headers.txt:FUZZ -u https://target.com/ \
  -H "FUZZ: value" -H "X-Custom: test" -v
```

### Advanced Filtering & Matching
```bash
# Size + status + regex combo (very effective)
ffuf -w wordlist.txt:FUZZ -u https://target/FUZZ \
  -mc 200,301,302 -fs 1234,5678 -fr "not found|error|login" \
  -ac -o results.csv -of csv

# Match on response time (slow pages)
ffuf -w dirs.txt:FUZZ -u https://target/FUZZ \
  -mr "200" -mt 1500   # responses taking >1.5s
```

### Rate Limiting / WAF Evasion
```bash
ffuf -w common.txt:FUZZ -u https://target/FUZZ \
  -t 5 -p 1.5 -rate 10 \
  -H "X-Forwarded-For: 10.0.0.$((RANDOM%255))" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

### Clusterbomb Style (multiple positions)
```bash
# Two FUZZ positions (like Burp clusterbomb)
ffuf -w users.txt:USER -w passwords.txt:PASS \
  -u https://target/login \
  -X POST -d "username=USER&password=PASS" \
  -mc 302 -fs 0
```

### Post-processing
```bash
# Extract only live interesting paths
ffuf -w dirs.txt:FUZZ -u https://target/FUZZ -o /tmp/ffuf.json -of json -silent
jq -r '.results[] | select(.status == 200) | .url' /tmp/ffuf.json | sort -u
```

References: ffuf GitHub, SecLists, ProjectDiscovery tooling.
