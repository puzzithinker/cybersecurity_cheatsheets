# Web Requests & APIs

Mastering HTTP clients is fundamental for manual testing and scripting.

## cURL Essentials

```bash
curl -h
curl https://target.com
curl -s -L -o file.html https://target.com
curl -k https://self-signed
curl -v https://target          # verbose headers + info
curl -I https://target          # HEAD only (headers)
curl -i ...                     # headers + body
```

**Headers & Auth**
```bash
curl -H "User-Agent: Mozilla/5.0" -H "X-Custom: foo" https://target
curl -u admin:pass https://target
curl -H "Authorization: Bearer eyJ..." https://target/api
curl -b "session=abc123; other=val" ...
curl -c cookies.txt -b cookies.txt ...   # persist cookies
```

**Methods & Data**
```bash
curl -X POST -d 'user=admin&pass=secret' -H "Content-Type: application/x-www-form-urlencoded" https://target/login
curl -X POST -d '{"key":"value"}' -H "Content-Type: application/json" https://target/api
curl -X PUT ...
curl -X DELETE ...
```

**Proxy & Advanced**
```bash
curl --proxy http://127.0.0.1:8080 -k https://target
curl --resolve target.com:443:1.2.3.4 https://target.com
```

## Working with APIs

REST examples (above in file).

GraphQL quick test:
```bash
curl -X POST -H "Content-Type: application/json" -d '{"query":"{ __schema { types { name } } }"}' https://target/graphql
```

Use `jq` for parsing JSON responses:
```bash
curl -s https://target/api | jq '.users[] | .id'
```

## Browser DevTools (Critical for Manual)

| Shortcut | Action |
|----------|--------|
| F12 / Ctrl+Shift+I | Open DevTools |
| Ctrl+Shift+E | Network tab |
| Ctrl+Shift+K | Console |
| Right-click request → Copy → Copy as cURL (bash) / fetch / PowerShell |  |

Network tab filters: `method:POST`, `domain:api`, status 200 etc. Preserve log + disable cache.

## Scripting Tips (2026)

- Prefer `httpx` + Python `requests` / `httpx` lib for automation.
- Burp "Copy as curl" → paste & modify.
- Use `-w "%{http_code} %{size_download}\n"` for stats.
- For large bodies or files: `--data-binary @file.bin`

### More cURL Examples

```bash
# Follow redirects + show final effective URL
curl -sL -w "%{url_effective}\n" -o /dev/null https://target

# Send raw request from file (great with Burp copy)
curl -K raw-request.txt

# Upload file + custom filename
curl -F 'file=@/path/to/shell.php;filename=shell.php.jpg' http://target/upload

# Multiple headers + bearer + verbose
curl -H "Authorization: Bearer $TOKEN" \
     -H "X-Requested-With: XMLHttpRequest" \
     -H "Accept: application/json" \
     -v https://target/api/user/1

# Download with resume support
curl -C - -O https://target/large.iso
```

### Python httpx / requests Examples

```python
import httpx

# Simple with proxy (Burp)
proxies = {"http://": "http://127.0.0.1:8080", "https://": "http://127.0.0.1:8080"}
r = httpx.get("https://target", verify=False, proxies=proxies)

# POST JSON + custom headers
data = {"username": "admin", "password": "test"}
headers = {"Content-Type": "application/json"}
r = httpx.post("https://target/login", json=data, headers=headers)
```

References: everything.curl.dev , MDN HTTP, Burp docs.
