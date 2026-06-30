# Web Proxies & Interception

Essential tools for intercepting, modifying, and replaying HTTP/S traffic.

## Burp Suite (Primary Tool)

Key features: Proxy, Repeater, Intruder, Decoder, Comparer, Extender (Bambdas in recent versions), Scanner (Pro).

### Useful Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+R | Send to Repeater |
| Ctrl+Shift+R | Switch to Repeater |
| Ctrl+I | Send to Intruder |
| Ctrl+Shift+I (or B) | Go to Intruder |
| Ctrl+U | URL encode selection |
| Ctrl+Shift+U | URL decode |
| Ctrl+Shift+F | Search in request/response history |
| Ctrl+T | Toggle intercept on current request (proxy) |

Tips:
- Use Match & Replace rules for global header injection (e.g. Authorization).
- Scope + Target tab to organize.
- Use Burp's "Copy as curl" or "Copy as PowerShell".
- Extensions: Auth Analyzer, Param Miner, Turbo Intruder, Logger++ , Hackvertor.

## OWASP ZAP

Free, good for automation and CI.

| Shortcut | Action |
|----------|--------|
| Ctrl+B | Toggle intercept (break) |
| Ctrl+R | Replacer |
| Ctrl+E | Encode / Decode / Hash dialog |

- Use ZAP Spider + Active Scan.
- Good HUD mode for browser.
- Scripting support (Python, JS, Groovy).

## Firefox / Browser DevTools

| Shortcut | Action |
|----------|--------|
| Ctrl+Shift+R | Hard refresh (bypass cache) |
| Ctrl+Shift+I | Open DevTools |
| Ctrl+Shift+K | Console |
| Network tab → right-click → Copy → Copy as fetch / curl |  |

Proxy config:
- FoxyProxy or manual: localhost:8080 (Burp default).
- For HTTPS: install Burp CA cert in browser (or use --ignore-certificate-errors for testing only).

## 2026 Modern Workflow

1. Browser + FoxyProxy → Burp/ZAP
2. Use `httpx` / `katana` / `nuclei` for bulk discovery outside proxy
3. Replay interesting in Burp Repeater or Caido (lightweight alternative gaining popularity)
4. For high-speed fuzz: ffuf or Turbo Intruder (not proxy for volume)

## Other Proxies & Helpers

- Caido — fast, modern, lightweight alternative to Burp.
- mitmproxy — terminal / scriptable.
- Proxychains / proxychains-ng for CLI tools through proxy.

```bash
# Send traffic from CLI through Burp
curl --proxy http://127.0.0.1:8080 -k https://target

# Or export env
export http_proxy=http://127.0.0.1:8080
export https_proxy=$http_proxy
```

### More Burp Practical Examples

- Use **Repeater** for manual testing + "Send to Intruder" for positions.
- Intruder: use "Pitchfork" for username+password pairs, "Cluster bomb" for many params.
- Match & Replace rule example: replace all `Host: target` with `Host: internal.target`.
- Logger++ extension to log everything with custom columns.
- Turbo Intruder for high-speed fuzzing inside Burp.

### ZAP Advanced Usage

```bash
# ZAP CLI automation example
zap.sh -daemon -host 127.0.0.1 -port 8090 &
zap-cli -p 8090 spider https://target
zap-cli -p 8090 active-scan -c Default -r https://target
zap-cli -p 8090 report -o report.html -f html
```

References: Official Burp docs, ZAP docs, PortSwigger Web Academy.
