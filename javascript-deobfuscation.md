# JavaScript Deobfuscation

JavaScript is commonly obfuscated in web apps (client-side logic hiding), malware droppers, skimmers, and trackers. Goal: beautify, unpack, simplify, and recover meaningful logic.

## Quick Workflow (2026)

1. View source (`Ctrl+U`) or DevTools Sources tab.
2. **Beautify** first (unminify).
3. Run automated deobfuscators.
4. Manual: CyberChef recipes, browser console eval tricks, or local Node.
5. For heavy obfuscation (obfuscator.io, VM-based): use specialized unpackers + LLM assistance if available.

## Commands & Tools

| Command / Tool | Description |
|----------------|-------------|
| `curl -s http://target/app.js \| head -c 500` | Fetch suspicious JS |
| `js-beautify -o clean.js obfuscated.js` | CLI beautify (npm i -g js-beautify) |
| `cat obfuscated.js \| xxd -p \| tr -d '\n'` | Quick hex view |
| Browser: F12 → Sources → {} (pretty print) | Built-in beautify |
| CyberChef "From Base64", "JavaScript Beautify", "Generic Code Beautify" | Swiss-army knife for layers |

## Popular Online Deobfuscators (2026)

- [deobfuscate.io](https://deobfuscate.io/) — Excellent general-purpose, detects common patterns (string array, etc.)
- [de4js](https://lelinhtinh.github.io/de4js/) — Auto decode + unpacker
- [UnPacker](https://matthewfl.com/unPacker.html) — Good for packed/eval
- [JSNice](http://www.jsnice.org/) — ML-renaming variables
- [Prettier](https://prettier.io/playground/) or Beautifier.io
- CyberChef (https://gchq.github.io/CyberChef/)

Local / Advanced:
- REstringer (https://github.com/HumanSecurity/restringer)
- Webcrack or deobfuscator (npm)
- Node + `vm` to step through

## Common Obfuscation Techniques & Bypasses

- **String array + encoding** (base64, rot13, hex, unicode escapes): Decode array entries manually or with script.
- `eval` / `Function` / `setTimeout(..., "code")`: Replace with `console.log` or use debugger breakpoints.
- Control flow flattening / opaque predicates: Harder; use symbolic execution or tools like Synchrony.
- Minification only: Just beautify.
- Polyglot / mixed: Extract the JS portion first.

Example simple decode snippet (browser console or Node):
```js
// After beautify
const _0xabc = ['hello', 'world'];
function _0xdef(a) { return _0xabc[a]; }
console.log(_0xdef(0) + ' ' + _0xdef(1));
```

## More Practical Deobfuscation Examples

**Browser console quick wins:**
```js
// Pretty print already loaded script
copy(document.scripts[0].innerHTML)   // then paste into beautifier

// Decode common patterns
atob('base64string')
String.fromCharCode(72,101,108,108,111)
```

**Node.js local deobfuscation:**
```bash
# Install
npm install -g js-beautify deobfuscate

# Run
js-beautify -o clean.js obfuscated.js
deobfuscate -i heavy.js -o clean.js
```

**CyberChef recipe example (copy-paste into CyberChef):**
- From Base64 → To Hex → Generic Code Beautify → JavaScript Beautify

**Deobfuscate.io usage:**
1. Paste minified/obfuscated code
2. Click "Deobfuscate"
3. Repeat if multiple layers

**Handling packed / eval-heavy:**
- Search for `eval(` and replace temporarily with `console.log(` or `window.DEBUG=`
- Use debugger; statement + step through in DevTools Sources
- For obfuscator.io: often need multiple passes through de4js + manual array resolution

**Extracting from HTML page:**
```bash
curl -s https://target/app.js | grep -oP 'eval\(.+?\)' | head -5
```

## 2026 Notes

- LLM-powered tools (e.g. CASCADE research at Google) and local LLMs can help with renaming + logic recovery.
- For bug bounties / web: focus on interesting client-side logic (auth, payments, tracking pixels).
- Malware JS: Combine with static analysis (VirusTotal, any.run) + dynamic (browser sandbox).
- Always test recovered payloads in isolated env.

## Misc

- `Ctrl+Shift+I` (or F12) → Console for quick `JSON.stringify` or `atob()`.
- For very large files use VS Code + Prettier extension.

References: HackTricks JS section, PortSwigger, deobfuscate.io blog, REstringer repo.
