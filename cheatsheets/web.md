# Cheatsheet — WEB

> Lane P2. Khung theo tier trong README mục 2.

**Công cụ:** Burp Suite, ffuf/gobuster, sqlmap, HackTricks + PayloadsAllTheThings, jwt_tool, phpggc/ysoserial.

```bash
ffuf -u http://host/FUZZ -w wordlist.txt
sqlmap -u 'http://host/?id=1' --batch --dbs
```

## T1 — SQLi / NoSQLi / IDOR / LFI / info disclosure
## T2 — XSS / CSRF / open redirect / upload bypass
## T3 — RCE injection (command, SSTI, eval)
## T4 — SSRF / XXE / LFI→RCE
## T5 — Deserialization (phpggc, pickle, ysoserial)
## T6 — Auth/token (JWT, OAuth, session)
## T7 — Logic/JS (prototype pollution, race condition)
## T8 — Chaining & bypass (WAF, request smuggling, cache poisoning)
## T9+ — GraphQL / WebSocket / CVE framework (stretch)

<!-- Dán payload đã chạy thật + link writeups/web/ -->
