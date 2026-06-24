# LucidScanner

Multi-stack web security audit tool. Built from real audits — detects target
stack (WordPress, Next.js/Vercel, Astro, Rails/Devise) and runs the
appropriate checks.

## Install (one-time)

```powershell
cd C:\Users\Administrator\lucid-scanner
pip install -r requirements.txt
```

## Run

### Interactive (easiest)

```powershell
python lucid_scanner.py
```

The script asks for the URL, runs all checks, writes a Markdown report.

### With URL as argument

```powershell
python lucid_scanner.py https://example.com
```

### Hide progress noise, save JSON too

```powershell
python lucid_scanner.py https://example.com -q --json findings.json
```

### Use a browser User-Agent (bypass Vercel/CF bot challenges on sites you own)

```powershell
python lucid_scanner.py https://example.com --browser-ua
```

### Authorized mode (only for sites you own — currently a placeholder for future write tests)

```powershell
python lucid_scanner.py https://example.com --authorized
```

## What it checks

| Phase | What |
|---|---|
| 1  | DNS records (A/MX/TXT), SPF, DMARC |
| 2  | CT-log subdomain enumeration (crt.sh + HackerTarget fallback) |
| 3  | Subdomains that bypass Cloudflare/Vercel (direct origin exposure) |
| 4  | HTTP security headers (HSTS, CSP, X-Content-Type-Options, Referrer-Policy, X-Powered-By leak) |
| 5  | TLS cert expiry |
| 6  | Stack-specific: WordPress (user enum, ?author leak, xmlrpc, password-reset oracle), Next.js/Vercel (env leaks, Vercel checkpoint), Devise (sign-up open, login form exposure) |
| 7  | Exposed config / backup files (.env, wp-config.php.bak, .git/config, etc.) |
| 8  | Hidden admin URLs (dictionary attack on common paths) |
| 9  | Safe SQL injection probes (error-based only — no destructive payloads) |
| 10 | Secret leaks in client JS (Stripe, AWS, Google, GitHub tokens) |

## Output

By default writes `report_<host>_<timestamp>.md` to your working directory.

Each finding has:
- **Severity** (Critical / High / Medium / Low / Info)
- **Evidence** (the actual response that triggered the flag)
- **Impact** (what an attacker can do)
- **Fix** (the specific remediation)

A one-line summary is also printed to stdout for chaining/scripting:
```
example.com | critical:1 high:3 medium:5 low:2 info:8
```

## Audit signature

Every request includes:
- `User-Agent: Mozilla/5.0 (LucidScanner/1.0; +safe-probes; tag=LucidScanner-<timestamp>)`
- `X-LucidScanner-Audit: LucidScanner-<timestamp>`

So you can search your access logs / Cloudflare Security Events to verify
which requests came from a scan vs real traffic.

## Safety

- **Read-only by default.** Only GET/HEAD/POST (for password-reset oracle).
  No PUT / PATCH / DELETE without `--authorized`.
- Single connection at a time (no parallelism that could trigger DDoS protection).
- Static payloads — never destructive SQL (no `DROP`, `UPDATE`, `DELETE`).

## Don't scan sites you don't own

This tool's signature is identifiable. Use it on your own infrastructure
or with explicit written authorization. Unauthorized scanning may violate
CFAA / Computer Misuse Act / equivalent in your jurisdiction.
