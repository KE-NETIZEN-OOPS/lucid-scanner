#!/usr/bin/env python3
"""
LucidScanner — multi-stack web security audit tool.

Built from multiple authorized security audits (trading portals, SaaS, gaming).
Detects target stack and runs appropriate checks. Safe by default.

v2.0 adds:
  - curl-cffi Chrome TLS impersonation (Cloudflare WAF bypass)
  - FinTech/trading portal detection + unauthenticated API probes
  - Authenticated financial injection probes (--token)
  - GUID/OperationId sequential entropy analysis
  - Error verbosity check (stack traces in 500 responses)
  - AngularJS SPA / ASP.NET WebAPI / Azure detection

USAGE
-----
Interactive:
    python lucid_scanner.py

With URL:
    python lucid_scanner.py https://example.com

Authorized mode with Bearer token:
    python lucid_scanner.py https://example.com --authorized --token <bearer> --cookie "<cookie>"

With curl-cffi Chrome TLS bypass (pip install curl-cffi):
    python lucid_scanner.py https://example.com --cffi

With output:
    python lucid_scanner.py https://example.com --output report.md --json findings.json

INSTALL
-------
    pip install requests dnspython
    pip install curl-cffi  # optional — enables Cloudflare TLS fingerprint bypass
"""
import argparse, json, os, re, socket, ssl, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

try:
    import requests
except ImportError:
    print("ERROR: 'requests' is required. Install with: pip install requests", file=sys.stderr)
    sys.exit(1)

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False
    print("WARN: 'dnspython' not installed - DNS checks will be limited. "
          "Install with: pip install dnspython", file=sys.stderr)

try:
    from curl_cffi import requests as cffi_req
    HAS_CFFI = True
except ImportError:
    HAS_CFFI = False

# ============================================================================
# CONFIG
# ============================================================================
VERSION = '2.0'
AUDIT_TS = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
AUDIT_TAG = f'LucidScanner-{AUDIT_TS}'
SCANNER_UA = (
    f'Mozilla/5.0 (LucidScanner/{VERSION}; +safe-probes; tag={AUDIT_TAG})'
)
BROWSER_UA = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
)
TIMEOUT = 12
SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
SEV_ICONS = {'critical': '[CRIT]', 'high': '[HIGH]', 'medium': '[MED]',
             'low': '[LOW]', 'info': '[INFO]'}

CF_RANGES = ('172.66.', '172.67.', '172.64.', '104.16.', '104.17.', '104.18.',
             '104.19.', '104.20.', '104.21.', '108.162.', '141.101.',
             '162.158.', '173.245.', '188.114.')
VERCEL_RANGES = ('216.150.', '76.76.21.', '76.76.19.')

# ============================================================================
# Finding model
# ============================================================================
class Finding:
    def __init__(self, severity, title, evidence='', impact='', fix=''):
        assert severity in SEV_ORDER
        self.severity = severity
        self.title = title
        self.evidence = evidence
        self.impact = impact
        self.fix = fix

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items()}


# ============================================================================
# Stack detection
# ============================================================================
class StackDetector:
    def __init__(self, scanner):
        self.s = scanner
        self.stack = {
            'cdn': set(),
            'app_framework': set(),
            'cms': set(),
            'auth': set(),
            'hosting': set(),
        }

    def detect(self):
        r = self.s.fetch('/')
        if not r:
            return self.stack
        h = {k.lower(): v.lower() if isinstance(v, str) else str(v)
             for k, v in r.headers.items()}
        body = r.text[:80000] if r.text else ''

        # --- CDN / Edge ---
        if 'cloudflare' in h.get('server', ''):
            self.stack['cdn'].add('cloudflare')
        if 'vercel' in h.get('server', '') or 'x-vercel-id' in h:
            self.stack['cdn'].add('vercel')
        if 'fastly' in h.get('via', ''):
            self.stack['cdn'].add('fastly')
        if 'cloudfront' in h.get('via', ''):
            self.stack['cdn'].add('cloudfront')

        # --- Hosting / origin tells ---
        if 'awselb' in h.get('server', ''):
            self.stack['hosting'].add('aws-elb')
        if 'amazons3' in h.get('server', '').replace(' ', ''):
            self.stack['hosting'].add('aws-s3')
        if 'nginx' in h.get('server', ''):
            self.stack['hosting'].add('nginx')

        # --- App framework ---
        if 'wp-content' in body or '/wp-json/' in body or '/wp-includes/' in body:
            self.stack['app_framework'].add('wordpress')
        if '_next/static' in body or 'x-nextjs' in h:
            self.stack['app_framework'].add('nextjs')
        if 'data-astro-cid' in body:
            self.stack['app_framework'].add('astro')
        if 'sveltekit' in body.lower() or '__sveltekit' in body:
            self.stack['app_framework'].add('sveltekit')

        # X-Powered-By hints
        xpb = h.get('x-powered-by', '')
        if 'express' in xpb: self.stack['app_framework'].add('express')
        if 'rails' in xpb: self.stack['app_framework'].add('rails')
        if 'php' in xpb: self.stack['app_framework'].add('php')

        # --- CMS hints ---
        if 'meta name="generator" content="woocommerce' in body.lower():
            self.stack['cms'].add('woocommerce')
        if 'shopify' in h.get('x-shopid', '') or 'shopify' in body.lower()[:5000]:
            self.stack['cms'].add('shopify')

        # --- Auth hints ---
        if '/users/sign_in' in body or '/users/sign_in' in h.get('location', ''):
            self.stack['auth'].add('devise')
        if '/api/auth/session' in body or '/api/auth/csrf' in body:
            self.stack['auth'].add('nextauth')
        if 'clerk' in body.lower()[:5000]:
            self.stack['auth'].add('clerk')
        if 'oauth2' in body.lower() or 'opaque' in h.get('www-authenticate', '').lower():
            self.stack['auth'].add('oauth2-opaque')

        # --- AngularJS SPA ---
        if 'ng-app' in body or 'ng-controller' in body or 'angular.module(' in body:
            self.stack['app_framework'].add('angularjs')
        if 'angular/core' in body or '"@angular/core"' in body:
            self.stack['app_framework'].add('angular')

        # --- ASP.NET / Azure ---
        xpb = h.get('x-powered-by', '')
        if 'asp.net' in xpb.lower(): self.stack['app_framework'].add('aspnet')
        if h.get('x-aspnet-version'):
            self.stack['app_framework'].add('aspnet')
            self.stack['hosting'].add('iis')
        if h.get('x-ms-routing-name') or 'arraff' in ','.join(
                v for k, v in h.items() if 'cookie' in k.lower()).lower():
            self.stack['hosting'].add('azure-appservice')

        # --- Trading / FinTech portal ---
        fintech_signals = ['tradingaccounts', 'traderportal', '/api/pub/',
                           'mt4', 'mt5', 'ctrader', 'equiti', 'metatrader',
                           'deposit', 'withdrawal', 'kyc', 'tradingstatus']
        if sum(1 for s in fintech_signals if s in body.lower()) >= 2:
            self.stack['app_framework'].add('trading-portal')

        # --- Laravel / PHP frameworks (from gaming audit experience) ---
        if 'laravel' in body.lower() or 'laravel_session' in h.get('set-cookie', '').lower():
            self.stack['app_framework'].add('laravel')

        return self.stack

    def is_wp(self):         return 'wordpress' in self.stack['app_framework']
    def is_next(self):       return 'nextjs' in self.stack['app_framework']
    def is_astro(self):      return 'astro' in self.stack['app_framework']
    def is_vercel(self):     return 'vercel' in self.stack['cdn']
    def is_devise(self):     return 'devise' in self.stack['auth']
    def is_cf(self):         return 'cloudflare' in self.stack['cdn']
    def is_woo(self):        return 'woocommerce' in self.stack['cms']
    def is_angular(self):    return bool({'angularjs', 'angular'} & self.stack['app_framework'])
    def is_aspnet(self):     return 'aspnet' in self.stack['app_framework']
    def is_azure(self):      return 'azure-appservice' in self.stack['hosting']
    def is_trading(self):    return 'trading-portal' in self.stack['app_framework']


# ============================================================================
# Scanner
# ============================================================================
class Scanner:
    def __init__(self, url, authorized=False, browser_ua=False, verbose=True,
                 token=None, cookie=None, use_cffi=False):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        self.url = url.rstrip('/')
        p = urlparse(self.url)
        self.host = p.netloc
        self.scheme = p.scheme or 'https'
        self.base = f'{self.scheme}://{self.host}'
        self.authorized = authorized
        self.verbose = verbose
        self.token = token
        self.cookie = cookie
        self.use_cffi = use_cffi and HAS_CFFI
        self.findings = []
        self.session = requests.Session()
        self.session.verify = False
        ua = BROWSER_UA if (browser_ua or token) else SCANNER_UA
        hdrs = {'User-Agent': ua, 'X-LucidScanner-Audit': AUDIT_TAG}
        if token:
            hdrs['Authorization'] = f'Bearer {token}'
        if cookie:
            hdrs['Cookie'] = cookie
        self.session.headers.update(hdrs)
        self.detector = None
        self.subdomains = set()
        self._op_ids_seen = []   # OperationIds collected during scan

    # ---- helpers ----
    def log(self, msg):
        if self.verbose:
            print(msg, file=sys.stderr, flush=True)

    def add(self, sev, title, **kw):
        f = Finding(sev, title, **kw)
        self.findings.append(f)
        self.log(f'  {SEV_ICONS[sev]:8s} {title}')

    def fetch(self, path, method='GET', **kw):
        url = urljoin(self.base, path)
        try:
            r = self.session.request(method, url, timeout=TIMEOUT,
                                     allow_redirects=False, verify=False, **kw)
            return r
        except requests.RequestException:
            return None

    def cffi_post(self, path, body, params=None):
        """POST via curl-cffi Chrome TLS impersonation — bypasses JA3/JA4 WAF fingerprinting."""
        if not HAS_CFFI:
            return None
        url = urljoin(self.base, path)
        hdrs = {
            'Authorization': f'Bearer {self.token}' if self.token else '',
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/plain, */*',
            'x-requested-with': 'XMLHttpRequest',
            'Origin': self.base,
            'Referer': self.base + '/',
            'User-Agent': BROWSER_UA,
            'sec-ch-ua': '"Chromium";v="125", "Google Chrome";v="125"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
        }
        if self.cookie:
            hdrs['Cookie'] = self.cookie
        # remove empty Authorization
        hdrs = {k: v for k, v in hdrs.items() if v}
        try:
            r = cffi_req.post(url, headers=hdrs, json=body, params=params,
                              timeout=30, verify=False, impersonate='chrome120')
            return r
        except Exception:
            return None

    def _api_post(self, path, body, params=None):
        """Try cffi first (WAF bypass), fall back to requests."""
        if self.use_cffi:
            r = self.cffi_post(path, body, params)
            if r is not None:
                return r
        url = urljoin(self.base, path)
        try:
            r = self.session.post(url, json=body, params=params,
                                  timeout=TIMEOUT, verify=False)
            return r
        except Exception:
            return None

    def _api_get(self, path, params=None):
        url = urljoin(self.base, path)
        try:
            r = self.session.get(url, params=params, timeout=TIMEOUT,
                                 verify=False, allow_redirects=False)
            return r
        except Exception:
            return None

    def _collect_op_id(self, resp_json):
        """Pull OperationId out of a response dict and save for entropy analysis."""
        if isinstance(resp_json, dict):
            op = resp_json.get('OperationId') or resp_json.get('operationId')
            if op and isinstance(op, str) and len(op) > 10:
                self._op_ids_seen.append(op)

    # ============================================================
    # PHASE 1: DNS / email auth
    # ============================================================
    def check_dns(self):
        self.log('\n[Phase 1] DNS / email-auth recon')
        if not HAS_DNS:
            self.log('  (skipped — dnspython not installed)')
            return

        try:
            a = [str(x) for x in dns.resolver.resolve(self.host, 'A')]
            cdn = 'unknown'
            if any(ip.startswith(CF_RANGES) for ip in a): cdn = 'cloudflare'
            elif any(ip.startswith(VERCEL_RANGES) for ip in a): cdn = 'vercel'
            self.add('info', f'DNS A records: {a}',
                     evidence=f'CDN/origin guess: {cdn}')
        except Exception:
            pass

        # SPF
        try:
            txt = [str(x) for x in dns.resolver.resolve(self.host, 'TXT')]
            spf = [t for t in txt if 'v=spf1' in t.lower()]
            if not spf:
                self.add('medium', 'No SPF record',
                         impact='Email can be spoofed from this domain.',
                         fix='Add SPF TXT: "v=spf1 include:<provider> -all"')
            elif spf and not any('-all' in s for s in spf):
                self.add('low', 'SPF uses ~all (soft fail) instead of -all',
                         evidence=spf[0],
                         fix='Change ~all to -all once legitimate senders verified.')
        except Exception:
            pass

        # DMARC
        try:
            dmarc = [str(x) for x in
                     dns.resolver.resolve(f'_dmarc.{self.host}', 'TXT')]
            d = dmarc[0] if dmarc else ''
            if 'p=none' in d:
                self.add('medium', 'DMARC policy is monitor-only (p=none)',
                         evidence=d,
                         impact='Spoofed mail is reported but not blocked.',
                         fix='Progress to p=quarantine then p=reject.')
            elif 'p=reject' in d:
                self.add('info', 'DMARC enforces p=reject (strongest)',
                         evidence=d)
        except Exception:
            self.add('high', 'No DMARC record published',
                     impact='Domain can be spoofed in phishing.',
                     fix='Publish _dmarc TXT, at minimum: '
                         '"v=DMARC1; p=none; rua=mailto:reports@..."')

    # ============================================================
    # PHASE 2: CT logs / subdomain enumeration
    # ============================================================
    def check_ct(self):
        self.log('\n[Phase 2] CT-log subdomain enumeration')
        # Try crt.sh first, fall back to HackerTarget
        sources = [
            ('crt.sh',
             f'https://crt.sh/?q=%25.{self.host}&output=json',
             self._parse_crt),
            ('hackertarget',
             f'https://api.hackertarget.com/hostsearch/?q={self.host}',
             self._parse_hackertarget),
        ]
        for name, url, parser in sources:
            try:
                r = requests.get(url, headers={'User-Agent': BROWSER_UA},
                                 timeout=30)
                if r.status_code == 200 and r.text:
                    names = parser(r.text)
                    if names:
                        self.subdomains = names
                        self.log(f'  found {len(names)} subdomains via {name}')
                        break
            except Exception:
                continue

        if self.subdomains:
            interesting_terms = ['admin', 'staging', 'test', 'sandbox', 'dev',
                                 'old', 'internal', 'beta', 'login', 'mcp',
                                 'agents', 'api', 'backup', 'vpn', 'qa',
                                 'metabase', 'vault', 'jenkins', 'gitlab',
                                 'kibana', 'grafana', 'prometheus', 'uat',
                                 'support']
            interesting = sorted(n for n in self.subdomains
                                 if any(t in n for t in interesting_terms))
            if interesting:
                self.add('medium',
                         f'Sensitive subdomains discoverable via CT logs',
                         evidence='\n'.join(interesting[:20]),
                         impact=('Attackers get a map of your infrastructure. '
                                 'Each name suggests what software/service runs there.'),
                         fix=('Cannot hide CT log entries. Mitigate by: '
                              '(1) using opaque subdomain names, '
                              '(2) Cloudflare Access on every internal service, '
                              '(3) issuing private-CA certs for internal-only hosts.'))

    def _parse_crt(self, text):
        try:
            data = json.loads(text)
            names = set()
            for c in data:
                for n in c.get('name_value', '').split('\n'):
                    n = n.strip().lower()
                    if n.endswith(self.host) and '*' not in n:
                        names.add(n)
            return names
        except Exception:
            return set()

    def _parse_hackertarget(self, text):
        names = set()
        for line in text.splitlines():
            if ',' in line:
                name = line.split(',')[0].strip().lower()
                if name.endswith(self.host):
                    names.add(name)
        return names

    # ============================================================
    # PHASE 3: CDN bypass check
    # ============================================================
    def check_origin_leak(self):
        if not HAS_DNS or not self.subdomains:
            return
        if not (self.detector and (self.detector.is_cf() or self.detector.is_vercel())):
            return
        self.log('\n[Phase 3] CDN bypass / direct-origin check')

        for sub in sorted(self.subdomains):
            if sub == self.host:
                continue
            try:
                ip = str(dns.resolver.resolve(sub, 'A')[0])
                in_cf = ip.startswith(CF_RANGES)
                in_vercel = ip.startswith(VERCEL_RANGES)
                if not in_cf and not in_vercel:
                    # Try to classify the provider
                    provider = self._classify_ip(ip)
                    self.add('medium',
                             f'Subdomain bypasses CDN: {sub}',
                             evidence=f'IP {ip} ({provider}) is direct, not CF/Vercel',
                             impact=('Origin directly exposed — edge WAF/DDoS '
                                     'protection absent for this host.'),
                             fix=('Orange-cloud the DNS record (proxy through Cloudflare) '
                                  'or take the subdomain down if unused.'))
            except Exception:
                pass

    def _classify_ip(self, ip):
        if ip.startswith(('3.', '15.', '13.', '18.', '34.', '52.', '54.')):
            return 'AWS'
        if ip.startswith('216.150.'): return 'Vercel'
        if ip.startswith('5.75.'): return 'Hetzner'
        if ip.startswith(('216.239.', '34.102.')): return 'Google'
        return 'unknown'

    # ============================================================
    # PHASE 4: Security headers
    # ============================================================
    def check_security_headers(self):
        self.log('\n[Phase 4] Security headers')
        r = self.fetch('/')
        if not r:
            return
        h = {k.lower(): v for k, v in r.headers.items()}
        checks = [
            ('strict-transport-security', 'high',
             'HSTS not set',
             'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'),
            ('x-content-type-options', 'low',
             'X-Content-Type-Options not set',
             'Add: X-Content-Type-Options: nosniff'),
            ('content-security-policy', 'medium',
             'Content-Security-Policy not set',
             'Define a CSP. Start with frame-ancestors to prevent clickjacking.'),
            ('referrer-policy', 'low',
             'Referrer-Policy not set',
             'Add: Referrer-Policy: strict-origin-when-cross-origin'),
        ]
        for header, sev, title, fix in checks:
            if header not in h:
                self.add(sev, title, fix=fix)
        if 'x-powered-by' in h:
            self.add('low', f'x-powered-by leaks: {h["x-powered-by"]}',
                     impact='Reveals server tech version.',
                     fix='Strip at edge or in app config.')

    # ============================================================
    # PHASE 5: TLS
    # ============================================================
    def check_tls(self):
        self.log('\n[Phase 5] TLS certificate')
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.host, 443), TIMEOUT) as s:
                with ctx.wrap_socket(s, server_hostname=self.host) as ss:
                    cert = ss.getpeercert()
                    not_after = datetime.strptime(cert['notAfter'],
                                                  '%b %d %H:%M:%S %Y %Z')
                    days = (not_after - datetime.utcnow()).days
                    if days < 14:
                        self.add('high', f'TLS cert expires in {days} days',
                                 fix='Renew now; verify ACME auto-renewal.')
                    elif days < 30:
                        self.add('medium', f'TLS cert expires in {days} days')
        except Exception:
            pass

    # ============================================================
    # PHASE 6: WordPress checks
    # ============================================================
    def check_wp(self):
        if not (self.detector and self.detector.is_wp()):
            return
        self.log('\n[Phase 6/WP] WordPress-specific checks')

        # Version disclosure
        for path in ('/readme.html', '/feed/'):
            r = self.fetch(path)
            if r and r.status_code == 200 and r.text:
                m = re.search(r'wordpress[^\d]*([\d.]+)', r.text.lower())
                if m:
                    self.add('low', f'WordPress version disclosed: {m.group(1)}',
                             evidence=f'{path} contains version',
                             fix='403 /readme.html and strip RSS generator tag.')
                    break

        # User enumeration
        r = self.fetch('/wp-json/wp/v2/users?per_page=100')
        if r and r.status_code == 200:
            try:
                users = r.json()
                if isinstance(users, list) and users:
                    admins = [u for u in users if u.get('is_super_admin')]
                    email_leak = [u['slug'] for u in users
                                  if any(d in u.get('slug', '') for d in
                                         ('gmail-com', 'yahoo-com', 'outlook-com',
                                          'hotmail-com'))]
                    sev = 'critical' if admins else 'high'
                    self.add(sev,
                             f'Unauthenticated user enumeration: '
                             f'{len(users)} users exposed via /wp-json/wp/v2/users',
                             evidence=f'Super-admins flagged: '
                                      f'{[u["slug"] for u in admins][:6]}',
                             impact=('Attacker gets target list. Slugs like '
                                     f'{email_leak[:3]} leak email addresses.'),
                             fix='Apply rest_endpoints filter to gate /wp/v2/users '
                                 'behind capability check (current_user_can("list_users")).')
            except Exception:
                pass

        # ?author=N enumeration
        for i in [1, 2, 3]:
            r = self.fetch(f'/?author={i}')
            if r and r.status_code in (301, 302):
                loc = r.headers.get('location', '')
                if '/author/' in loc:
                    slug = loc.split('/author/')[1].strip('/').split('?')[0]
                    self.add('medium', f'?author={i} reveals username',
                             evidence=f'Redirects to /author/{slug}/',
                             fix='In template_redirect, redirect is_author() to '
                                 'home for unauthenticated users.')
                    break

        # xmlrpc.php
        r = self.fetch('/xmlrpc.php', method='POST',
                       data='<?xml version="1.0"?><methodCall>'
                            '<methodName>system.listMethods</methodName>'
                            '</methodCall>',
                       headers={'Content-Type': 'text/xml'})
        if r and r.status_code == 200 and 'methodResponse' in (r.text or ''):
            self.add('medium', 'xmlrpc.php is accessible',
                     impact='Enables silent credential testing via '
                            'wp.getUsersBlogs and pingback DDoS amplification.',
                     fix='Block at edge OR: '
                         'add_filter("xmlrpc_enabled", "__return_false")')

        # Password reset response-size oracle
        self._check_password_reset_oracle()

    def _check_password_reset_oracle(self):
        if not (self.detector and self.detector.is_wp()):
            return
        paths = [('/my-account/lost-password/',
                  {'user_login': 'admin', 'wc_reset_password': 'true'}),
                 ('/wp-login.php?action=lostpassword',
                  {'user_login': 'admin'})]
        for path, base_data in paths:
            r_real = self.fetch(path, method='POST', data=base_data)
            fake_data = dict(base_data)
            fake_data[list(fake_data.keys())[0]] = 'def-not-a-real-user-xyzzy123'
            r_fake = self.fetch(path, method='POST', data=fake_data)
            if r_real and r_fake and r_real.status_code == r_fake.status_code:
                delta = abs(len(r_real.content) - len(r_fake.content))
                if delta > 100:
                    self.add('high',
                             'Password-reset oracle: response size differs '
                             'for real vs fake usernames',
                             evidence=f'real={len(r_real.content)}B, '
                                      f'fake={len(r_fake.content)}B (Δ {delta})',
                             impact='Attacker can enumerate valid emails one request at a time.',
                             fix='Ensure the lost-password handler returns identical '
                                 'response (status, size, timing) regardless of whether '
                                 'the user exists.')
                    return

    # ============================================================
    # PHASE 6n: Next.js / Vercel checks
    # ============================================================
    def check_nextjs_vercel(self):
        if not (self.detector and (self.detector.is_next() or self.detector.is_vercel())):
            return
        self.log('\n[Phase 6/Next.js] Next.js / Vercel exposure')

        paths = [
            '/.env', '/.env.local', '/.env.production', '/.env.development',
            '/_next/static/chunks/webpack.js',
            '/.well-known/vercel/microfrontend-routing',
            '/_next/data/index.json',
            '/__nextjs_original-stack-frame',
            '/api/health',
        ]
        for p in paths:
            r = self.fetch(p)
            if not r:
                continue
            if r.status_code == 200 and len(r.content) > 0:
                preview = (r.text or '').lower()[:1000]
                if any(s in preview for s in
                       ('database_url', 'jwt_secret', 'api_key=', 'secret_key',
                        'aws_access_key', 'private_key')):
                    self.add('critical', f'Possible env/secret leak at {p}',
                             evidence=(r.text or '')[:200],
                             fix='Block /.env* and source-map paths at edge.')

        # Vercel Security Checkpoint detection
        r = self.fetch('/')
        if r and any('x-vercel-mitigated' in k.lower() for k in r.headers):
            self.add('info', 'Vercel Security Checkpoint active',
                     evidence='X-Vercel-Mitigated header present',
                     impact='Bot probes challenged. Limits automated scanning.',
                     fix='Allowlist legitimate bot UAs + /robots.txt /security.txt '
                         'through the firewall.')

    # ============================================================
    # PHASE 6d: Devise (Rails) checks
    # ============================================================
    def check_devise(self):
        if not (self.detector and self.detector.is_devise()):
            return
        self.log('\n[Phase 6/Devise] Devise (Rails) auth paths')

        # Sign-up open?
        r = self.fetch('/users/sign_up')
        if r and r.status_code == 200 and r.text and 'form' in r.text.lower():
            self.add('high', 'Devise sign-up endpoint reachable',
                     impact='Anyone can create an account at /users/sign_up. '
                            'If role assignment is misconfigured, this is direct '
                            'privilege escalation.',
                     fix='If sign-up not intended, remove :registerable from User '
                         'Devise config. Also verify role defaults to lowest privilege.')

        # Sign-in form publicly reachable
        r = self.fetch('/users/sign_in')
        if r and r.status_code == 200 and r.text:
            self.add('medium', 'Devise login form publicly reachable',
                     evidence='200 OK on /users/sign_in',
                     impact='Credential-stuffing / brute-force surface. '
                            'Default Devise rate limiting is loose.',
                     fix='Put Cloudflare Access SSO in front for admin URLs, '
                         'OR install rack-attack with strict limits on /users/sign_in.')

        # Password reset form
        r = self.fetch('/users/password/new')
        if r and r.status_code == 200:
            self.add('info', 'Devise password-reset page reachable',
                     fix='Verify response is identical for known/unknown emails.')

    # ============================================================
    # PHASE 7: Exposed config / backup files
    # ============================================================
    def check_exposed_files(self):
        self.log('\n[Phase 7] Exposed config / backup files')
        paths = ['/.env', '/.env.local', '/.git/config', '/wp-config.php',
                 '/wp-config.php.bak', '/wp-config.php.old', '/wp-config.php~',
                 '/.htaccess', '/.htpasswd', '/composer.json', '/yarn.lock',
                 '/package.json', '/backup.sql', '/dump.sql', '/db.sql',
                 '/backup.zip', '/site-backup.tar.gz', '/.DS_Store',
                 '/phpinfo.php', '/info.php']
        for p in paths:
            r = self.fetch(p)
            if r and r.status_code == 200 and len(r.content) > 0:
                txt = (r.text or '').lower()[:500]
                # Heuristic: skip if it's the site's 404 / homepage
                if '<title>' in txt and ('404' in txt or 'not found' in txt):
                    continue
                if len(r.content) > 10000 and 'doctype html' in txt[:50]:
                    continue
                # Sensitive content?
                if any(s in (r.text or '')[:2000] for s in
                       ('DB_PASSWORD', 'AUTH_KEY', 'SECRET_KEY_BASE',
                        'AWS_ACCESS_KEY', 'STRIPE_SECRET', 'DATABASE_URL=',
                        'mysql:', '[branch ', 'repositoryformatversion')):
                    self.add('critical', f'Exposed sensitive file: {p}',
                             evidence=f'HTTP 200, {len(r.content)} bytes, '
                                      f'contains sensitive markers',
                             impact='Credentials / source / config exposed publicly.',
                             fix=f'Block {p} at edge / web server config.')

    # ============================================================
    # PHASE 8: Hidden admin URLs
    # ============================================================
    def check_hidden_admins(self):
        self.log('\n[Phase 8] Hidden admin / login URLs')
        candidates = ['/wp-admin/', '/wp-login.php', '/login', '/admin',
                      '/administrator', '/portal', '/backend', '/control',
                      '/staff', '/dashboard', '/console', '/manage',
                      '/operator', '/secure-login', '/logintest', '/admin-login',
                      '/users/sign_in', '/auth/login']
        seen = set()
        for p in candidates:
            r = self.fetch(p)
            if not r or r.status_code != 200:
                continue
            txt = r.text or ''
            title_m = re.search(r'<title>([^<]+)</title>', txt)
            title = title_m.group(1) if title_m else ''
            has_login_input = bool(re.search(
                r'name=["\'](log|user_login|username|email|user|user\[email\])["\']',
                txt))
            if (has_login_input or 'login' in title.lower() or
                    'admin' in title.lower() or 'sign in' in title.lower()):
                # Dedupe by title — multiple aliases of same page
                key = title.lower().strip()
                if key in seen:
                    continue
                seen.add(key)
                self.add('medium',
                         f'Login-form page reachable: {p}',
                         evidence=f'title="{title}"',
                         impact='Brute-force / credential-stuffing target.',
                         fix='Put SSO (Cloudflare Access) in front, restrict by IP, '
                             'or at minimum add aggressive rate limits.')

    # ============================================================
    # PHASE 9: SQLi probes (SAFE)
    # ============================================================
    def check_sqli_probe(self):
        self.log('\n[Phase 9] SQLi probes (safe, error-based only)')
        endpoints = [
            ('/?p=1', "/?p=1'"),
            ('/?s=test', "/?s=test'"),
            ('/wp-json/wp/v2/posts?search=test', "/wp-json/wp/v2/posts?search=test'"),
        ]
        for clean, dirty in endpoints:
            r_c = self.fetch(clean)
            r_d = self.fetch(dirty)
            if not (r_c and r_d):
                continue
            if r_d.status_code == 500 and r_c.status_code != 500:
                if r_d.text and any(p in r_d.text.lower() for p in
                        ('sql syntax', 'mysql_', 'sqlstate', 'unclosed',
                         'odbc_', 'pg_query', 'sqlite_')):
                    self.add('critical', 'SQL error message in response',
                             evidence=f'{dirty} leaks DB error string',
                             impact='Likely SQL injection — query DB directly.',
                             fix='Parameterized queries; hide display_errors in prod.')
                else:
                    self.add('high',
                             f'500 on quote injection (possible SQLi)',
                             evidence=f'{dirty} → 500, baseline → {r_c.status_code}',
                             fix='Investigate the endpoint handler for proper '
                                 'input escaping.')

    # ============================================================
    # PHASE 10: Secret leaks in JS/HTML
    # ============================================================
    def check_secrets_in_assets(self):
        self.log('\n[Phase 10] Secret leaks in JS / HTML')
        r = self.fetch('/')
        if not r:
            return
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text or '')
        all_text = r.text or ''
        for s in scripts[:25]:
            url = urljoin(self.base, s)
            try:
                sr = self.session.get(url, timeout=TIMEOUT)
                all_text += '\n' + (sr.text or '')
            except Exception:
                pass

        patterns = {
            'critical': [
                (r'sk_live_[A-Za-z0-9]{20,}', 'Stripe live secret key'),
                (r'rk_live_[A-Za-z0-9]{20,}', 'Stripe live restricted key'),
                (r'AKIA[A-Z0-9]{16}', 'AWS access key ID'),
                (r'AIza[A-Za-z0-9_-]{35}', 'Google API key'),
                (r'-----BEGIN [A-Z ]*PRIVATE KEY-----', 'Private key block'),
                (r'ghp_[A-Za-z0-9]{36}', 'GitHub PAT'),
                (r'xoxb-[0-9]+-[A-Za-z0-9-]+', 'Slack bot token'),
                (r'whsec_[A-Za-z0-9]{20,}', 'Stripe webhook signing secret'),
            ],
            'high': [
                (r'pk_live_[A-Za-z0-9]{20,}',
                 'Stripe live publishable key (usually OK, but worth knowing)'),
            ],
        }
        for sev, items in patterns.items():
            for pat, name in items:
                hits = re.findall(pat, all_text)
                if hits:
                    self.add(sev, f'Leaked credential in client assets: {name}',
                             evidence=f'{len(set(hits))} instance(s) found',
                             impact='Anyone fetching pages obtains this credential.',
                             fix='Rotate immediately. Move to server-side only.')

    # ============================================================
    # PHASE 11: WAF fingerprint & custom block detection
    # ============================================================
    def check_waf_fingerprint(self):
        self.log('\n[Phase 11] WAF fingerprint / custom block detection')
        if not (self.detector and self.detector.is_cf()):
            return

        # Probe a non-existent API path — clean probe to see base WAF response
        r = self.fetch('/api/probe-lucidscanner-nonexistent')
        if not r:
            return
        body_txt = r.text or ''

        # Equiti/custom Cloudflare 499 pattern (#NA-EC-*)
        if '#NA-EC-' in body_txt or r.status_code == 499:
            self.add('medium',
                     'Cloudflare custom block rule active (#NA-EC-* pattern)',
                     evidence=f'HTTP {r.status_code}: {body_txt[:200]}',
                     impact=('WAF blocks datacenter TLS fingerprints (JA3/JA4). '
                             'Python requests / curl blocked by default. '
                             'Residential IPs or Chrome TLS impersonation bypass this.'),
                     fix=('Extend to also inspect request bodies for redirect URL '
                          'fields which can re-trigger body inspection rules.'))

        # Check if cffi bypasses it
        if HAS_CFFI and self.use_cffi:
            r2 = self.cffi_post('/api/probe-lucidscanner-nonexistent', {})
            if r2 and r2.status_code not in (499,) and '#NA-EC-' not in (r2.text or ''):
                self.add('high',
                         'Cloudflare WAF bypassed via Chrome TLS impersonation (curl-cffi)',
                         evidence=(f'Standard requests → {r.status_code}, '
                                   f'cffi/chrome120 → {r2.status_code}'),
                         impact=('Attacker with curl-cffi can reach origin APIs '
                                 'that should be WAF-protected.'),
                         fix=('Add bot-score rules that check for session cookies '
                              'and JS challenge completion, not just TLS fingerprint.'))

    # ============================================================
    # PHASE 12: FinTech / trading portal unauthenticated probes
    # ============================================================
    def check_fintech_portal(self):
        if not (self.detector and self.detector.is_trading()):
            return
        self.log('\n[Phase 12] FinTech/trading portal probes')

        api_base = '/api/pub'

        # --- 12a: ping / token check ---
        r = self._api_get(f'{api_base}/ping')
        if r and r.status_code == 200:
            self.add('info', 'Trading portal API ping reachable',
                     evidence=f'GET {api_base}/ping → 200')

        # --- 12b: KYC-free endpoints (unauthenticated) ---
        kyc_paths = [
            'kycfree/clientstepcompleted',
            'kycfree/sendprofilecompleteemail',
            'kycfree/completestep',
            'kycfree/updatestep',
        ]
        for path in kyc_paths:
            r = self._api_post(f'{api_base}/{path}', {'test': True})
            if r and r.status_code not in (401, 403, 404, 405):
                sev = 'critical' if r.status_code in (200, 400) else 'high'
                self.add(sev,
                         f'KYC endpoint reachable without authentication: /{path}',
                         evidence=f'POST → {r.status_code}: {(r.text or "")[:200]}',
                         impact=('KYC endpoints process verification status updates. '
                                 'Unauthenticated access may allow KYC status manipulation.'),
                         fix='All /kycfree/* endpoints must require valid Bearer token.')

        # --- 12c: Unauthenticated workflow PUT ---
        r_put = self.fetch(f'{api_base}/updateclient/workflow',
                           method='PUT',
                           json={'userId': '00000000-0000-0000-0000-000000000000'},
                           headers={'Content-Type': 'application/json'})
        if r_put and r_put.status_code not in (401, 403, 404):
            body_txt = r_put.text or ''
            # If it reaches ASP.NET Identity (CheckPasswordAsync), it's a real hit
            if any(x in body_txt for x in ('CheckPassword', 'Identity', 'password')):
                self.add('critical',
                         'Unauthenticated PUT /updateclient/workflow reaches identity layer',
                         evidence=f'HTTP {r_put.status_code}: {body_txt[:400]}',
                         impact=('No auth check before password verification. '
                                 'Enables brute-force against any user ID with '
                                 'no rate limit at the framework level.'),
                         fix='Add [Authorize] attribute to UpdateClientWorkflowController. '
                             'Validate userId matches authenticated session.')
            elif r_put.status_code in (200, 400, 500):
                self.add('high',
                         f'Unauthenticated PUT /updateclient/workflow → {r_put.status_code}',
                         evidence=body_txt[:300],
                         fix='Controller must require authentication.')

        # --- 12d: Error verbosity — stack traces in 500s ---
        self._check_error_verbosity(api_base)

        # --- 12e: Demo account workflow (unauthenticated probe) ---
        r_demo = self._api_post(f'{api_base}/workflow/existingclient/demoaccount', {
            'accountType': 'LandingWallet', 'currency': 'USD',
            'platform': 'MT5', 'initialBalance': 100000,
        })
        if r_demo and r_demo.status_code not in (401, 403, 404):
            try:
                j = r_demo.json()
                self._collect_op_id(j)
                state = j.get('ExecutionState', '')
                op_id = j.get('OperationId', '')
                if r_demo.status_code == 200:
                    self.add('critical',
                             'Demo account workflow reachable; ExecutionState may be misleading',
                             evidence=f'POST workflow/existingclient/demoaccount → 200 '
                                      f'[{state}] OperationId={op_id}',
                             impact=('ExecutionState: Aborted does NOT mean the account was '
                                     'not created. MT5 account provisioning occurs async; '
                                     'Aborted = workflow step error, account may still exist. '
                                     'initialBalance is accepted without server-side validation.'),
                             fix=('Validate initialBalance server-side. '
                                  'Confirm ExecutionState reflects actual MT5 account state. '
                                  'Rate-limit this endpoint per user.'))
            except Exception:
                pass

    def _check_error_verbosity(self, api_base):
        """Check whether 500 responses leak internal stack traces."""
        # Send a deliberately malformed payload
        r = self._api_post(f'{api_base}/payment/deposit',
                           {'amount': 'not-a-number', 'currency': 'USD'})
        if not r:
            return
        body = r.text or ''
        if r.status_code == 500 and ('ExceptionDetails' in body or
                                      'at System.' in body or
                                      'StackTrace' in body or
                                      'D:\\a\\' in body):
            # Extract file paths if present
            paths = re.findall(r'in [A-Z]:\\[^\r\n]+\.cs:line \d+', body)
            self.add('high',
                     'Internal stack traces exposed in 500 error responses',
                     evidence='\n'.join(paths[:5]) if paths else body[:400],
                     impact=('Attackers get exact source file paths, class names, '
                             'line numbers, and internal service structure. '
                             'Dramatically accelerates vulnerability research.'),
                     fix=('Set <customErrors mode="On"> in web.config. '
                          'Return generic error IDs (SupportTicketId) only. '
                          'Strip ExceptionDetails from API responses in production.'))

    # ============================================================
    # PHASE 13: Authenticated financial injection probes
    # ============================================================
    def check_authenticated_api(self):
        if not self.token:
            return
        self.log('\n[Phase 13] Authenticated financial injection probes')
        api_base = '/api/pub'

        # Discover query-string pattern from response headers / body
        # Common pattern: ?id=<CRM_ID>&origin=TraderPortal&view=Trader
        r_ping = self._api_get(f'{api_base}/ping')
        if r_ping and r_ping.status_code != 200:
            self.add('info', f'Bearer token appears expired (ping → {r_ping.status_code})',
                     fix='Refresh token and re-run with --token.')
            return

        # --- 13a: Fetch trading accounts to get real IDs ---
        r_accts = self._api_get(f'{api_base}/client/tradingaccounts')
        live_ids = []
        demo_ids = []
        if r_accts and r_accts.status_code == 200:
            try:
                accts = r_accts.json()
                if isinstance(accts, list):
                    for a in accts:
                        tid = a.get('TradingAccountId') or a.get('Id') or a.get('id')
                        if not tid:
                            continue
                        if a.get('IsDemo') or a.get('isDemo'):
                            demo_ids.append(tid)
                        else:
                            live_ids.append(tid)
                    self.add('info',
                             f'Trading accounts discovered: '
                             f'{len(live_ids)} live, {len(demo_ids)} demo',
                             evidence=f'Live IDs: {live_ids[:3]}, Demo IDs: {demo_ids[:3]}')
            except Exception:
                pass

        target_id = (live_ids + demo_ids + ['00000000-0000-0000-0000-000000000000'])[0]

        # --- 13b: Negative amount injection ---
        for amt in [-50000, -1, 0]:
            r = self._api_post(f'{api_base}/payment/deposit', {
                'tradingAccountId': target_id,
                'amount': amt,
                'currency': 'USD',
                'culture': 'en',
                'isDemo': False,
                'Mop': 'CARD',
            })
            if r and r.status_code not in (400, 422):
                body = r.text or ''
                # If it's a 500 with a business logic error (not validation), that's a finding
                if r.status_code == 500 and 'validation' not in body.lower():
                    self.add('high',
                             f'Payment deposit amount={amt} reaches business logic (no input validation)',
                             evidence=f'HTTP {r.status_code}: {body[:300]}',
                             impact=('Negative amounts not rejected at input layer. '
                                     'Depends entirely on gateway to refuse — '
                                     'some gateways process negative amounts as refunds.'),
                             fix='Validate amount > 0 at API layer before gateway call.')
                elif r.status_code == 200:
                    self.add('critical',
                             f'Deposit accepted with amount={amt}',
                             evidence=f'HTTP 200: {body[:400]}',
                             impact='Negative deposit may credit funds or process as withdrawal.',
                             fix='Hard reject amount <= 0 at controller level.')

        # --- 13c: Integer overflow / max value ---
        r_overflow = self._api_post(f'{api_base}/payment/deposit', {
            'tradingAccountId': target_id,
            'amount': 2147483648,  # int32 overflow
            'currency': 'USD',
            'culture': 'en',
            'isDemo': False,
            'Mop': 'CARD',
        })
        if r_overflow and r_overflow.status_code == 200:
            self.add('critical',
                     'Deposit accepted with int32 overflow amount (2147483648)',
                     evidence=(r_overflow.text or '')[:300],
                     fix='Enforce sensible max deposit limit server-side.')

        # --- 13d: IDOR — deposit to a GUID we fabricate ---
        fake_id = str(uuid.uuid4())
        r_idor = self._api_post(f'{api_base}/payment/deposit', {
            'tradingAccountId': fake_id,
            'amount': 100,
            'currency': 'USD',
            'culture': 'en',
            'isDemo': False,
            'Mop': 'CARD',
        })
        if r_idor and r_idor.status_code not in (400, 404, 422):
            body = r_idor.text or ''
            if 'not found' not in body.lower() and 'invalid' not in body.lower():
                self.add('high',
                         'Deposit endpoint does not validate tradingAccountId ownership',
                         evidence=f'Fabricated ID {fake_id} → {r_idor.status_code}: {body[:200]}',
                         impact='IDOR: may allow depositing to/from other users\' accounts.',
                         fix='Server must verify the authenticated user owns the tradingAccountId.')

        # --- 13e: Demo account initialBalance injection ---
        for balance in [999999, -999999]:
            r_demo = self._api_post(f'{api_base}/workflow/existingclient/demoaccount', {
                'accountType': 'LandingWallet',
                'currency': 'USD',
                'platform': 'MT5',
                'initialBalance': balance,
            })
            if r_demo and r_demo.status_code == 200:
                try:
                    j = r_demo.json()
                    self._collect_op_id(j)
                    state = j.get('ExecutionState', 'unknown')
                    self.add('high' if balance > 0 else 'critical',
                             f'Demo account initialBalance={balance} accepted without validation',
                             evidence=f'ExecutionState={state}, OperationId={j.get("OperationId","")}',
                             impact=('initialBalance is passed to MT5 account provisioning. '
                                     'No server-side cap means arbitrary starting balances. '
                                     'ExecutionState: Aborted does NOT prevent account creation.'),
                             fix='Enforce initialBalance limits server-side; do not trust client.')
                except Exception:
                    pass

        # --- 13f: Withdrawal without funds ---
        for wpath in ['payment/withdrawal', 'withdraw', 'payment/withdraw',
                      'withdrawal/workflow/bank', 'withdrawal/workflow/card']:
            r_w = self._api_post(f'{api_base}/{wpath}', {
                'tradingAccountId': target_id,
                'amount': 999999,
                'currency': 'USD',
                'bankName': 'Test Bank',
                'accountNumber': '1234567890',
                'accountName': 'Test User',
            })
            if r_w and r_w.status_code not in (404, 405):
                body = r_w.text or ''
                if r_w.status_code == 200:
                    self.add('critical',
                             f'Withdrawal endpoint {wpath} returned 200',
                             evidence=body[:400],
                             impact='Potential unauthorised withdrawal initiation.',
                             fix='Verify balance, ownership, and KYC before processing.')
                elif r_w.status_code not in (400, 401, 403, 422):
                    self.add('medium',
                             f'Withdrawal endpoint {wpath} reachable: {r_w.status_code}',
                             evidence=body[:200])

    # ============================================================
    # PHASE 14: Sequential GUID / OperationId entropy analysis
    # ============================================================
    def check_guid_entropy(self):
        self.log('\n[Phase 14] GUID / OperationId sequential entropy')
        if len(self._op_ids_seen) < 2:
            return

        # Split GUIDs into segments: 8-4-4-4-12
        def segs(g):
            return g.lower().replace('{', '').replace('}', '').split('-')

        parsed = [segs(g) for g in self._op_ids_seen if len(segs(g)) == 5]
        if len(parsed) < 2:
            return

        # Check if last N-1 segments are constant across all observed GUIDs
        for n_const in [3, 2, 1]:
            cols = list(zip(*parsed))
            const_from = 5 - n_const
            if all(len(set(cols[i])) == 1 for i in range(const_from, 5)):
                constant_suffix = '-'.join(parsed[0][const_from:])
                varying_prefix = '-'.join(parsed[0][:const_from])
                self.add('critical',
                         f'OperationId GUIDs have constant last {n_const} segment(s) — predictable',
                         evidence=(f'Observed IDs:\n' +
                                   '\n'.join(self._op_ids_seen[:6]) +
                                   f'\n\nConstant suffix: ...{constant_suffix}' +
                                   f'\nVarying prefix:  {varying_prefix}...'),
                         impact=('Sequential GUIDs allow enumeration of all operations '
                                 'on the platform. Attacker can iterate the prefix to '
                                 'discover other users\' OperationIds and potentially '
                                 'resume/replay their workflows.'),
                         fix=('Use cryptographically random GUIDs (Guid.NewGuid() in .NET). '
                              'Never derive operation IDs from a counter or timestamp. '
                              'Add authorization checks when looking up operations by ID.'))
                return

        # Check if first segment is monotonically incrementing (hex)
        try:
            first_segs = [int(p[0], 16) for p in parsed]
            diffs = [first_segs[i+1] - first_segs[i] for i in range(len(first_segs)-1)]
            if all(0 < d < 0x10000 for d in diffs):
                self.add('high',
                         'OperationId first segment appears to increment sequentially',
                         evidence=f'Hex diffs between observed IDs: {diffs[:5]}',
                         impact='Enumerable operation IDs across the platform.',
                         fix='Use Guid.NewGuid() — all segments must be random.')
        except Exception:
            pass

    # ============================================================
    # PHASE 15: Angular SPA / ASP.NET specific checks
    # ============================================================
    def check_aspnet_angular(self):
        if not (self.detector and
                (self.detector.is_aspnet() or self.detector.is_angular())):
            return
        self.log('\n[Phase 15] ASP.NET / AngularJS specific checks')

        # --- 15a: Swagger / API docs exposed ---
        for path in ['/swagger', '/swagger/index.html', '/swagger/v1/swagger.json',
                     '/api-docs', '/api/swagger', '/api/pub/swagger']:
            r = self.fetch(path)
            if r and r.status_code == 200:
                body = r.text or ''
                if 'swagger' in body.lower() or 'openapi' in body.lower():
                    self.add('high',
                             f'Swagger/OpenAPI docs publicly accessible: {path}',
                             evidence=f'HTTP 200, {len(r.content)} bytes',
                             impact='Full API surface enumeration without authentication.',
                             fix='Gate Swagger behind Cloudflare Access or only expose in dev.')
                    break

        # --- 15b: API version header leakage ---
        r = self.fetch('/')
        if r:
            h = r.headers
            ver_headers = {k: v for k, v in h.items()
                          if k.lower() in ('x-aspnet-version', 'x-aspnetmvc-version',
                                           'x-powered-by', 'server')}
            for k, v in ver_headers.items():
                if any(c.isdigit() for c in v):
                    self.add('low',
                             f'Version disclosed in header: {k}: {v}',
                             evidence=f'{k}: {v}',
                             fix=f'Remove {k} from response headers in web.config / IIS.')

        # --- 15c: Bundled Angular app.js for secret scanning ---
        r_home = self.fetch('/')
        if r_home:
            scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']',
                                 r_home.text or '')
            # Find the largest JS bundle (likely the AngularJS app)
            app_js_url = None
            for s in scripts:
                if any(x in s for x in ('app.', 'main.', 'bundle.', 'chunk.')):
                    app_js_url = urljoin(self.base, s)
                    break
            if app_js_url:
                try:
                    rjs = self.session.get(app_js_url, timeout=30, verify=False)
                    js_body = rjs.text or ''
                    # Look for hardcoded GUIDs that look like broker/CRM IDs
                    guids = re.findall(
                        r'["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']',
                        js_body)
                    # Look for API keys / secrets
                    secret_pats = [
                        (r'apiKey\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']', 'API key'),
                        (r'clientSecret\s*[=:]\s*["\']([^"\']{10,})["\']', 'client secret'),
                        (r'brokerId\s*[=:]\s*["\']([0-9a-f-]{30,})["\']', 'broker GUID'),
                    ]
                    found = []
                    for pat, label in secret_pats:
                        hits = re.findall(pat, js_body, re.IGNORECASE)
                        if hits:
                            found.append(f'{label}: {hits[0][:50]}')
                    if found:
                        self.add('high',
                                 'Hardcoded IDs/secrets in AngularJS bundle',
                                 evidence='\n'.join(found[:10]),
                                 impact=('Broker IDs, client secrets, and GUIDs exposed '
                                         'in client-side code allow attackers to construct '
                                         'valid API calls without reverse-engineering.'),
                                 fix='Keep internal IDs server-side; inject via API response, '
                                     'not hardcoded in JS bundles.')
                    if len(guids) > 5:
                        self.add('medium',
                                 f'{len(guids)} GUIDs found in JS bundle (internal IDs exposed)',
                                 evidence='; '.join(set(guids[:10])),
                                 fix='Audit which GUIDs are safe to expose client-side.')
                except Exception:
                    pass

    # ============================================================
    # Orchestration
    # ============================================================
    def run(self):
        self.log(f'\n=== LucidScanner v{VERSION} starting on {self.base} ===')
        self.log(f'    Audit tag:      {AUDIT_TAG}')
        self.log(f'    Authorized:     {self.authorized}')
        self.log(f'    Token:          {"yes" if self.token else "no"}')
        self.log(f'    curl-cffi:      {"yes (Chrome TLS)" if self.use_cffi else "no"}')

        self.detector = StackDetector(self)
        stack = self.detector.detect()
        self.log(f'    Detected stack:')
        for category, items in stack.items():
            if items:
                self.log(f'      {category}: {sorted(items)}')

        # Phase groups — passive first, active second, authenticated last
        passive_steps = [
            self.check_dns,
            self.check_ct,
            self.check_origin_leak,
            self.check_security_headers,
            self.check_tls,
            self.check_secrets_in_assets,
        ]
        active_steps = [
            self.check_wp,
            self.check_nextjs_vercel,
            self.check_devise,
            self.check_exposed_files,
            self.check_hidden_admins,
            self.check_sqli_probe,
            self.check_waf_fingerprint,
            self.check_fintech_portal,
            self.check_aspnet_angular,
        ]
        auth_steps = [
            self.check_authenticated_api,   # no-ops if no token
            self.check_guid_entropy,        # uses op_ids collected above
        ]

        all_steps = passive_steps + active_steps + auth_steps

        for fn in all_steps:
            try:
                fn()
            except KeyboardInterrupt:
                self.log('\n[!] Interrupted by user.')
                return self.findings
            except Exception as e:
                self.log(f'  ! check {fn.__name__} errored: {e}')

        return self.findings


# ============================================================================
# Reporting
# ============================================================================
def render_markdown(target, findings, detected_stack=None):
    by_sev = {s: [] for s in SEV_ORDER}
    for f in findings:
        by_sev[f.severity].append(f)
    icons = {'critical': '🔴', 'high': '🟠', 'medium': '🟡',
             'low': '🟢', 'info': '⚪'}

    out = [
        f'# LucidScanner report — {target}',
        '',
        f'**Scanned:** {AUDIT_TS}  ',
        f'**Audit signature:** `{AUDIT_TAG}` (search your access logs for this header)',
        '',
    ]
    if detected_stack:
        out.append('## Detected stack\n')
        for cat, items in detected_stack.items():
            if items:
                out.append(f'- **{cat}**: {", ".join(sorted(items))}')
        out.append('')

    out.append('## Summary\n')
    out.append('| Severity | Count |')
    out.append('|---|---|')
    for s in SEV_ORDER:
        out.append(f'| {icons[s]} {s.title()} | {len(by_sev[s])} |')
    out.append('')

    for s in SEV_ORDER:
        if not by_sev[s]:
            continue
        out.append(f'## {icons[s]} {s.title()} findings\n')
        for i, f in enumerate(by_sev[s], 1):
            out.append(f'### {s.upper()}-{i}: {f.title}\n')
            if f.evidence:
                out.append('**Evidence:**\n')
                out.append('```')
                out.append(f.evidence)
                out.append('```\n')
            if f.impact:
                out.append(f'**Impact:** {f.impact}\n')
            if f.fix:
                out.append(f'**Fix:** {f.fix}\n')

    return '\n'.join(out)


# ============================================================================
# CLI
# ============================================================================
def banner():
    print(f'''
================================================================
  LucidScanner v{VERSION}
  Multi-stack web security audit
================================================================
''', file=sys.stderr)


def prompt_url():
    print('Enter the target URL to scan (e.g. https://example.com):', file=sys.stderr)
    try:
        url = input('> ').strip()
    except (EOFError, KeyboardInterrupt):
        print('\nAborted.', file=sys.stderr)
        sys.exit(0)
    if not url:
        print('No URL given, exiting.', file=sys.stderr)
        sys.exit(1)
    return url


def main():
    ap = argparse.ArgumentParser(
        description='LucidScanner v2 — multi-stack web security audit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument('url', nargs='?', help='Target URL (prompts if omitted)')
    ap.add_argument('--authorized', action='store_true',
                    help='Enable authorized active probes (REQUIRES owner consent)')
    ap.add_argument('--browser-ua', action='store_true',
                    help='Use a browser User-Agent (needed for CF/Vercel bot-protected sites)')
    ap.add_argument('-t', '--token',
                    help='Bearer token for authenticated financial injection probes')
    ap.add_argument('-c', '--cookie',
                    help='Cookie string for authenticated requests (e.g. "id=...; cf_clearance=...")')
    ap.add_argument('--cffi', action='store_true',
                    help='Use curl-cffi Chrome TLS impersonation to bypass WAF fingerprinting '
                         '(requires: pip install curl-cffi)')
    ap.add_argument('-o', '--output',
                    help='Markdown report path (default: report_<host>_<ts>.md)')
    ap.add_argument('--json', help='Also write JSON findings to this path')
    ap.add_argument('-q', '--quiet', action='store_true',
                    help='Suppress progress output to stderr')
    args = ap.parse_args()

    banner()

    if args.cffi and not HAS_CFFI:
        print('WARN: --cffi requested but curl-cffi not installed. '
              'Run: pip install curl-cffi', file=sys.stderr)

    url = args.url or prompt_url()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    host = urlparse(url).netloc
    default_out = f'report_{host}_{AUDIT_TS}.md'
    output_path = args.output or default_out

    scanner = Scanner(url,
                      authorized=args.authorized,
                      browser_ua=args.browser_ua,
                      verbose=not args.quiet,
                      token=args.token,
                      cookie=args.cookie,
                      use_cffi=args.cffi)
    findings = scanner.run()

    detected = scanner.detector.stack if scanner.detector else None
    md = render_markdown(url, findings, detected_stack=detected)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(md)
    print(f'\n=== Report saved: {output_path} ({len(findings)} findings) ===',
          file=sys.stderr)

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump([x.to_dict() for x in findings], f, indent=2)
        print(f'=== JSON saved: {args.json} ===', file=sys.stderr)

    # Print one-line summary to stdout (greppable)
    by_sev = {s: 0 for s in SEV_ORDER}
    for f in findings:
        by_sev[f.severity] += 1
    print(f'{host} | ' + ' '.join(f'{s}:{by_sev[s]}' for s in SEV_ORDER))


if __name__ == '__main__':
    main()
