#!/usr/bin/env python3
"""
LucidScanner — multi-stack web security audit tool.

Detects the target stack (WordPress, Next.js/Vercel, Astro, Rails/Devise, etc.)
and runs the appropriate checks. Safe by default (no destructive writes).

For use on infrastructure you own or have explicit written authorization to test.

USAGE
-----
Interactive:
    python lucid_scanner.py

With URL:
    python lucid_scanner.py https://example.com

With output paths:
    python lucid_scanner.py https://example.com --output report.md --json findings.json

Authorized mode (only for sites you own):
    python lucid_scanner.py https://example.com --authorized

INSTALL
-------
    pip install requests dnspython
"""
import argparse, json, os, re, socket, ssl, sys, time
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

# ============================================================================
# CONFIG
# ============================================================================
VERSION = '1.0'
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

# Supabase / PostgREST detection. The anon key is *meant* to be public (it
# ships in the client bundle); the only thing standing between it and the
# whole database is Row-Level Security. This phase tests whether RLS is
# actually doing its job.
SUPABASE_URL_RE = re.compile(r'https://([a-z0-9]{8,})\.supabase\.co')
JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')
SUPABASE_TABLE_WORDLIST = [
    'profiles', 'users', 'accounts', 'customers', 'members', 'people',
    'payments', 'transactions', 'orders', 'invoices', 'subscriptions',
    'messages', 'chats', 'conversations', 'contacts', 'leads', 'listings',
    'posts', 'comments', 'reviews', 'bookings', 'events', 'products',
    'admin_users', 'admins', 'roles', 'settings', 'config', 'notifications',
    'sessions', 'files', 'media', 'waitlist', 'subscribers', 'emails',
    'feedback', 'tickets', 'addresses', 'cards',
]


def _jwt_payload(token):
    """Best-effort decode of a JWT payload (no signature check). Returns {}."""
    import base64
    try:
        seg = token.split('.')[1]
        seg += '=' * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg.encode()))
    except Exception:
        return {}


def extract_supabase_creds(text):
    """Find a Supabase project URL and its *anon* key in client-side text.

    Pure/offline so it is unit-testable. Returns (project_url, anon_key);
    either element may be None. Only a JWT whose decoded role == 'anon' is
    returned as the key — service_role keys are ignored (they should never
    appear client-side, and probing with one would be meaningless).
    """
    m = SUPABASE_URL_RE.search(text or '')
    if not m:
        return (None, None)
    url = m.group(0)
    anon = None
    for tok in JWT_RE.findall(text or ''):
        if _jwt_payload(tok).get('role') == 'anon':
            anon = tok
            break
    return (url, anon)


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
            'backend': set(),
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

        # --- Backend-as-a-service hints (URL may live in a linked JS bundle,
        #     so this is only a hint; check_supabase_backend confirms it) ---
        if 'supabase' in body.lower() or SUPABASE_URL_RE.search(body):
            self.stack['backend'].add('supabase')
        if 'firebaseio.com' in body or 'firebasedatabase.app' in body:
            self.stack['backend'].add('firebase')

        return self.stack

    def is_wp(self):     return 'wordpress' in self.stack['app_framework']
    def is_next(self):   return 'nextjs' in self.stack['app_framework']
    def is_astro(self):  return 'astro' in self.stack['app_framework']
    def is_vercel(self): return 'vercel' in self.stack['cdn']
    def is_devise(self): return 'devise' in self.stack['auth']
    def is_cf(self):     return 'cloudflare' in self.stack['cdn']
    def is_woo(self):    return 'woocommerce' in self.stack['cms']
    def is_supabase(self): return 'supabase' in self.stack['backend']


# ============================================================================
# Scanner
# ============================================================================
class Scanner:
    def __init__(self, url, authorized=False, browser_ua=False, verbose=True):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        self.url = url.rstrip('/')
        p = urlparse(self.url)
        self.host = p.netloc
        self.scheme = p.scheme or 'https'
        self.base = f'{self.scheme}://{self.host}'
        self.authorized = authorized
        self.verbose = verbose
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': BROWSER_UA if browser_ua else SCANNER_UA,
            'X-LucidScanner-Audit': AUDIT_TAG,
        })
        self.detector = None
        self.subdomains = set()

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
                                     allow_redirects=False, **kw)
            return r
        except requests.RequestException:
            return None

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
    # PHASE 11: Supabase / PostgREST RLS exposure
    # ============================================================
    def _gather_client_text(self):
        """Homepage HTML + the linked JS bundles, concatenated. The Supabase
        URL and anon key usually live in a vendor bundle, not the HTML."""
        r = self.fetch('/')
        if not r:
            return ''
        text = r.text or ''
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', text)
        for s in scripts[:25]:
            try:
                sr = self.session.get(urljoin(self.base, s), timeout=TIMEOUT)
                text += '\n' + (sr.text or '')
            except Exception:
                pass
        return text

    def _supabase_table_count(self, base_url, headers, table):
        """Return how many rows the anon role can read from `table`, or None.

        Uses HEAD + `Prefer: count=exact` so we learn the row count WITHOUT
        ever pulling a row of data — the scanner must never exfiltrate the
        very PII it is warning about. A correctly-locked table returns count
        0 (RLS filters everything); a missing table returns 404.
        """
        try:
            rr = self.session.request(
                'HEAD', f'{base_url}/rest/v1/{table}',
                headers={**headers, 'Prefer': 'count=exact', 'Range': '0-0'},
                timeout=TIMEOUT)
        except requests.RequestException:
            return None
        if rr.status_code not in (200, 206):
            return None
        tail = rr.headers.get('content-range', '').split('/')[-1]
        return int(tail) if tail.isdigit() else None

    def check_supabase_backend(self):
        self.log('\n[Phase 11] Supabase backend / RLS exposure')
        sb_url, anon = extract_supabase_creds(self._gather_client_text())
        if not sb_url:
            return
        self.stack_backend_found = True
        if self.detector:
            self.detector.stack['backend'].add('supabase')
        self.log(f'  detected Supabase backend: {sb_url}')

        if not anon:
            self.add('info',
                     'Supabase backend detected but no anon key found in client JS',
                     evidence=sb_url,
                     impact='Could not test RLS without the publishable anon key.',
                     fix='Manually verify Row-Level Security is enabled on every '
                         'table in the Supabase dashboard.')
            return

        headers = {'apikey': anon, 'Authorization': f'Bearer {anon}'}
        exposed = []
        for t in SUPABASE_TABLE_WORDLIST:
            n = self._supabase_table_count(sb_url, headers, t)
            if n and n > 0:
                exposed.append((t, n))

        if exposed:
            ev = '\n'.join(f'{t}: {n} row(s) readable by anon' for t, n in exposed)
            total = sum(n for _, n in exposed)
            self.add('critical',
                     f'Supabase tables readable by the anonymous key '
                     f'({len(exposed)} table(s), ~{total} rows)',
                     evidence=ev,
                     impact='The anon key ships in every visitor\'s browser, so '
                            'anyone can SELECT these rows directly from the REST '
                            'API. Row-Level Security is missing or permissive — '
                            'this is how a "whole database" gets dumped.',
                     fix='ALTER TABLE <t> ENABLE ROW LEVEL SECURITY on every table, '
                         'then add policies that scope rows to the authenticated '
                         'owner (auth.uid()). Put paid/sensitive columns behind a '
                         'security-definer RPC or a restricted view. NOTE: the anon '
                         'key is not a secret — rotating it does nothing; only RLS '
                         'closes this.')
        else:
            self.add('info',
                     'Supabase backend present; no anon-readable tables found',
                     evidence=sb_url,
                     impact='Common table names returned no rows to the anon key — '
                            'consistent with RLS being enforced.',
                     fix='Spot-check any app-specific table names not in the probe '
                         'wordlist.')

    # ============================================================
    # Orchestration
    # ============================================================
    def run(self):
        self.log(f'\n=== LucidScanner v{VERSION} starting on {self.base} ===')
        self.log(f'    Audit tag: {AUDIT_TAG}')
        self.log(f'    Authorized mode: {self.authorized}')

        self.detector = StackDetector(self)
        stack = self.detector.detect()
        self.log(f'    Detected stack:')
        for category, items in stack.items():
            if items:
                self.log(f'      {category}: {sorted(items)}')

        # Phases — always run these
        steps = [
            self.check_dns,
            self.check_ct,
            self.check_origin_leak,
            self.check_security_headers,
            self.check_tls,
            self.check_wp,
            self.check_nextjs_vercel,
            self.check_devise,
            self.check_exposed_files,
            self.check_hidden_admins,
            self.check_sqli_probe,
            self.check_secrets_in_assets,
            self.check_supabase_backend,
        ]
        for fn in steps:
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
        description='LucidScanner — multi-stack web security audit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument('url', nargs='?', help='Target URL (prompts if omitted)')
    ap.add_argument('--authorized', action='store_true',
                    help='Enable authorized active probes (REQUIRES owner consent)')
    ap.add_argument('--browser-ua', action='store_true',
                    help='Use a browser User-Agent instead of LucidScanner UA '
                         '(needed for Vercel/CF bot-protected sites)')
    ap.add_argument('-o', '--output',
                    help='Markdown report path (default: report_<host>_<ts>.md)')
    ap.add_argument('--json', help='Also write JSON findings to this path')
    ap.add_argument('-q', '--quiet', action='store_true',
                    help='Suppress progress output to stderr')
    args = ap.parse_args()

    banner()

    url = args.url or prompt_url()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    host = urlparse(url).netloc
    default_out = f'report_{host}_{AUDIT_TS}.md'
    output_path = args.output or default_out

    scanner = Scanner(url, authorized=args.authorized,
                      browser_ua=args.browser_ua, verbose=not args.quiet)
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
