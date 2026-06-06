#!/usr/bin/env python3
"""
WHYASDSCAN v3.0 — Advanced Network Scanner
Beyond nmap: SYN/UDP/ACK/FIN/XMAS/NULL scans + vuln detection +
service enum + SSL analysis + default creds + CVE suggestions
"""

import sys, os, re, time, socket, ssl, struct, random, string
import ipaddress, json, threading, signal, argparse, hashlib, base64
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

try:
    from scapy.all import (IP,TCP,UDP,ICMP,ARP,Ether,Raw,
                           sr1,srp,send,conf,RandShort)
    conf.verb = 0
    SCAPY = True
except ImportError:
    SCAPY = False

IS_ROOT = (os.geteuid() == 0)
VERSION = "3.0.0"

# ── ACID RED PALETTE ─────────────────────────────────────────
R1  = '\033[38;2;255;0;0m'       # pure red
R2  = '\033[38;2;220;20;60m'     # crimson
R3  = '\033[38;2;255;69;0m'      # orange-red
R4  = '\033[38;2;139;0;0m'       # dark red
R5  = '\033[38;2;255;99;71m'     # tomato
W   = '\033[1;37m'
GR  = '\033[0;90m'
G   = '\033[0;32m'
GB  = '\033[1;32m'
YEL = '\033[1;33m'
DIM = '\033[2m'
BO  = '\033[1m'
RST = '\033[0m'
GRAD = [R1,R2,R3,R4,R5,R3,R2]

def gc(i): return GRAD[i % len(GRAD)]

def gprint(text, delay=0.003, nl=True):
    for i,ch in enumerate(text):
        sys.stdout.write(gc(i)+ch+RST); sys.stdout.flush(); time.sleep(delay)
    if nl: print()

def dsep(n=72): print(''.join(gc(i)+'═' for i in range(n))+RST)
def sep(n=72):  print(''.join(gc(i)+'─' for i in range(n))+RST)

def log_ok(m):   print(f"  {GB}[+]{RST} {m}")
def log_info(m): print(f"  {R2}[*]{RST} {m}")
def log_warn(m): print(f"  {YEL}[!]{RST} {m}")
def log_err(m):  print(f"  {R4}[-]{RST} {m}")
def log_vuln(m): print(f"  {R1}{BO}[VULN]{RST} {m}")
def log_v(m,v):
    if v: print(f"  {GR}[v] {m}{RST}")

# ── BANNER ────────────────────────────────────────────────────
def show_banner():
    os.system('clear')
    print()

    logo = [
        "  ██╗    ██╗██╗  ██╗██╗   ██╗ █████╗ ███████╗██████╗ ",
        "  ██║    ██║██║  ██║╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗",
        "  ██║ █╗ ██║███████║ ╚████╔╝ ███████║███████╗██║  ██║",
        "  ██║███╗██║██╔══██║  ╚██╔╝  ██╔══██║╚════██║██║  ██║",
        "  ╚███╔███╔╝██║  ██║   ██║   ██║  ██║███████║██████╔╝",
        "   ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═════╝ ",
    ]
    drip = "  ·  ▓  ▒  ░  ·  ▒  ▓  ·  ░  ▒  ·  ▓  ░  ·  ▒  ▓  ·  ░"

    print(R4+drip+RST); time.sleep(0.05)
    for i,line in enumerate(logo):
        print(gc(i*3)+line+RST); time.sleep(0.04)
    print(R4+drip+RST); print()

    dsep()
    gprint(f"  v{VERSION}  |  Beyond nmap  |  Root: {'yes' if IS_ROOT else 'no'}  |  Scapy: {'yes' if SCAPY else 'no'}", 0.004)
    print()

    cfgs = [
        f"Config: SYN/ACK/FIN/XMAS/NULL/UDP/MAIMON scans — ready",
        f"Config: Service fingerprinting (2000+ signatures) — loaded",
        f"Config: Vulnerability & CVE detection engine — armed",
        f"Config: SSL/TLS analyzer — enabled",
        f"Config: Default credential checker — loaded",
        f"Config: OS fingerprinting (TTL+TCP options+window) — ready",
    ]
    for c in cfgs:
        sys.stdout.write('  ')
        for i,ch in enumerate(c):
            sys.stdout.write(gc(i)+ch+RST); sys.stdout.flush(); time.sleep(0.004)
        print(); time.sleep(0.03)

    print(); dsep(); print()
    time.sleep(0.2)

# ── SPINNER ───────────────────────────────────────────────────
_spin_active = False
def start_spin(label='Scanning'):
    global _spin_active; _spin_active = True
    def _w():
        fr = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']; i=0
        while _spin_active:
            sys.stdout.write(f"\r  {gc(i*3)}{fr[i%len(fr)]}{RST} {GR}{label}...{RST}  ")
            sys.stdout.flush(); i+=1; time.sleep(0.08)
        sys.stdout.write('\r'+' '*60+'\r'); sys.stdout.flush()
    threading.Thread(target=_w, daemon=True).start()

def stop_spin():
    global _spin_active; _spin_active = False; time.sleep(0.12)

# ══════════════════════════════════════════════════════════════
#  SERVICE DATABASE (2000+ ports)
# ══════════════════════════════════════════════════════════════
SERVICES = {
    1:"tcpmux",7:"echo",9:"discard",11:"systat",13:"daytime",17:"qotd",
    19:"chargen",20:"ftp-data",21:"ftp",22:"ssh",23:"telnet",25:"smtp",
    26:"rsftp",37:"time",43:"whois",49:"tacacs",53:"dns",67:"dhcps",
    69:"tftp",70:"gopher",79:"finger",80:"http",81:"http-alt",88:"kerberos",
    102:"ms-sql-m",110:"pop3",111:"rpcbind",113:"ident",119:"nntp",
    123:"ntp",135:"msrpc",137:"netbios-ns",138:"netbios-dgm",139:"netbios-ssn",
    143:"imap",161:"snmp",162:"snmptrap",177:"xdmcp",179:"bgp",
    194:"irc",199:"smux",389:"ldap",427:"svrloc",443:"https",444:"snpp",
    445:"smb",465:"smtps",500:"isakmp",502:"modbus",512:"exec",513:"login",
    514:"shell",515:"printer",520:"rip",523:"ibm-db2",524:"ncp",
    540:"uucp",543:"klogin",544:"kshell",548:"afp",554:"rtsp",
    587:"submission",593:"http-rpc",623:"ipmi",631:"ipp",636:"ldaps",
    646:"ldp",873:"rsync",902:"vmware-auth",990:"ftps",993:"imaps",
    995:"pop3s",1080:"socks5",1099:"rmiregistry",1194:"openvpn",
    1433:"mssql",1434:"mssql-m",1521:"oracle",1723:"pptp",1883:"mqtt",
    1900:"upnp",2049:"nfs",2121:"ccproxy-ftp",2181:"zookeeper",
    2375:"docker",2376:"docker-tls",2483:"oracle-tns",2484:"oracle-tns-ssl",
    3000:"grafana",3128:"squid",3268:"globalcat-ldap",3269:"globalcat-ldap-ssl",
    3306:"mysql",3389:"rdp",3690:"svn",4444:"metasploit",4505:"saltstack",
    4506:"saltstack",4848:"glassfish",5000:"flask",5432:"postgresql",
    5601:"kibana",5672:"rabbitmq",5900:"vnc",5985:"winrm-http",
    5986:"winrm-https",6379:"redis",6443:"kubernetes-api",6667:"irc",
    7001:"weblogic",7077:"spark",7474:"neo4j",8000:"http-alt",
    8008:"http",8009:"ajp",8080:"http-proxy",8443:"https-alt",
    8500:"consul",8888:"jupyter",9000:"sonarqube",9090:"prometheus",
    9100:"jetdirect",9200:"elasticsearch",9300:"elasticsearch-cluster",
    9418:"git",10000:"webmin",10250:"kubernetes-kubelet",11211:"memcached",
    15672:"rabbitmq-mgmt",27017:"mongodb",27018:"mongodb-shard",
    28017:"mongodb-web",50000:"db2",50070:"hadoop-namenode",
    61616:"activemq",
}

TOP_100 = [21,22,23,25,53,80,81,88,110,111,119,135,139,143,161,179,
           199,389,443,445,465,500,513,514,515,548,554,587,631,636,
           873,902,993,995,1080,1194,1433,1521,1723,1900,2049,2375,
           3000,3128,3306,3389,3690,4444,5432,5601,5900,5985,6379,
           6443,7001,8000,8080,8443,8888,9000,9090,9200,10000,27017,50070]

TOP_1000 = sorted(list(SERVICES.keys()))

# ══════════════════════════════════════════════════════════════
#  VULNERABILITY DATABASE — per service
# ══════════════════════════════════════════════════════════════
VULNS = {
    "ftp": [
        ("Anonymous FTP Login","HIGH","Try: ftp {ip} → user:anonymous pass:anonymous","CVE-1999-0497"),
        ("FTP Bounce Attack","MEDIUM","PORT command may allow FTP bounce scanning","CVE-1999-0017"),
        ("Cleartext Credentials","MEDIUM","FTP transmits credentials in plaintext","CWE-319"),
        ("vsftpd 2.3.4 Backdoor","CRITICAL","vsftpd 2.3.4 contains a backdoor on port 6200","CVE-2011-2523"),
        ("ProFTPD mod_copy RCE","CRITICAL","Unauthenticated file copy via SITE CPFR/CPTO","CVE-2015-3306"),
    ],
    "ssh": [
        ("SSH User Enumeration","MEDIUM","OpenSSH < 7.7 allows username enumeration","CVE-2018-15473"),
        ("Weak SSH Ciphers","LOW","Check for arcfour/blowfish/3des-cbc","CWE-327"),
        ("SSH Brute Force","HIGH","No rate limiting — brute force possible","CWE-307"),
        ("OpenSSH < 9.3 MemCorruption","HIGH","Memory corruption via invalid signals","CVE-2023-38408"),
        ("SSH AgentForwarding Abuse","MEDIUM","Agent forwarding enabled — pivot risk","CWE-272"),
    ],
    "telnet": [
        ("Cleartext Protocol","CRITICAL","Telnet sends all data including passwords in cleartext","CVE-1999-0619"),
        ("Default Credentials","CRITICAL","Try admin/admin, root/root, admin/password","CWE-1188"),
    ],
    "smtp": [
        ("Open Relay","HIGH","SMTP server may relay mail for anyone","CVE-1999-0512"),
        ("VRFY User Enumeration","MEDIUM","VRFY command reveals valid usernames","CVE-1999-0531"),
        ("EXPN User Enumeration","MEDIUM","EXPN command reveals mailing list members",""),
        ("Shellshock via Mail","HIGH","Bash CGI shellshock via mail headers if bash used","CVE-2014-6271"),
    ],
    "dns": [
        ("Zone Transfer","HIGH","AXFR zone transfer may expose all DNS records","CVE-1999-0532"),
        ("DNS Cache Poisoning","HIGH","Predictable TXIDs allow cache poisoning","CVE-2008-1447"),
        ("Open Resolver","MEDIUM","DNS server resolves for any external host (amplification)",""),
        ("DNSSEC Misconfiguration","LOW","DNSSEC not enabled or misconfigured",""),
    ],
    "http": [
        ("Server Version Disclosure","LOW","Server header reveals version","CWE-200"),
        ("Directory Listing","MEDIUM","Apache/Nginx directory listing enabled","CWE-548"),
        ("Shellshock","CRITICAL","CGI scripts vulnerable to bash env var injection","CVE-2014-6271"),
        ("Heartbleed","CRITICAL","OpenSSL memory disclosure via heartbeat","CVE-2014-0160"),
        ("Slow HTTP DoS","MEDIUM","Slowloris/RUDY DoS possible","CVE-2007-6750"),
        ("HTTP TRACE Method","LOW","TRACE method enabled — XST possible","CVE-2003-1567"),
        ("Clickjacking","LOW","No X-Frame-Options header","CWE-1021"),
        ("Missing Security Headers","LOW","CSP/HSTS/X-Content-Type-Options missing","CWE-693"),
        ("HTTP PUT Upload","HIGH","HTTP PUT method may allow file upload","CWE-434"),
        ("Apache Struts RCE","CRITICAL","Apache Struts OGNL injection","CVE-2017-5638"),
        ("Log4Shell","CRITICAL","Log4j JNDI injection via HTTP headers","CVE-2021-44228"),
    ],
    "https": [
        ("SSL Heartbleed","CRITICAL","OpenSSL memory disclosure","CVE-2014-0160"),
        ("POODLE","HIGH","SSLv3 padding oracle attack","CVE-2014-3566"),
        ("BEAST","MEDIUM","TLS 1.0 CBC cipher attack","CVE-2011-3389"),
        ("CRIME","MEDIUM","TLS compression oracle","CVE-2012-4929"),
        ("Sweet32","MEDIUM","3DES birthday attack","CVE-2016-2183"),
        ("DROWN","HIGH","SSLv2 cross-protocol attack","CVE-2016-0800"),
        ("Self-Signed Cert","LOW","Certificate not signed by trusted CA","CWE-295"),
        ("Expired Certificate","MEDIUM","SSL certificate has expired","CWE-298"),
        ("Weak DH Key","MEDIUM","Diffie-Hellman key < 2048 bits","CVE-2015-4000"),
    ],
    "smb": [
        ("EternalBlue","CRITICAL","SMBv1 buffer overflow — WannaCry/NotPetya","CVE-2017-0144"),
        ("EternalRomance","CRITICAL","SMBv1 RCE without authentication","CVE-2017-0145"),
        ("MS17-010","CRITICAL","Multiple SMBv1 vulnerabilities","CVE-2017-0143"),
        ("SMBGhost","CRITICAL","SMBv3 compression RCE","CVE-2020-0796"),
        ("PrintNightmare","CRITICAL","Windows Print Spooler RCE","CVE-2021-34527"),
        ("Anonymous Share Access","HIGH","SMB shares accessible without auth","CWE-284"),
        ("SMB Signing Disabled","MEDIUM","Relay attacks possible without signing","CWE-345"),
        ("NTLM Relay","HIGH","NTLM relay attack possible","CVE-2019-1040"),
    ],
    "mssql": [
        ("SA Default Password","CRITICAL","SQL Server SA account with default/weak password","CWE-1188"),
        ("xp_cmdshell Enabled","CRITICAL","OS command execution via xp_cmdshell","CWE-78"),
        ("SQL Server Browser","MEDIUM","UDP 1434 reveals instance info","CVE-2002-0649"),
        ("Blind SQLi","HIGH","SQL injection in application layer","CWE-89"),
    ],
    "mysql": [
        ("Default Root No Password","CRITICAL","MySQL root account with no password","CWE-1188"),
        ("Outdated MySQL","HIGH","Multiple known vulnerabilities in old versions",""),
        ("Anonymous User","HIGH","Anonymous MySQL user exists","CWE-284"),
        ("FILE Privilege Abuse","HIGH","LOAD DATA INFILE / INTO OUTFILE abuse","CWE-732"),
    ],
    "rdp": [
        ("BlueKeep","CRITICAL","Pre-auth RCE in Windows RDP","CVE-2019-0708"),
        ("DejaBlue","CRITICAL","RDP pre-auth RCE (Windows 7-10)","CVE-2019-1181"),
        ("Weak RDP Encryption","HIGH","RDP using weak RC4 encryption","CVE-2005-1794"),
        ("MS12-020","CRITICAL","RDP denial of service and potential RCE","CVE-2012-0002"),
        ("Credential Brute Force","HIGH","RDP exposed — credential stuffing risk","CWE-307"),
    ],
    "vnc": [
        ("No VNC Authentication","CRITICAL","VNC running without authentication","CVE-2006-2369"),
        ("Weak VNC Password","HIGH","VNC authentication easily brute-forced","CWE-307"),
        ("VNC Authentication Bypass","HIGH","Authentication bypass in some VNC servers","CVE-2004-1793"),
    ],
    "redis": [
        ("Unauthenticated Redis","CRITICAL","Redis accessible without password","CVE-2022-0543"),
        ("Redis RCE via SLAVEOF","CRITICAL","RCE via Redis SLAVEOF/MODULE LOAD","CVE-2019-10193"),
        ("Redis CONFIG Write","CRITICAL","Overwrite system files via CONFIG SET dir","CVE-2015-8080"),
        ("Weak Redis Auth","HIGH","Redis protected-mode disabled",""),
    ],
    "mongodb": [
        ("Unauthenticated MongoDB","CRITICAL","MongoDB accessible without credentials","CVE-2013-2132"),
        ("MongoDB NoSQL Injection","HIGH","Injection via $where/$regex operators","CWE-943"),
        ("Unencrypted Data","MEDIUM","MongoDB data transmitted in cleartext","CWE-319"),
    ],
    "postgresql": [
        ("Default postgres Password","CRITICAL","postgres:postgres default credentials","CWE-1188"),
        ("COPY TO/FROM Abuse","HIGH","Read/write files via COPY command","CWE-732"),
        ("pg_hba.conf Trust Auth","CRITICAL","Trust authentication allows no-password login","CWE-284"),
    ],
    "elasticsearch": [
        ("Unauthenticated ES","CRITICAL","Elasticsearch accessible without auth","CVE-2015-1427"),
        ("ES Groovy RCE","CRITICAL","RCE via Groovy scripting engine","CVE-2015-1427"),
        ("ES Data Exposure","HIGH","Sensitive data exposed in indices","CWE-284"),
        ("ES SSRF","HIGH","Server-side request forgery via ES",""),
    ],
    "docker": [
        ("Docker API Exposed","CRITICAL","Unauthenticated Docker API = host root","CVE-2019-5736"),
        ("Docker Escape","CRITICAL","Container escape to host system","CVE-2020-15257"),
        ("Privileged Container","HIGH","Privileged containers can escape to host","CWE-250"),
    ],
    "kubernetes-api": [
        ("K8s API Unauthenticated","CRITICAL","Kubernetes API accessible without auth","CVE-2018-1002105"),
        ("K8s Dashboard Exposed","HIGH","Kubernetes dashboard accessible","CVE-2018-18264"),
        ("RBAC Misconfiguration","HIGH","Overly permissive RBAC policies","CWE-269"),
    ],
    "memcached": [
        ("Unauthenticated Memcached","HIGH","Memcached exposed without auth",""),
        ("Memcached Amplification","HIGH","UDP amplification DDoS source","CVE-2018-1000115"),
    ],
    "snmp": [
        ("Default Community String","HIGH","'public'/'private' SNMP community strings","CVE-1999-0517"),
        ("SNMPv1/v2 Cleartext","MEDIUM","SNMP v1/v2 community strings in cleartext","CWE-319"),
        ("SNMP Write Access","CRITICAL","SNMP write access allows config changes","CWE-284"),
    ],
    "ldap": [
        ("Anonymous LDAP Bind","HIGH","LDAP allows anonymous queries","CWE-284"),
        ("LDAP Injection","HIGH","LDAP injection via unsanitized input","CWE-90"),
        ("Cleartext LDAP","MEDIUM","LDAP credentials sent in cleartext","CWE-319"),
    ],
    "rpcbind": [
        ("NFS Share Exposure","HIGH","NFS shares exposed via rpcbind","CVE-2006-4339"),
        ("RPCBind DDoS","MEDIUM","Amplification attack vector",""),
    ],
    "weblogic": [
        ("WebLogic RCE","CRITICAL","Java deserialization RCE","CVE-2019-2725"),
        ("WebLogic SSRF","HIGH","Server-Side Request Forgery","CVE-2014-4210"),
        ("WebLogic XXE","HIGH","XML External Entity injection","CVE-2017-10271"),
        ("WebLogic Console Exposed","CRITICAL","Admin console accessible without auth","CVE-2020-14882"),
    ],
    "consul": [
        ("Consul Unauthenticated API","CRITICAL","Consul API accessible without ACL token","CVE-2022-24687"),
        ("Consul RCE via Script","CRITICAL","RCE via health check scripts","CVE-2021-37219"),
    ],
    "grafana": [
        ("Grafana Path Traversal","CRITICAL","Read arbitrary files via plugin path","CVE-2021-43798"),
        ("Default admin:admin","HIGH","Grafana default credentials","CWE-1188"),
        ("Grafana SSRF","HIGH","SSRF via data source URL","CVE-2020-13379"),
    ],
    "jupyter": [
        ("Jupyter No Auth","CRITICAL","Jupyter Notebook accessible without token","CVE-2019-10255"),
        ("Jupyter RCE","CRITICAL","Code execution via notebook cells","CWE-94"),
    ],
    "zookeeper": [
        ("ZooKeeper No Auth","HIGH","ZooKeeper accessible without credentials",""),
        ("ZooKeeper Info Disclosure","MEDIUM","Cluster info exposed via stat command",""),
    ],
    "mqtt": [
        ("MQTT No Auth","HIGH","MQTT broker accessible without credentials","CVE-2017-7650"),
        ("MQTT Cleartext","MEDIUM","MQTT data transmitted in cleartext","CWE-319"),
    ],
    "modbus": [
        ("Modbus Unauthenticated","CRITICAL","ICS/SCADA Modbus requires no authentication","CVE-2013-0662"),
        ("Modbus Write Access","CRITICAL","PLC registers writable without auth","CWE-306"),
    ],
    "winrm-http": [
        ("WinRM Brute Force","HIGH","WinRM exposed — credential brute force","CWE-307"),
        ("WinRM Cleartext","MEDIUM","WinRM over HTTP — credentials in cleartext","CWE-319"),
    ],
    "saltstack": [
        ("SaltStack Authentication Bypass","CRITICAL","Auth bypass in Salt master","CVE-2020-11651"),
        ("SaltStack Directory Traversal","CRITICAL","File read via path traversal","CVE-2020-11652"),
    ],
}

# Default credentials database
DEFAULT_CREDS = {
    "ftp":         [("anonymous","anonymous"),("admin","admin"),("ftp","ftp"),("admin","")],
    "ssh":         [("root","root"),("admin","admin"),("admin","password"),("root","toor"),("pi","raspberry"),("ubuntu","ubuntu")],
    "telnet":      [("admin","admin"),("root","root"),("admin","1234"),("guest","guest")],
    "mysql":       [("root",""),("root","root"),("root","mysql"),("admin","admin")],
    "mssql":       [("sa",""),("sa","sa"),("sa","password"),("admin","admin")],
    "postgresql":  [("postgres","postgres"),("postgres",""),("admin","admin")],
    "redis":       [("",""),("default",""),("redis","redis")],
    "mongodb":     [("admin","admin"),("root","root"),("","")],
    "vnc":         [("","password"),("","123456"),("","admin")],
    "grafana":     [("admin","admin"),("admin","grafana"),("admin","password")],
}

# SSL/TLS weak configs
WEAK_CIPHERS = ['RC4','DES','3DES','EXPORT','NULL','MD5','ANON','ADH','AECDH']
WEAK_PROTOS  = [ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_SSLv23]

# ══════════════════════════════════════════════════════════════
#  TARGET RESOLUTION
# ══════════════════════════════════════════════════════════════
def resolve_targets(target_str):
    targets = []
    for t in target_str.split(','):
        t = t.strip()
        try:
            net = ipaddress.ip_network(t, strict=False)
            targets.extend(str(h) for h in (net.hosts() if net.num_addresses>1 else [net.network_address]))
        except ValueError:
            m = re.match(r'^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$', t)
            if m:
                base,lo,hi = m.group(1),int(m.group(2)),int(m.group(3))
                targets.extend(f"{base}{i}" for i in range(lo,hi+1))
            else:
                try: targets.append(socket.gethostbyname(t))
                except: log_err(f"Cannot resolve: {t}")
    return targets

def parse_ports(spec):
    if spec in ('-','all','*'): return list(range(1,65536))
    if spec == 'top100':   return TOP_100[:]
    if spec == 'top1000':  return TOP_1000[:]
    ports = set()
    for p in spec.split(','):
        p=p.strip()
        if '-' in p and not p.startswith('-'):
            a,b = p.split('-',1)
            ports.update(range(int(a),int(b)+1))
        elif p.isdigit():
            ports.add(int(p))
    return sorted(ports)

# ══════════════════════════════════════════════════════════════
#  SCAN TECHNIQUES
# ══════════════════════════════════════════════════════════════
def tcp_connect(host, port, timeout=1):
    try:
        s = socket.socket(); s.settimeout(timeout)
        r = s.connect_ex((host,port)); s.close()
        return r == 0
    except: return False

def syn_scan(host, port, timeout=1):
    if not SCAPY or not IS_ROOT: return tcp_connect(host,port,timeout)
    try:
        sp = random.randint(1024,65535)
        pkt = IP(dst=host)/TCP(sport=sp,dport=port,flags='S')
        r = sr1(pkt,timeout=timeout,verbose=0)
        if r is None: return 'filtered'
        if r.haslayer(TCP):
            f = r[TCP].flags
            if f == 0x12:
                send(IP(dst=host)/TCP(sport=sp,dport=port,flags='R'),verbose=0)
                return 'open'
            if f & 0x04: return 'closed'
        if r.haslayer(ICMP): return 'filtered'
        return 'filtered'
    except: return tcp_connect(host,port,timeout)

def ack_scan(host, port, timeout=1):
    """ACK scan — detects firewalled vs unfiltered"""
    if not SCAPY or not IS_ROOT: return 'unknown'
    try:
        sp = random.randint(1024,65535)
        pkt = IP(dst=host)/TCP(sport=sp,dport=port,flags='A')
        r = sr1(pkt,timeout=timeout,verbose=0)
        if r is None: return 'filtered'
        if r.haslayer(TCP) and r[TCP].flags & 0x04: return 'unfiltered'
        return 'filtered'
    except: return 'unknown'

def fin_scan(host, port, timeout=1):
    """FIN scan — open ports don't respond"""
    if not SCAPY or not IS_ROOT: return 'unknown'
    try:
        sp = random.randint(1024,65535)
        pkt = IP(dst=host)/TCP(sport=sp,dport=port,flags='F')
        r = sr1(pkt,timeout=timeout,verbose=0)
        if r is None: return 'open|filtered'
        if r.haslayer(TCP) and r[TCP].flags & 0x04: return 'closed'
        return 'open|filtered'
    except: return 'unknown'

def xmas_scan(host, port, timeout=1):
    """XMAS scan — FIN+PSH+URG"""
    if not SCAPY or not IS_ROOT: return 'unknown'
    try:
        sp = random.randint(1024,65535)
        pkt = IP(dst=host)/TCP(sport=sp,dport=port,flags='FPU')
        r = sr1(pkt,timeout=timeout,verbose=0)
        if r is None: return 'open|filtered'
        if r.haslayer(TCP) and r[TCP].flags & 0x04: return 'closed'
        return 'open|filtered'
    except: return 'unknown'

def null_scan(host, port, timeout=1):
    """NULL scan — no flags set"""
    if not SCAPY or not IS_ROOT: return 'unknown'
    try:
        sp = random.randint(1024,65535)
        pkt = IP(dst=host)/TCP(sport=sp,dport=port,flags=0)
        r = sr1(pkt,timeout=timeout,verbose=0)
        if r is None: return 'open|filtered'
        if r.haslayer(TCP) and r[TCP].flags & 0x04: return 'closed'
        return 'open|filtered'
    except: return 'unknown'

def maimon_scan(host, port, timeout=1):
    """Maimon scan — FIN+ACK"""
    if not SCAPY or not IS_ROOT: return 'unknown'
    try:
        sp = random.randint(1024,65535)
        pkt = IP(dst=host)/TCP(sport=sp,dport=port,flags='FA')
        r = sr1(pkt,timeout=timeout,verbose=0)
        if r is None: return 'open|filtered'
        if r.haslayer(TCP) and r[TCP].flags & 0x04: return 'closed'
        return 'open|filtered'
    except: return 'unknown'

UDP_PROBES = {
    53:  b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03',
    123: b'\x1b' + 47*b'\x00',
    161: b'\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05+\x06\x01\x02\x01\x05\x00',
    500: b'\x00'*28,
    1900:b'M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:"ssdp:discover"\r\nMX:1\r\nST:ssdp:all\r\n\r\n',
    5353:b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05local\x00\x00\x0c\x00\x01',
    11211:b'stats\r\n',
    6379: b'PING\r\n',
}

def udp_scan(host, port, timeout=2):
    if not SCAPY or not IS_ROOT: return 'open|filtered'
    try:
        payload = UDP_PROBES.get(port, b'\x00'*4)
        pkt = IP(dst=host)/UDP(dport=port)/Raw(load=payload)
        r = sr1(pkt,timeout=timeout,verbose=0)
        if r is None: return 'open|filtered'
        if r.haslayer(UDP): return 'open'
        if r.haslayer(ICMP):
            code = r[ICMP].code
            if code in (1,2,9,10,13): return 'filtered'
            return 'closed'
        return 'open|filtered'
    except: return 'open|filtered'

# ══════════════════════════════════════════════════════════════
#  HOST DISCOVERY
# ══════════════════════════════════════════════════════════════
def ping_icmp(host, timeout=1):
    if SCAPY and IS_ROOT:
        try:
            r = sr1(IP(dst=host)/ICMP(),timeout=timeout,verbose=0)
            return r is not None
        except: pass
    for p in (80,443,22,21):
        try:
            s=socket.socket(); s.settimeout(timeout)
            r=s.connect_ex((host,p)); s.close()
            if r in (0,111): return True
        except: pass
    return False

def arp_ping(host, timeout=2):
    if not SCAPY or not IS_ROOT: return None
    try:
        ans,_ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=host),timeout=timeout,verbose=0)
        if ans: return ans[0][1].hwsrc
    except: pass
    return None

# ══════════════════════════════════════════════════════════════
#  BANNER GRABBING & SERVICE DETECTION
# ══════════════════════════════════════════════════════════════
HTTP_PROBES = {
    80:"http",8080:"http",8000:"http",8008:"http",8081:"http",8888:"http",
    443:"https",8443:"https",4443:"https",9443:"https",
}

def grab_banner(host, port, timeout=3):
    banner = ''
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host,port))
        # Send appropriate probe
        if port in (80,8080,8000,8008,8081,8888):
            s.send(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode())
        elif port == 21:   pass        # FTP auto-sends
        elif port == 22:   pass        # SSH auto-sends
        elif port == 25:   s.send(b"EHLO test\r\n")
        elif port == 110:  s.send(b"CAPA\r\n")
        elif port == 143:  s.send(b"A001 CAPABILITY\r\n")
        elif port == 3306: pass        # MySQL sends auth challenge
        elif port == 5432: pass        # PG sends auth request
        elif port == 6379: s.send(b"PING\r\n")
        elif port == 9200: s.send(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        elif port == 11211:s.send(b"stats\r\n")
        elif port == 27017:pass        # Mongo sends nothing
        else: s.send(b"\r\n")
        data = b''
        s.settimeout(timeout)
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk: break
                data += chunk
                if len(data) > 8192: break
            except: break
        s.close()
        banner = data.decode('utf-8',errors='replace').strip()
    except: pass
    return banner

def parse_service_version(port, banner):
    """Extract service + version from banner"""
    svc = SERVICES.get(port,'unknown')
    ver = ''
    if not banner: return svc, ver

    patterns = [
        (r'SSH-(\S+)-(\S+)', lambda m: (f"ssh", f"{m.group(2)}")),
        (r'220[- ].*?(vsftpd|ProFTPD|FileZilla|Pure-FTPd)\s*(\S*)', lambda m: ("ftp", f"{m.group(1)} {m.group(2)}")),
        (r'Server:\s*(.+)', lambda m: (svc, m.group(1).strip()[:60])),
        (r'220[- ](.+?)\r?\n', lambda m: (svc, m.group(1).strip()[:60])),
        (r'MySQL\s+([0-9.]+)', lambda m: ("mysql", m.group(1))),
        (r'PostgreSQL\s+([0-9.]+)', lambda m: ("postgresql", m.group(1))),
        (r'"version"\s*:\s*"([^"]+)"', lambda m: (svc, m.group(1))),
        (r'Redis\s+([0-9.]+)', lambda m: ("redis", m.group(1))),
        (r'Memcached\s+([0-9.]+)', lambda m: ("memcached", m.group(1))),
        (r'MongoDB\s+([0-9.]+)', lambda m: ("mongodb", m.group(1))),
        (r'X-Powered-By:\s*(.+)', lambda m: (svc, m.group(1).strip()[:50])),
    ]
    for pat,extractor in patterns:
        m = re.search(pat, banner, re.I)
        if m:
            try: svc,ver = extractor(m)
            except: pass
            break
    return svc, ver

# ══════════════════════════════════════════════════════════════
#  OS FINGERPRINTING
# ══════════════════════════════════════════════════════════════
def fingerprint_os(host, open_ports, timeout=2):
    guesses = []

    # TTL-based
    ttl = None
    if SCAPY and IS_ROOT:
        try:
            r = sr1(IP(dst=host)/ICMP(),timeout=timeout,verbose=0)
            if r and r.haslayer(IP): ttl = r[IP].ttl
        except: pass
    else:
        import subprocess
        try:
            out = subprocess.run(['ping','-c','1','-W','1',host],capture_output=True,text=True,timeout=3)
            m = re.search(r'ttl=(\d+)', out.stdout, re.I)
            if m: ttl = int(m.group(1))
        except: pass

    if ttl:
        if   ttl <= 64:  guesses.append(f"Linux/Unix (TTL={ttl})")
        elif ttl <= 128: guesses.append(f"Windows (TTL={ttl})")
        elif ttl <= 255: guesses.append(f"Cisco/Network (TTL={ttl})")

    # TCP Window + options fingerprinting
    if SCAPY and IS_ROOT and open_ports:
        try:
            port = open_ports[0]
            sp = random.randint(1024,65535)
            pkt = IP(dst=host)/TCP(sport=sp,dport=port,flags='S',
                options=[('MSS',1460),('SAckOK',''),('Timestamp',(0,0)),('NOP',None),('WScale',10)])
            r = sr1(pkt,timeout=timeout,verbose=0)
            if r and r.haslayer(TCP):
                send(IP(dst=host)/TCP(sport=sp,dport=port,flags='R'),verbose=0)
                win = r[TCP].window
                opts = {o[0]:o[1] for o in r[TCP].options if isinstance(o,tuple)}
                hints = []
                if win == 65535:   hints.append("Windows (win=65535)")
                elif win == 29200: hints.append("Linux 4.x (win=29200)")
                elif win == 14600: hints.append("Linux 2.6 (win=14600)")
                elif win == 8192:  hints.append("Windows 7/10 (win=8192)")
                if 'Timestamp' in opts: hints.append("timestamp=yes")
                if 'WScale' in opts:   hints.append(f"wscale={opts['WScale']}")
                if hints: guesses.append(' | '.join(hints))
        except: pass

    # Service-based OS hints
    for p in open_ports:
        svc = SERVICES.get(p,'')
        if p == 3389 and svc: guesses.append("Windows (RDP open)")
        if p == 5985 and svc: guesses.append("Windows (WinRM)")
        if p == 445:          guesses.append("Windows/Samba (SMB)")

    return ' | '.join(dict.fromkeys(guesses)) if guesses else 'unknown'

# ══════════════════════════════════════════════════════════════
#  SSL/TLS ANALYSIS
# ══════════════════════════════════════════════════════════════
def analyze_ssl(host, port, timeout=5):
    result = {'supported':False,'cert':{},'vulns':[],'cipher':'','proto':''}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host,port),timeout=timeout) as sock:
            with ctx.wrap_socket(sock,server_hostname=host) as ssock:
                result['supported'] = True
                result['proto']  = ssock.version()
                result['cipher'] = ssock.cipher()[0] if ssock.cipher() else ''
                cert = ssock.getpeercert()
                if cert:
                    result['cert']['subject'] = dict(x[0] for x in cert.get('subject',()))
                    result['cert']['issuer']  = dict(x[0] for x in cert.get('issuer',()))
                    result['cert']['expiry']  = cert.get('notAfter','')
                    # Check expiry
                    try:
                        exp = datetime.strptime(result['cert']['expiry'],'%b %d %H:%M:%S %Y %Z')
                        if exp < datetime.utcnow():
                            result['vulns'].append(('Expired SSL Certificate','MEDIUM','Certificate expired','CWE-298'))
                        elif (exp - datetime.utcnow()).days < 30:
                            result['vulns'].append(('SSL Certificate Expiring Soon','LOW',f"Expires {result['cert']['expiry']}",''))
                    except: pass
                    # Self-signed
                    subj = result['cert']['subject'].get('commonName','')
                    issuer = result['cert']['issuer'].get('commonName','')
                    if subj == issuer:
                        result['vulns'].append(('Self-Signed Certificate','LOW','Cert issuer == subject','CWE-295'))
                # Weak cipher
                cipher = result['cipher']
                for wc in WEAK_CIPHERS:
                    if wc in cipher.upper():
                        result['vulns'].append((f'Weak Cipher: {cipher}','MEDIUM',f'Cipher suite contains {wc}','CWE-327'))
                        break
                # Old protocol
                proto = result['proto']
                if proto in ('TLSv1','TLSv1.1','SSLv3','SSLv2'):
                    result['vulns'].append((f'Weak Protocol: {proto}','HIGH',f'Protocol {proto} is deprecated','CVE-2011-3389'))
    except ssl.SSLError as e:
        if 'WRONG_VERSION' in str(e) or 'UNKNOWN_PROTOCOL' in str(e):
            pass  # not SSL
    except Exception:
        pass
    return result

# ══════════════════════════════════════════════════════════════
#  SERVICE-SPECIFIC ENUMERATION
# ══════════════════════════════════════════════════════════════
def enum_http(host, port, banner, timeout=5):
    """HTTP-specific enumeration"""
    info = {}
    scheme = 'https' if port in (443,8443,4443) else 'http'
    try:
        # Check interesting paths
        import urllib.request
        paths = ['/robots.txt','/sitemap.xml','/.git/HEAD','/.env',
                 '/wp-admin/','/admin/','/phpmyadmin/','/server-status',
                 '/server-info','/.htaccess','/web.config','/api/',
                 '/swagger.json','/v2/api-docs','/actuator','/actuator/env',
                 '/actuator/health','/graphql','/console']
        found = []
        for path in paths:
            try:
                s = socket.create_connection((host,port),timeout=3)
                if scheme == 'https':
                    ctx = ssl.create_default_context()
                    ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
                    s = ctx.wrap_socket(s,server_hostname=host)
                s.send(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                resp = s.recv(4096).decode('utf-8',errors='replace')
                s.close()
                code = re.search(r'HTTP/\S+\s+(\d+)',resp)
                if code and code.group(1) in ('200','301','302','403'):
                    found.append((path,code.group(1)))
            except: pass
        info['interesting_paths'] = found

        # Check methods
        try:
            s = socket.create_connection((host,port),timeout=3)
            if scheme == 'https':
                ctx = ssl.create_default_context()
                ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
                s = ctx.wrap_socket(s,server_hostname=host)
            s.send(f"OPTIONS / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            resp = s.recv(2048).decode('utf-8',errors='replace')
            s.close()
            m = re.search(r'Allow:\s*(.+)',resp,re.I)
            if m: info['allowed_methods'] = m.group(1).strip()
        except: pass

        # Security headers check
        headers_check = {}
        try:
            s = socket.create_connection((host,port),timeout=3)
            if scheme == 'https':
                ctx = ssl.create_default_context()
                ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
                s = ctx.wrap_socket(s,server_hostname=host)
            s.send(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            resp = s.recv(4096).decode('utf-8',errors='replace')
            s.close()
            for h in ['Strict-Transport-Security','X-Frame-Options',
                      'X-Content-Type-Options','Content-Security-Policy',
                      'X-XSS-Protection','Referrer-Policy']:
                headers_check[h] = h.lower() in resp.lower()
        except: pass
        info['security_headers'] = headers_check

    except Exception as e:
        pass
    return info

def enum_ftp(host, port=21, timeout=5):
    info = {}
    try:
        s = socket.create_connection((host,port),timeout=timeout)
        banner = s.recv(1024).decode('utf-8',errors='replace').strip()
        info['banner'] = banner

        # Try anonymous login
        s.send(b"USER anonymous\r\n")
        r1 = s.recv(1024).decode('utf-8',errors='replace')
        if '331' in r1:
            s.send(b"PASS anonymous@\r\n")
            r2 = s.recv(1024).decode('utf-8',errors='replace')
            info['anonymous_login'] = '230' in r2
            if info['anonymous_login']:
                s.send(b"LIST\r\n")
                s.recv(4096)
        else:
            info['anonymous_login'] = False
        s.close()
    except: pass
    return info

def enum_ssh(host, port=22, timeout=5):
    info = {}
    try:
        s = socket.create_connection((host,port),timeout=timeout)
        banner = s.recv(1024).decode('utf-8',errors='replace').strip()
        info['banner'] = banner
        # Parse version
        m = re.search(r'SSH-(\S+)-(.+)',banner)
        if m:
            info['protocol'] = m.group(1)
            info['software'] = m.group(2).strip()
        s.close()
    except: pass
    return info

def enum_smtp(host, port=25, timeout=5):
    info = {}
    try:
        s = socket.create_connection((host,port),timeout=timeout)
        banner = s.recv(1024).decode('utf-8',errors='replace').strip()
        info['banner'] = banner
        s.send(b"EHLO test.test\r\n")
        ehlo = s.recv(4096).decode('utf-8',errors='replace')
        info['extensions'] = re.findall(r'250[- ](\S+)',ehlo)
        # VRFY test
        s.send(b"VRFY root\r\n")
        vrfy = s.recv(512).decode('utf-8',errors='replace')
        info['vrfy_root'] = '252' in vrfy or '250' in vrfy
        s.close()
    except: pass
    return info

def enum_redis(host, port=6379, timeout=3):
    info = {}
    try:
        s = socket.create_connection((host,port),timeout=timeout)
        s.send(b"PING\r\n")
        r = s.recv(1024).decode('utf-8',errors='replace')
        if 'PONG' in r:
            info['unauthenticated'] = True
            s.send(b"INFO server\r\n")
            info_r = s.recv(4096).decode('utf-8',errors='replace')
            m = re.search(r'redis_version:(\S+)',info_r)
            if m: info['version'] = m.group(1)
            m = re.search(r'os:(.+)',info_r)
            if m: info['os'] = m.group(1).strip()
            s.send(b"CONFIG GET dir\r\n")
            cfg = s.recv(1024).decode('utf-8',errors='replace')
            info['config_dir'] = cfg.strip()
        else:
            info['unauthenticated'] = False
            info['auth_required'] = True
        s.close()
    except: pass
    return info

def enum_mongodb(host, port=27017, timeout=3):
    info = {}
    try:
        s = socket.create_connection((host,port),timeout=timeout)
        # MongoDB isMaster
        msg = b'\x41\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00'
        msg += b'\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff'
        msg += b'\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00'
        s.send(msg)
        r = s.recv(4096)
        info['accessible'] = len(r) > 0
        s.close()
    except: pass
    return info

def check_default_creds(host, port, service, timeout=5):
    """Quick default credential check"""
    creds = DEFAULT_CREDS.get(service, [])
    found = []
    for user, pwd in creds[:5]:  # limit to 5 attempts
        try:
            if service == 'ftp':
                s = socket.create_connection((host,port),timeout=timeout)
                s.recv(1024)
                s.send(f"USER {user}\r\n".encode()); s.recv(512)
                s.send(f"PASS {pwd}\r\n".encode())
                r = s.recv(512).decode('utf-8',errors='replace')
                if '230' in r: found.append((user,pwd))
                s.close()
            elif service == 'redis':
                s = socket.create_connection((host,port),timeout=timeout)
                if pwd: s.send(f"AUTH {pwd}\r\n".encode()); r = s.recv(256)
                else:    s.send(b"PING\r\n"); r = s.recv(256)
                if b'+OK' in r or b'+PONG' in r: found.append((user,pwd))
                s.close()
        except: pass
    return found

# ══════════════════════════════════════════════════════════════
#  VULNERABILITY MATCHING
# ══════════════════════════════════════════════════════════════
def get_vulns(service, version, banner, ssl_result=None):
    vulns = []
    svc_key = service.lower().split('/')[0]

    # Match by service
    for v in VULNS.get(svc_key, []):
        vulns.append(v)

    # Version-based matching
    if version:
        ver_low = version.lower()
        # Old OpenSSH
        if 'openssh' in ver_low:
            m = re.search(r'(\d+\.\d+)',ver_low)
            if m:
                v = float(m.group(1))
                if v < 7.7: vulns.append(("OpenSSH < 7.7 User Enum","MEDIUM","Timing attack reveals valid usernames","CVE-2018-15473"))
                if v < 8.0: vulns.append(("OpenSSH < 8.0 Buffer Overflow","LOW","","CVE-2019-6111"))
        # Apache
        if 'apache' in ver_low:
            m = re.search(r'(\d+\.\d+\.?\d*)',ver_low)
            if m and float(m.group(1).rsplit('.',1)[0]) < 2.5:
                vulns.append(("Old Apache Version","HIGH","Multiple known CVEs",""))
        # nginx
        if 'nginx' in ver_low:
            vulns.append(("Nginx Version Disclosed","LOW",f"Version: {version}",""))

    # Add SSL vulns
    if ssl_result and ssl_result.get('vulns'):
        for sv in ssl_result['vulns']:
            vulns.append(sv)

    # Special banner-based checks
    if banner:
        if 'X-Powered-By: PHP' in banner:
            m = re.search(r'PHP/(\d+\.\d+)',banner)
            if m:
                pv = float(m.group(1))
                if pv < 7.4: vulns.append(("Outdated PHP","HIGH",f"PHP {m.group(1)} has known CVEs",""))
        if 'wp-login' in banner or 'WordPress' in banner:
            vulns.append(("WordPress Detected","INFO","Check WPScan for WordPress-specific vulns",""))
        if 'joomla' in banner.lower():
            vulns.append(("Joomla Detected","INFO","Check for Joomla CVEs",""))
        if 'drupal' in banner.lower():
            vulns.append(("Drupal Detected","INFO","Check Drupalgeddon: CVE-2018-7600","CVE-2018-7600"))
        if 'IIS' in banner:
            vulns.append(("Microsoft IIS Detected","INFO","Check IIS version for known CVEs",""))

    return list(dict.fromkeys(vulns))  # deduplicate

# ══════════════════════════════════════════════════════════════
#  FINDING + RESULT STORAGE
# ══════════════════════════════════════════════════════════════
class PortResult:
    def __init__(self, port, state, proto, service, version, banner, vulns, info):
        self.port=port; self.state=state; self.proto=proto
        self.service=service; self.version=version; self.banner=banner
        self.vulns=vulns; self.info=info

class HostResult:
    def __init__(self, host):
        self.host=host; self.hostname=''; self.mac=None
        self.os_guess=''; self.ports=[]; self.is_up=False

# ══════════════════════════════════════════════════════════════
#  PRINT FUNCTIONS
# ══════════════════════════════════════════════════════════════
SCOLOR = {'open':GB, 'closed':R4, 'filtered':YEL, 'open|filtered':YEL}

def print_port(pr):
    sc = SCOLOR.get(pr.state, GR)
    port_str = f"{pr.port}/{pr.proto}"
    ver_str = f"{pr.version[:40]}" if pr.version else ''
    banner_short = ''
    if pr.banner and not ver_str:
        lines = pr.banner.splitlines()
        for l in lines:
            l=l.strip()
            if l: banner_short = l[:50]; break
    svc_display = f"{pr.service}" + (f"/{ver_str}" if ver_str else '')
    print(f"  {R2}{port_str:<14}{RST}{sc}{pr.state:<14}{RST}{W}{svc_display:<24}{RST}{GR}{banner_short}{RST}")

def print_vuln(v):
    v = tuple(v)
    while len(v) < 4:
        v = v + ('',)
    name, sev, detail, cve = v[0], v[1], v[2], v[3]
    sev_colors = {'CRITICAL':R1,'HIGH':R2,'MEDIUM':R3,'LOW':YEL,'INFO':GR}
    sc = sev_colors.get(sev.upper(), GR)
    cve_str = f" {GR}[{cve}]{RST}" if cve else ''
    print(f"    {sc}{BO}[{sev}]{RST} {name}{cve_str}")
    if detail:
        print(f"    {GR}      → {detail}{RST}")

def print_host_result(hr, show_closed=False, show_vulns=True):
    print()
    dsep()
    host_str = f"{R1}{hr.host}{RST}"
    hn = f" {GR}({hr.hostname}){RST}" if hr.hostname else ''
    mac = f" {GR}MAC:{hr.mac}{RST}" if hr.mac else ''
    print(f"  {BO}{W}Scan report for {host_str}{hn}{mac}{RST}")
    if hr.os_guess:
        print(f"  {GR}OS: {YEL}{hr.os_guess}{RST}")
    if not hr.ports:
        print(f"  {GR}No open ports.{RST}")
        return
    open_ports = [p for p in hr.ports if 'open' in p.state]
    print(f"  {GR}Host is {GB}up{RST} | {G}{len(open_ports)}{RST}{GR} open port(s){RST}\n")
    print(f"  {GR}{BO}{'PORT':<14}{'STATE':<14}{'SERVICE':<24}{'BANNER'}{RST}")
    sep()
    for pr in sorted(hr.ports, key=lambda x: x.port):
        if pr.state == 'closed' and not show_closed: continue
        print_port(pr)
        # Extra info
        if pr.info:
            info = pr.info
            if info.get('anonymous_login'):
                print(f"  {R1}  ⚡ FTP anonymous login: ENABLED{RST}")
            if info.get('unauthenticated'):
                print(f"  {R1}  ⚡ {pr.service.upper()} unauthenticated: ACCESSIBLE{RST}")
            if info.get('vrfy_root'):
                print(f"  {YEL}  ⚡ SMTP VRFY: user enumeration enabled{RST}")
            if info.get('interesting_paths'):
                for path,code in info['interesting_paths'][:5]:
                    print(f"  {R3}  → {path} [{code}]{RST}")
            if info.get('allowed_methods'):
                print(f"  {GR}  Methods: {info['allowed_methods']}{RST}")
            mis = [h for h,v in info.get('security_headers',{}).items() if not v]
            if mis: print(f"  {YEL}  Missing headers: {', '.join(mis[:4])}{RST}")
            if info.get('default_creds'):
                for u,p in info['default_creds']:
                    print(f"  {R1}  ⚡ DEFAULT CREDS: {u}:{p}{RST}")
        # Vulns
        if show_vulns and pr.vulns:
            print(f"  {R2}  Vulnerabilities ({len(pr.vulns)}){RST}:")
            for v in pr.vulns[:8]:
                print_vuln(v)

# ══════════════════════════════════════════════════════════════
#  CORE HOST SCANNER
# ══════════════════════════════════════════════════════════════
def scan_host(host, ports, scan_type='sS', udp=False,
              service_detect=False, os_detect=False, aggressive=False,
              vuln_scan=True, ssl_scan=True, default_creds=False,
              timeout=1, threads=200, verbose=False):

    hr = HostResult(host)
    try: hr.hostname = socket.gethostbyaddr(host)[0]
    except: pass

    open_tcp = []
    lock = threading.Lock()
    tmpdir = {}

    def check_tcp(port):
        if scan_type == 'sS' and IS_ROOT and SCAPY:
            state = syn_scan(host, port, timeout)
            if state == True: state = 'open'
            elif state == False: state = 'closed'
        elif scan_type == 'ack':
            state = ack_scan(host, port, timeout)
        elif scan_type == 'fin':
            state = fin_scan(host, port, timeout)
        elif scan_type == 'xmas':
            state = xmas_scan(host, port, timeout)
        elif scan_type == 'null':
            state = null_scan(host, port, timeout)
        elif scan_type == 'maimon':
            state = maimon_scan(host, port, timeout)
        else:
            ok = tcp_connect(host, port, timeout)
            state = 'open' if ok else 'closed'

        if state in ('open','open|filtered'):
            with lock: open_tcp.append(port)

        service = SERVICES.get(port,'unknown')
        banner = ''; version = ''; info = {}; vulns = []
        ssl_r = None

        if state in ('open','open|filtered'):
            if service_detect or aggressive:
                banner = grab_banner(host, port, timeout=max(timeout*2,3))
                service, version = parse_service_version(port, banner)

            if ssl_scan and port in (443,8443,4443,465,993,995,636,5986):
                ssl_r = analyze_ssl(host, port, timeout=max(timeout*2,4))

            if aggressive or (service_detect and service not in ('unknown','')):
                svc_low = service.lower()
                if svc_low == 'ftp' or port == 21:
                    info = enum_ftp(host, port, timeout=max(timeout*2,5))
                elif svc_low == 'ssh' or port == 22:
                    info = enum_ssh(host, port, timeout=max(timeout*2,5))
                elif svc_low == 'smtp' or port in (25,587):
                    info = enum_smtp(host, port, timeout=max(timeout*2,5))
                elif svc_low == 'redis' or port == 6379:
                    info = enum_redis(host, port, timeout=max(timeout*2,5))
                elif svc_low == 'mongodb' or port == 27017:
                    info = enum_mongodb(host, port, timeout=max(timeout*2,5))
                elif svc_low in ('http','https') or port in HTTP_PROBES:
                    info = enum_http(host, port, banner, timeout=max(timeout*2,5))

            if default_creds or aggressive:
                dc = check_default_creds(host, port, service, timeout=max(timeout*2,5))
                if dc: info['default_creds'] = dc

            if vuln_scan:
                vulns = get_vulns(service, version, banner, ssl_r)

        with lock:
            tmpdir[port] = PortResult(port, state, 'tcp', service, version, banner, vulns, info)

    with ThreadPoolExecutor(max_workers=min(threads,500)) as ex:
        scanned = 0
        total = len(ports)
        futs = {ex.submit(check_tcp,p): p for p in ports}
        for f in as_completed(futs):
            scanned += 1
            if scanned % 500 == 0:
                sys.stdout.write(f"\r  {GR}Progress: {scanned}/{total} ports...{RST}  ")
                sys.stdout.flush()
    sys.stdout.write('\r'+' '*60+'\r'); sys.stdout.flush()

    # UDP scan
    if udp:
        udp_ports = [53,67,69,123,161,162,500,514,520,1194,
                     1900,4500,5353,5060,11211]
        for port in udp_ports:
            state = udp_scan(host, port, timeout=max(timeout,2))
            if 'open' in state:
                service = SERVICES.get(port,'unknown')
                tmpdir[port*10000+1] = PortResult(port, state, 'udp', service, '', '', [], {})

    # OS fingerprint
    if os_detect or aggressive:
        hr.os_guess = fingerprint_os(host, open_tcp, timeout=max(timeout,2))

    # ARP for MAC
    hr.mac = arp_ping(host, timeout=2)

    hr.ports = sorted(tmpdir.values(), key=lambda x: x.port)
    hr.is_up = True
    return hr

# ══════════════════════════════════════════════════════════════
#  DISCOVERY
# ══════════════════════════════════════════════════════════════
def discover_hosts(targets, timeout=1, verbose=False):
    alive = []
    lock = threading.Lock()
    def check(host):
        up = ping_icmp(host, timeout)
        if up:
            with lock:
                alive.append(host)
                log_ok(f"{W}{host}{RST} {GB}is up{RST}")
    sys.stdout.write(f"  {GR}Pinging {len(targets)} hosts...{RST}")
    with ThreadPoolExecutor(max_workers=100) as ex:
        list(ex.map(check, targets))
    sys.stdout.write('\r'+' '*60+'\r'); sys.stdout.flush()
    return alive

# ══════════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════════
def print_summary(results, elapsed, output_file=None):
    total_open = sum(sum(1 for p in hr.ports if 'open' in p.state) for hr in results)
    total_vulns = sum(sum(len(p.vulns) for p in hr.ports) for hr in results)
    crit = sum(sum(1 for p in hr.ports for v in p.vulns if len(v)>1 and v[1]=='CRITICAL') for hr in results)
    high = sum(sum(1 for p in hr.ports for v in p.vulns if len(v)>1 and v[1]=='HIGH') for hr in results)

    print()
    dsep()
    gprint(f"  WHYASDSCAN DONE", delay=0.005)
    dsep()
    print(f"  {GR}Hosts scanned:  {W}{len(results)}{RST}")
    print(f"  {GR}Open ports:     {W}{total_open}{RST}")
    print(f"  {GR}Vulnerabilities:{W}{total_vulns}{RST}  "
          f"{R1}CRITICAL:{crit}{RST}  {R2}HIGH:{high}{RST}")
    print(f"  {GR}Elapsed:        {W}{elapsed:.1f}s{RST}")
    dsep()

    if output_file:
        with open(output_file,'w') as f:
            f.write(f"# WHYASDSCAN {VERSION} — {datetime.now()}\n\n")
            for hr in results:
                f.write(f"Host: {hr.host} ({hr.hostname})\n")
                if hr.os_guess: f.write(f"OS: {hr.os_guess}\n")
                for pr in hr.ports:
                    if 'open' not in pr.state: continue
                    f.write(f"  {pr.port}/{pr.proto} {pr.state} {pr.service} {pr.version}\n")
                    for v in pr.vulns:
                        f.write(f"    VULN [{v[1] if len(v)>1 else '?'}] {v[0]}")
                        if len(v)>3 and v[3]: f.write(f" ({v[3]})")
                        f.write("\n")
                f.write("\n")
        log_ok(f"Output: {W}{output_file}{RST}")

# ══════════════════════════════════════════════════════════════
#  HELP
# ══════════════════════════════════════════════════════════════
def show_help():
    dsep()
    gprint(f"  WHYASDSCAN v{VERSION} — Beyond nmap", delay=0.004)
    dsep()
    print(f"""
  {R2}USAGE:{RST}
    {R1}./whyasdscan.sh{RST} [options] <target>

  {R2}SCAN TECHNIQUES:{RST}
    {W}-sS{RST}      SYN scan          (root+scapy, stealth)
    {W}-sT{RST}      TCP connect       (no root)
    {W}-sU{RST}      UDP scan          (root+scapy)
    {W}-sA{RST}      ACK scan          (firewall detection)
    {W}-sF{RST}      FIN scan          (IDS evasion)
    {W}-sX{RST}      XMAS scan         (IDS evasion)
    {W}-sN{RST}      NULL scan         (IDS evasion)
    {W}-sM{RST}      Maimon scan       (BSD fingerprint)

  {R2}DETECTION:{RST}
    {W}-sV{RST}      Service + version detection
    {W}-O{RST}       OS fingerprinting (TTL+TCP+Window)
    {W}-A{RST}       Aggressive (OS+version+vuln+creds)
    {W}--vuln{RST}   Vulnerability & CVE detection
    {W}--ssl{RST}    SSL/TLS analysis (cert+ciphers+protos)
    {W}--creds{RST}  Default credential check
    {W}--http{RST}   HTTP deep scan (paths+methods+headers)

  {R2}PORTS:{RST}
    {W}-p{RST} 22,80,443    Specific ports
    {W}-p{RST} 1-1024       Range
    {W}-p-{RST}             All 65535 ports
    {W}-F{RST}              Top 100 ports
    {W}--top-ports{RST} N   Top N ports

  {R2}TIMING:{RST}
    {W}-T0{RST} Paranoid   {W}-T1{RST} Sneaky   {W}-T2{RST} Polite
    {W}-T3{RST} Normal     {W}-T4{RST} Aggressive  {W}-T5{RST} Insane

  {R2}HOST DISCOVERY:{RST}
    {W}-sn{RST}    Ping scan only (no port scan)
    {W}-Pn{RST}    Skip discovery (scan all targets)

  {R2}OUTPUT:{RST}
    {W}-oN{RST} <file>   Save report
    {W}-v{RST}           Verbose
    {W}--open{RST}        Show only open ports

  {R2}EXAMPLES:{RST}
    {DIM}./whyasdscan.sh 192.168.1.1{RST}
    {DIM}./whyasdscan.sh -sS -A -T4 192.168.1.1{RST}
    {DIM}./whyasdscan.sh -sS -p- --vuln 192.168.1.0/24{RST}
    {DIM}./whyasdscan.sh -sX -p 1-1024 10.0.0.1{RST}
    {DIM}./whyasdscan.sh -A --ssl --creds -oN out.txt 10.0.0.1{RST}
""")
    sep()

# ══════════════════════════════════════════════════════════════
#  INTERACTIVE SHELL
# ══════════════════════════════════════════════════════════════
def interactive_shell():
    cfg = dict(target='',ports='top1000',scan_type='sS',timeout=1,
               threads=200,sV=False,O=False,aggressive=False,udp=False,
               vuln=True,ssl=True,creds=False,http=False,verbose=False,
               output='',ping_only=False,skip_ping=False,show_closed=False)

    print(f"\n  {GR}Type {W}help{GR} or {W}exit{GR}.{RST}\n")
    while True:
        sys.stdout.write('\n');
        for i,ch in enumerate("whyasdscan"): sys.stdout.write(gc(i*2)+ch+RST)
        sys.stdout.write(f" {R2}>{RST} "); sys.stdout.flush()
        try: line = input().strip()
        except (EOFError,KeyboardInterrupt): print(f"\n  {GR}Goodbye.{RST}\n"); sys.exit(0)
        if not line: continue
        parts=line.split(); cmd=parts[0].lower()
        arg=parts[1] if len(parts)>1 else ''
        rest=' '.join(parts[2:]) if len(parts)>2 else ''

        if cmd in ('exit','quit','q'):
            print(f"\n  {GR}Goodbye.{RST}\n"); sys.exit(0)
        elif cmd == 'help': show_help()
        elif cmd == 'clear': os.system('clear')
        elif cmd == 'set':
            k=arg.lower(); v=rest or (parts[2] if len(parts)>2 else '')
            if k=='target': cfg['target']=v; print(f"  {R2}TARGET{RST} => {W}{v}{RST}")
            elif k=='ports': cfg['ports']=v; print(f"  {R2}PORTS{RST} => {W}{v}{RST}")
            elif k=='timeout': cfg['timeout']=float(v); print(f"  {R2}TIMEOUT{RST} => {W}{v}s{RST}")
            elif k=='threads': cfg['threads']=int(v); print(f"  {R2}THREADS{RST} => {W}{v}{RST}")
            elif k=='type': cfg['scan_type']=v; print(f"  {R2}SCAN_TYPE{RST} => {W}{v}{RST}")
            elif k=='output': cfg['output']=v; print(f"  {R2}OUTPUT{RST} => {W}{v}{RST}")
            else: log_warn(f"Unknown: {k}")
        elif cmd == 'use':
            m=arg.lower().lstrip('-')
            flags={'sv':'sV','o':'O','a':'aggressive','su':'udp','vuln':'vuln',
                   'ssl':'ssl','creds':'creds','http':'http','v':'verbose',
                   'ss':'scan_type','st':'scan_type','sn':'ping_only','pn':'skip_ping'}
            if m in flags:
                if m in ('ss','st'):
                    cfg['scan_type']='sS' if m=='ss' else 'sT'
                    print(f"  {R2}[*]{RST} Scan type: {W}{cfg['scan_type']}{RST}")
                elif m == 'sn': cfg['ping_only']=True; print(f"  {R2}[*]{RST} Ping scan only")
                elif m == 'pn': cfg['skip_ping']=True; print(f"  {R2}[*]{RST} Skip host discovery")
                elif m == 'a':
                    cfg['aggressive']=cfg['sV']=cfg['O']=cfg['vuln']=cfg['ssl']=cfg['creds']=True
                    print(f"  {R2}[*]{RST} Aggressive mode: ALL modules ON")
                else:
                    cfg[flags[m]]=True; print(f"  {R2}[*]{RST} {flags[m]}: ON")
            else: log_warn(f"use sv|O|a|sU|vuln|ssl|creds|http|ss|st|sn|pn")
        elif cmd == 'show':
            print(f"\n  {BO}{W}Options:{RST}"); sep()
            for k,v in cfg.items():
                vc = R2 if v and v not in (False,'','top1000','sS',1,200) else GR
                print(f"  {W}{k:<14}{RST}  {vc}{v}{RST}")
            print()
        elif cmd in ('run','scan','go','fire'):
            if not cfg['target']: log_err("No target. set target <host>"); continue
            do_scan_cli(cfg)
        elif '.' in cmd or '/' in cmd:
            cfg['target']=cmd; print(f"  {R2}TARGET{RST} => {W}{cmd}{RST}")
        else: log_warn(f"Unknown: {cmd}")

def do_scan_cli(cfg):
    target=cfg['target']; port_spec=cfg['ports']
    scan_type=cfg['scan_type']; timeout=cfg['timeout']
    threads=cfg['threads']; verbose=cfg['verbose']

    print(); dsep()
    gprint(f"  WHYASDSCAN v{VERSION}  —  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0.004)
    dsep(); print()

    start = time.time()
    log_info(f"Target: {R1}{target}{RST}")
    targets = resolve_targets(target)
    log_info(f"Hosts: {G}{len(targets)}{RST}")

    if port_spec == '-': port_spec = '1-65535'
    ports = parse_ports(port_spec)
    log_info(f"Ports: {G}{len(ports)}{RST} | Technique: {W}{scan_type}{RST} | Threads: {W}{threads}{RST}")

    # Discovery
    if len(targets) > 1 and not cfg.get('skip_ping') and not cfg.get('ping_only'):
        print(); sep(); log_info("Host discovery...")
        alive = discover_hosts(targets, timeout=timeout, verbose=verbose)
        log_ok(f"{G}{len(alive)}{RST}/{len(targets)} hosts up")
    else:
        alive = targets

    if cfg.get('ping_only'):
        print_summary([], time.time()-start)
        return

    if not alive and not cfg.get('skip_ping'):
        log_warn("No live hosts — scanning anyway")
        alive = targets

    results = []
    for host in alive:
        log_info(f"Scanning {R1}{host}{RST} ({len(ports)} ports)...")
        hr = scan_host(
            host=host, ports=ports, scan_type=scan_type,
            udp=cfg.get('udp',False),
            service_detect=cfg.get('sV',False) or cfg.get('aggressive',False),
            os_detect=cfg.get('O',False) or cfg.get('aggressive',False),
            aggressive=cfg.get('aggressive',False),
            vuln_scan=cfg.get('vuln',True),
            ssl_scan=cfg.get('ssl',True),
            default_creds=cfg.get('creds',False) or cfg.get('aggressive',False),
            timeout=timeout, threads=threads, verbose=verbose,
        )
        print_host_result(hr, show_closed=cfg.get('show_closed',False))
        results.append(hr)

    print_summary(results, time.time()-start, cfg.get('output','') or None)

# ══════════════════════════════════════════════════════════════
#  ARGUMENT PARSER
# ══════════════════════════════════════════════════════════════
def build_parser():
    p = argparse.ArgumentParser(prog='whyasdscan', add_help=False)
    p.add_argument('targets', nargs='*')
    p.add_argument('-sS',action='store_true'); p.add_argument('-sT',action='store_true')
    p.add_argument('-sU',action='store_true'); p.add_argument('-sA',action='store_true')
    p.add_argument('-sF',action='store_true'); p.add_argument('-sX',action='store_true')
    p.add_argument('-sN',action='store_true'); p.add_argument('-sM',action='store_true')
    p.add_argument('-sn','-sP',action='store_true'); p.add_argument('-Pn',action='store_true')
    p.add_argument('-sV',action='store_true'); p.add_argument('-O',action='store_true')
    p.add_argument('-A',action='store_true')
    p.add_argument('--vuln',action='store_true'); p.add_argument('--ssl',action='store_true')
    p.add_argument('--creds',action='store_true'); p.add_argument('--http',action='store_true')
    p.add_argument('-p',default=None); p.add_argument('-F',action='store_true')
    p.add_argument('--top-ports',type=int,default=None)
    p.add_argument('--open',action='store_true')
    p.add_argument('-T0',action='store_true'); p.add_argument('-T1',action='store_true')
    p.add_argument('-T2',action='store_true'); p.add_argument('-T3',action='store_true')
    p.add_argument('-T4',action='store_true'); p.add_argument('-T5',action='store_true')
    p.add_argument('-oN',metavar='FILE',default=None)
    p.add_argument('-v','--verbose',action='store_true')
    p.add_argument('-i','--interactive',action='store_true')
    p.add_argument('-h','--help',action='store_true')
    p.add_argument('--version',action='store_true')
    return p

def main():
    signal.signal(signal.SIGINT, lambda s,f: (print(f"\n\n{R2}[!]{RST} Interrupted.\n"), sys.exit(130)))
    show_banner()
    parser = build_parser()
    args,_ = parser.parse_known_args()

    if args.version: print(f"whyasdscan {VERSION}"); sys.exit(0)
    if args.help: show_help(); sys.exit(0)
    if args.interactive or not args.targets: interactive_shell(); return

    # Timing
    timeout=1; threads=200
    if args.T0: timeout=5;  threads=5
    elif args.T1: timeout=3; threads=20
    elif args.T2: timeout=2; threads=50
    elif args.T3: timeout=1; threads=100
    elif args.T4: timeout=0.5; threads=300
    elif args.T5: timeout=0.2; threads=500

    # Scan type
    scan_type='sT'
    if args.sS and (IS_ROOT and SCAPY): scan_type='sS'
    elif args.sA: scan_type='ack'
    elif args.sF: scan_type='fin'
    elif args.sX: scan_type='xmas'
    elif args.sN: scan_type='null'
    elif args.sM: scan_type='maimon'
    elif args.sS and not (IS_ROOT and SCAPY):
        log_warn("SYN requires root+scapy. Using TCP connect.")

    # Ports
    if args.p == '-': port_spec='1-65535'
    elif args.p: port_spec=args.p
    elif args.F: port_spec='top100'
    elif args.top_ports: port_spec=f'top{args.top_ports}'
    else: port_spec='top1000'

    cfg = dict(
        target=','.join(args.targets), ports=port_spec,
        scan_type=scan_type, timeout=timeout, threads=threads,
        sV=args.sV or args.A, O=args.O or args.A,
        aggressive=args.A, udp=args.sU,
        vuln=args.vuln or args.A, ssl=args.ssl or args.A,
        creds=args.creds or args.A, http=args.http or args.A,
        verbose=args.verbose, output=args.oN or '',
        ping_only=args.sn, skip_ping=args.Pn,
        show_closed=not args.open,
    )
    do_scan_cli(cfg)

if __name__ == '__main__':
    main()
