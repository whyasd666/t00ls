<div align="center">

```
 ▄█     █▄    ▄█    █▄    ▄██   ▄      ▄████████   ▄████████ ████████▄  
███     ███  ███    ███  ███   ██▄    ███    ███  ███    ███ ███   ▀███ 
███     ███  ███    ███  ███▄▄▄███    ███    ███  ███    █▀  ███    ███ 
███     ███  ███    ███  ▀▀▀▀▀▀███   ▄███▄▄▄▄██▀  ███        ███    ███ 
███     ███  ███    ███  ▄██   ███  ▀▀███▀▀▀▀▀    ███        ███    ███ 
███     ███  ███    ███  ███   ███  ▀███████████  ███    █▄  ███    ███ 
███ ▄█▄ ███  ███    ███  ███   ███    ███    ███  ███    ███ ███   ▄███ 
 ▀███▀███▀    ▀██████▀    ▀█████▀     ███    ███  ████████▀  ████████▀  
                                       ███    ███                       
```

### offensive security toolkit — by [whyasd666](https://github.com/whyasd666)

`#1 RU · TryHackMe King of the Hill` · CTF / bug bounty · team **CVC**

[![Python](https://img.shields.io/badge/python-3.8+-39FF14?style=flat-square&logo=python&logoColor=black)](https://python.org)
[![Bash](https://img.shields.io/badge/bash-4.0+-ff1a1a?style=flat-square&logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Go](https://img.shields.io/badge/go-1.22+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-555?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-39FF14?style=flat-square)](https://github.com/whyasd666/t00ls)

</div>

---

> Набор кастомных утилит для пентеста, CTF и red team тренировок. Каждый тул — свой
> цвет, свой баннер, свой характер. Сделано под себя, выложено для всех.

## ⚠ Disclaimer

Инструменты предназначены **только** для авторизованного тестирования: CTF,
bug bounty в рамках программы, пентест по договору / письменному разрешению
владельца системы. Автор не несёт ответственности за использование во вред.
No warranty, used at your own risk.

---

## 📦 Состав тулкита

| Tool | Назначение | Стек | Палитра |
|---|---|---|---|
| [`whyxss.py`](#-whyxsspy) | XSS-сканер (reflected / DOM / blind) | Python 3 | acid green |
| [`whyasdscan.py`](#-whyasdscanpy) | Сетевой сканер (port scan + vuln detect) | Python 3 + scapy | acid red |
| [`whytrix.py`](#-whytrixpy) | Сканер уязвимостей Bitrix CMS | Python 3 | blue → violet → pink |
| [`whyproc.sh`](#-whyprocsh) | Live-монитор процессов для CTF | Bash | red gradient |
| [`whysentry`](#-whysentry) | Host-агент защиты: детект reverse shell + SUID-аудит (EDR/SOAR-lite) | Go (static, no CGO) | blood red / signal magenta |
| [`whyhard`](#-whyhard) | Кросс-дистрибутивный Linux hardening (audit + fix): sysctl, SSH, accounts, SUID/permissions, legacy-сервисы | Go (static, no CGO) | acid red / safety yellow |

---

## 🚀 Установка

```bash
git clone https://github.com/whyasd666/t00ls.git
cd t00ls
chmod +x *.sh

# Зависимости (requests, beautifulsoup4, scapy) — авто через install.sh,
# либо руками:
pip install requests beautifulsoup4 scapy --break-system-packages
```

`install.sh` сам пробует `apt` → `pip --break-system-packages` → `pipx` →
venv-фоллбэк (`~/.whyasdscan-venv`), если систему не даёт трогать напрямую.

```bash
./install.sh
```

---

## 🟢 whyxss.py

XSS-сканер уровня XSStrike: краулинг форм, DOM-анализ, фаззинг параметров,
поддержка blind XSS и кастомных пейлоадов.

```bash
$ python3 whyxss.py -u https://target.com --forms --dom --level 3
```

**Возможности:**
- Обход и тест всех форм на странице (`--forms`)
- DOM-based XSS анализ (`--dom`)
- Фаззинг GET/POST параметров (`--fuzzer`)
- Blind XSS пейлоады для асинхронных колбэков (`--blind`)
- Кастомный пейлоад вручную (`--payload`)
- Многопоточность (`--threads`), proxy, кастомные cookies/headers
- Экспорт результатов в файл (`-o report.json`)

| Флаг | Описание |
|---|---|
| `-u, --url` | Целевой URL |
| `-f, --file` | Список URL из файла |
| `--forms` | Сканировать HTML-формы |
| `--dom` | DOM XSS анализ |
| `--fuzzer` | Фаззинг параметров |
| `--blind` | Blind XSS режим |
| `--level N` | Глубина проверки (1–3) |
| `--threads N` | Кол-во потоков |
| `-i, --interactive` | Интерактивный режим |
| `-o, --output` | Файл отчёта |

---

## 🔴 whyasdscan.py

Сетевой сканер «за пределами nmap»: SYN/UDP/ACK/FIN/XMAS/NULL-сканы поверх
scapy, детект сервисов и версий, базовый SSL-анализ, проверка дефолтных
кредов, подсказки по CVE для найденных версий ПО.

```bash
$ sudo python3 whyasdscan.py 192.168.1.0/24 -sS --top-ports 1000 -A
```

**Возможности:**
- Типы сканов: `-sS` SYN, `-sT` TCP connect, `-sU` UDP, `-sA` ACK, `-sF` FIN,
  `-sX` XMAS, `-sN` NULL, `-sn` ping scan
- Детект ОС и версий сервисов (`-O`, `-sV`), агрессивный режим (`-A`)
- Поиск известных уязвимостей по баннерам (`--vuln`)
- Анализ SSL/TLS-конфигурации (`--ssl`)
- Проверка дефолтных учётных данных (`--creds`)
- Тайминг-профили `-T0`…`-T5` (от stealth до insane)
- Экспорт в файл (`-oN report.txt`)

> Без root — только TCP connect scan. С root (`sudo`) — полный набор:
> SYN/UDP/OS detection.

| Флаг | Описание |
|---|---|
| `-sS / -sT / -sU / -sA / -sF / -sX / -sN` | Тип скана |
| `-p, -F, --top-ports` | Диапазон / быстрый / топ-N портов |
| `-A` | Агрессивный режим (OS + version + vuln + script) |
| `--vuln` | Поиск уязвимостей по баннерам |
| `--ssl` | SSL/TLS-анализ |
| `--creds` | Дефолтные креды |
| `-T0`…`-T5` | Скорость скана |
| `-oN FILE` | Сохранить отчёт |

---

## 🟣 whytrix.py

Сканер уязвимостей для сайтов на **1C-Битрикс**: проверка типовых
SQLi/XSS/LFI/SSRF, обход авторизации, утечки данных, опасные конфиги,
известные CVE для модулей Bitrix, открытые редиректы, API-эндпоинты.

```bash
$ python3 whytrix.py -u https://target.ru --all
```

**Возможности:**
- Полный скан всех категорий (`--all`) либо точечно: `--sqli`, `--xss`,
  `--lfi`, `--ssrf`, `--auth`, `--redirect`, `--upload`, `--api`
- Брутфорс типовых путей и админок Bitrix (`--paths`)
- Сверка версии с базой известных CVE (`--cves`)
- Анализ заголовков безопасности (`--headers`)
- Поддержка cookies/proxy/UA, задержки между запросами (`--delay`)
- Экспорт отчёта (`-o report.json`)

| Флаг | Описание |
|---|---|
| `-u, --url` | Целевой сайт на Bitrix |
| `--all` | Полный скан по всем категориям |
| `--sqli / --xss / --lfi / --ssrf / --auth` | Точечная проверка категории |
| `--paths` | Брут типовых путей/админок Bitrix |
| `--cves` | Сверка версии с базой CVE |
| `--proxy / --cookies / --ua` | Сетевые параметры запроса |
| `-o, --output` | Файл отчёта |

---

## 🔥 whyproc.sh

Live-монитор процессов на базе `/proc` — без зависимостей, без root.
Сделан для CTF: подсвечивает реверс-шеллы, веб-шеллы, привилегированные
команды (`sudo`/`su`/`pkexec`), файловые операции, архивацию, передачу
файлов и другие категории действий прямо в реальном времени.

```bash
$ ./whyproc.sh
```

**Возможности:**
- Классификация процессов по категориям: `REVSH`, `WSHELL`, `SSH`, `PRIV`,
  `VIEW`, `EDIT`, `FILE`, `ARCH`, `XFER` и др.
- Цветовая индикация важности (от обычных команд до подозрительных паттернов)
- Резолв пользователя и tty процесса через `/proc/<pid>/status` и `stat`
- Полностью на bash + `/proc`, работает на любой Linux-машине CTF-таргета
  без установки пакетов

---

## 🛡 whysentry

Host-агент активной защиты для Linux (EDR/SOAR-lite) — первый
**defensive** тул в этом репо, остальные выше offensive. Ставится на сервер
и работает в фоне постоянно, а не запускается разово против цели: детектит
reverse shell в реальном времени и аудитит SUID privesc-векторы при старте.

```bash
$ sudo ./whysentry.sh
```

**Возможности:**
- Модульная архитектура (Core Engine + Monitor / Response / Audit) на общем
  Go-интерфейсе `core.Module`, легко расширяется новыми модулями
- Детект reverse shell по живому сетевому сокету на `stdin/stdout/stderr`
  процесса (`/proc/[pid]/fd`) — это и есть техническая суть reverse shell,
  почти нулевой false-positive → авто-kill (`syscall.Kill`, `SIGKILL`)
- Доп. слой — якорные regex-сигнатуры известных one-liner'ов (`/dev/tcp/`,
  `nc -e /bin/sh`, `pty.spawn(`, `socket.socket()+connect/dup2`, ...), но
  только как **low-confidence** warning без авто-действия: текстовый анализ
  cmdline в принципе не может надёжно отличить «упомянуто» от «исполняется»
- Разовый SUID privesc sweep при старте — сверка с GTFOBins-кандидатами
  (`find`, `vim`, `pkexec`, `awk`, `nmap`, `perl`, ...)
- Один статический бинарник, `CGO_ENABLED=0` — без пересборки работает на
  Ubuntu / Debian / CentOS / Rocky / Alpine, независимо от glibc/musl и
  init-системы (systemd / OpenRC)

| Модуль | Назначение |
|---|---|
| `core` | Диспетчер модулей, graceful shutdown по `SIGINT`/`SIGTERM` |
| `monitor` | Скан `/proc` каждые 2-3с, детект reverse shell (socket-stdio + паттерны) |
| `response` | `syscall.Kill(pid, SIGKILL)` + структурированный лог события |
| `audit` | Разовый SUID-скан при старте по ключевым каталогам ФС |

> `whysentry.sh` — единая точка входа: если бинарник не собран, соберёт
> (`go build`, статически) и сразу запустит. Нужен root — для чтения
> `/proc/[pid]/fd` чужих процессов и `syscall.Kill` за пределами своего uid.

---

## 🟡 whyhard

Кросс-дистрибутивный инструмент Linux hardening (audit + fix) — второй
defensive-тул в репо, тот же подход к архитектуре, что у `whysentry`
(статический Go, Core Engine + модули), но однопроходный: проверил,
по желанию исправил, напечатал отчёт, вышел — а не работает в фоне.

```bash
$ ./whyhard.sh                  # audit — только чтение, ничего не меняет
$ sudo ./whyhard.sh --apply        # + безопасные фиксы
$ sudo ./whyhard.sh --apply-risky  # + рискованные фиксы (внимательно!)
```

**Философия — tiered safety, не "закрыть всё одним махом":** каждая
находка размечена уровнем риска применения фикса:

| Risk | Когда применяется | Примеры |
|---|---|---|
| `safe` | `--apply` | sysctl, права на файлы, login.defs, баннеры |
| `risky` | `--apply-risky` | `PermitRootLogin no`, `PasswordAuthentication no`, стоп legacy-сервисов |
| `report-only` | никогда (только аудит) | пустые пароли, дубли UID 0, world-writable файлы |

`PasswordAuthentication no` дополнительно проверяется на наличие хотя бы
одного `authorized_keys` в системе — иначе фикс пропускается, чтобы не
отрезать себе единственный путь на сервер.

**Возможности:**
- **sysctl** — ICMP redirects/source-route, rp_filter, SYN cookies, ASLR,
  `dmesg_restrict`, `kptr_restrict`, `fs.protected_*`, персистентно в
  `/etc/sysctl.d/99-whyhard.conf`
- **filesystem** — права `/etc/shadow`, SSH host-ключей, `grub.cfg`;
  поиск world-writable файлов без sticky bit; `noexec/nosuid/nodev` для
  `/tmp`, `/var/tmp`, `/dev/shm`
- **ssh** — 9 safe-директив (`X11Forwarding no`, `MaxAuthTries`, и т.д.) +
  2 risky (`PermitRootLogin`, `PasswordAuthentication`); backup перед
  каждой правкой; **никогда не делает `reload/restart sshd` сам**
- **accounts** — password policy в `login.defs`; аудит пустых паролей и
  не-root аккаунтов с UID 0 (report-only)
- **banner** — legal warning в `/etc/issue`, `/etc/issue.net`
- **services** — `telnet`/`rsh`/`rlogin`/`rexec`/`tftp`, отключение
  только с `--apply-risky`

| Модуль | Назначение |
|---|---|
| `sysctl` | Hardening параметров ядра/сети |
| `filesystem` | Права критичных файлов + world-writable scan + mount-флаги |
| `ssh` | Hardening `sshd_config` с защитой от lockout |
| `accounts` | Password policy + аудит подозрительных аккаунтов |
| `banner` | Legal-баннер при логине |
| `services` | Аудит/отключение legacy-демонов |

> Печатает цветной summary с **hardening score** (% проверок в норме) и
> сохраняет полный отчёт в файл. Exit code `0`, если не осталось
> непокрытых находок high/critical — удобно для cron/CI.

---

## 🛠 Стек

`Python 3` · `Bash` · `Go` · `scapy` · `requests` · `BeautifulSoup4` · `/proc` · `syscall` · `argparse`

## 📡 Контакты

- Telegram: [@whyasd666](https://t.me/whyasd666)
- TryHackMe: [whyasd666](https://tryhackme.com/p/whyasd666) — `#1 RU King of the Hill`
- Team: **CVC** (CTF / bug bounty)
- Портфолио: [whyasd666.github.io/whyasd-bio](https://whyasd666.github.io/whyasd-bio/)

---

<div align="center">

`PRs и issues — велкам. Используй с умом.`

</div>
