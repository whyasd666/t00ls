# WhySentry

Легковесный кросс-дистрибутивный агент безопасности для Linux (EDR/SOAR-lite).
Статический бинарник, без CGO, без зависимостей от glibc/musl/systemd/OpenRC.

```
[ host intrusion containment // EDR-SOAR-lite // CVC ]
static binary // no CGO // any-distro // any-init
```

## Архитектура

```
cmd/whysentry/main.go     — точка входа, сборка Core Engine, graceful shutdown
internal/core/            — Core Engine: общий интерфейс Module + диспетчер жизненного цикла
internal/monitor/         — Monitor Module: сканирование /proc, детект reverse shell
internal/response/        — Response Module: SIGKILL + структурированный лог события
internal/audit/           — Audit Module: разовый sweep SUID-бинарников при старте
internal/logger/          — цветной ANSI-логгер (INFO/WARN/ERR/KILL)
internal/banner/          — ASCII-banner при старте
whysentry.sh               — единая точка входа (build-if-needed + exec)
```

Все модули реализуют единый контракт `core.Module`:

```go
type Module interface {
    Name() string
    Start(ctx context.Context) error
}
```

Core Engine регистрирует модули и запускает каждый в своей горутине; общий
`context.Context` с `signal.NotifyContext(SIGINT, SIGTERM)` обеспечивает
синхронный graceful shutdown всех модулей сразу.

## Monitor Module — логика детекта (важно)

Первая версия детектила reverse shell простым substring-поиском по всей
`/proc/[pid]/cmdline` — это привело к false positive: легитимный процесс был
убит, потому что строка `/dev/tcp/` встретилась **в комментарии** внутри
длинного скрипта, а не в реально исполняемом коде. Текстовый анализ
командной строки в принципе не может надёжно отличить «паттерн упомянут» от
«паттерн исполняется» — поэтому детект разделён на два уровня уверенности:

**Tier 1 — auto-kill (высокая уверенность).**
Проверяется, что у процесса (из списка целевых бинарников: `sh`, `bash`,
`python`, `perl`, `nc`, `socat`, ...) хотя бы один из дескрипторов
`stdin/stdout/stderr` (`/proc/[pid]/fd/{0,1,2}`) — это **сетевой сокет**, а
не tty/файл/pipe. Дублирование сокета на стандартные потоки — это и есть
техническая суть reverse shell, и легитимные процессы такого практически
никогда не делают. Только это срабатывание приводит к `syscall.Kill`.

**Tier 2 — low-confidence, без авто-kill.**
Якорные regex-сигнатуры (`/dev/(tcp|udp)/<host>/<port>`, `nc ... -e /bin/sh`,
`pty.spawn(`, связки `socket.socket()+.connect(`/`dup2`, `IO::Socket`,
`stream_socket_client` и т.п.) — и только для **компактного** cmdline
(≤ 320 символов: реальные one-liner'ы короткие, а «простыни»-скрипты
сознательно не проверяются паттернами). Совпадение только логируется
(`WARN`) для ручного разбора/эскалации — никакого автоматического действия.

Целевой бинарник определяется через `/proc/[pid]/exe` (надёжнее `comm`,
который усечён до 15 символов и легче подделывается через `argv[0]`), с
fallback на `comm`, если `exe` недоступен.

## Audit Module — SUID privesc sweep

При старте агента (разовый проход, не блокирует остальные модули):
обходит `/usr`, `/bin`, `/sbin`, `/usr/local`, `/opt` через `filepath.WalkDir`,
ищет файлы с `os.ModeSetuid` и сверяет basename со списком потенциально
опасных бинарников (`find`, `vim`/`vi`, `nano`, `pkexec`, `awk`/`gawk`,
`nmap`, `perl`, `python`/`python3`, `bash`, `cp`, `less`, `more`, `env`,
`tar` — см. GTFOBins). Найденные опасные SUID-бинарники логируются как
`WARN`, остальные SUID-файлы — как информационная строка `INFO`.

## Сборка

```bash
CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o whysentry ./cmd/whysentry
file whysentry   # ELF 64-bit ... statically linked
```

Без CGO и динамических зависимостей — один и тот же бинарник запускается на
Ubuntu/Debian/CentOS/Rocky/Alpine независимо от версии glibc/musl и
init-системы (systemd/OpenRC), т.к. агент не трогает init вообще, только
`/proc` и `syscall.Kill`.

## Запуск

```bash
sudo ./whysentry.sh
```

`whysentry.sh` — единая точка входа: если бинарник `./whysentry` уже собран,
сразу запускает его (`exec`); если нет — собирает (`go build`, статически) и
затем запускает. Рут нужен, чтобы:
- читать `/proc/[pid]/fd/*` и `/proc/[pid]/exe` любых процессов, не только
  своего пользователя;
- иметь право `syscall.Kill` на процессы других пользователей;
- читать SUID-биты во всех системных каталогах.

## Известные ограничения MVP

- Tier 2 (regex) — это именно low-confidence сигнал; он специально не убивает
  процесс, т.к. это принципиально ненадёжно по самой природе текстового
  анализа cmdline. Основной защитный механизм — Tier 1 (socket-stdio).
- Сетевой namespace процесса не проверяется — детект socket-stdio видит
  любой AF_INET/AF_INET6/AF_UNIX сокет на стандартных потоках, независимо от
  адреса назначения (это сознательное расширение охвата, а не баг).
- Audit Module — разовый sweep при старте, не watch-режим (для MVP).
