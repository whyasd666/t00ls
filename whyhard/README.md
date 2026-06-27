# whyhard

Кросс-дистрибутивный инструмент Linux hardening (audit + fix). Тот же
архитектурный подход, что и в [WhySentry](https://github.com/whyasd666/t00ls):
статический Go-бинарник без CGO, модульный Core Engine — но в отличие от
WhySentry (демон) whyhard — однопроходный: запускается, проверяет систему,
по желанию фиксит, печатает отчёт и завершается.

```
[ cross-distro Linux hardening // CIS-style audit+fix // CVC ]
static binary // no CGO // any-distro // any-init
```

## Философия: tiered safety, а не "закрыть все дырки одним махом"

Хардеринг-тулы, которые бездумно правят всё подряд, регулярно сами
становятся причиной инцидента — отключили пароль без ключей и потеряли
доступ к серверу, выключили нужный сервис, обрезали права на файл, который
требовался демону. whyhard разделяет каждую находку на уровень риска:

| Risk | Когда применяется | Примеры |
|---|---|---|
| `safe` | `--apply` | sysctl, права на файлы, login.defs, баннеры — никогда не оборвут доступ |
| `risky` | `--apply-risky` | `PermitRootLogin no`, `PasswordAuthentication no`, остановка legacy-сервисов |
| `report-only` | никогда (только аудит) | пустые пароли, дубли UID 0, world-writable файлы — решение всегда за человеком |

Дополнительно: `PasswordAuthentication no` применяется только если в
системе действительно есть хотя бы один настроенный `authorized_keys`
(`/root/.ssh/` или `/home/*/.ssh/`) — иначе фикс пропускается со статусом
`SAFE-SKIP`, чтобы не отрезать единственный способ зайти на сервер.

Это тот же принцип, что и в Monitor Module WhySentry: автоматическое
действие применяется только когда оно не может само стать инцидентом.

## Архитектура

```
cmd/whyhard/main.go         — CLI (flag), сборка Core Engine, печать отчёта
internal/core/               — Mode/Finding/Severity/Risk + интерфейс Module
internal/checks/sysctl.go    — hardening параметров ядра/сети (safe)
internal/checks/filesystem.go— права критичных файлов, world-writable scan, mount-флаги tmp
internal/checks/ssh.go       — hardening sshd_config (safe + risky)
internal/checks/accounts.go  — login.defs policy (safe) + пустые пароли/дубли UID 0 (report-only)
internal/checks/banner.go    — legal warning в /etc/issue, /etc/issue.net (safe)
internal/checks/services.go  — legacy-демоны (telnet/rsh/rlogin/tftp), risky
internal/report/             — цветной summary, hardening score, отчёт в файл
internal/logger/, internal/banner/ — тот же стиль, что у whysentry
whyhard.sh                   — единая точка входа (build-if-needed + exec)
```

Каждый модуль реализует:

```go
type Module interface {
    Name() string
    Run(mode Mode) []Finding
}
```

`core.Engine` запускает модули последовательно (порядок важен — backup
файла должен случиться до его правки внутри модуля) и собирает все
находки в общий отчёт.

## Что проверяет/фиксит

**sysctl** (`/proc/sys`, персистентно в `/etc/sysctl.d/99-whyhard.conf`):
ICMP redirects/source-route, rp_filter, SYN cookies, ASLR, `dmesg_restrict`,
`kptr_restrict`, `fs.protected_hardlinks/symlinks`, `fs.suid_dumpable`.
Форвардинг трафика (`ip_forward`) сознательно не трогается — это
функциональная настройка, а не дырка.

**filesystem**: права на `/etc/shadow`, `/etc/gshadow`, host-ключи SSH,
`grub.cfg` → safe chmod. Поиск world-writable файлов без sticky bit в
`/etc`, `/usr`, `/opt`, `/var/www` → report-only (до 25 находок). Флаги
монтирования `noexec,nosuid,nodev` для `/tmp`, `/var/tmp`, `/dev/shm` →
risky (remount может сломать ПО, исполняющее файлы из tmp).

**ssh**: 9 safe-директив (`X11Forwarding no`, `MaxAuthTries 3`,
`ClientAliveInterval`, `PermitEmptyPasswords no`, и т.д.) + 2 risky
(`PermitRootLogin no`, `PasswordAuthentication no`, с проверкой
authorized_keys). Бэкап `sshd_config` перед каждой правкой. **whyhard
никогда не делает `systemctl reload/restart sshd` сам** — печатает
инструкцию проверить `sshd -t` и перезагрузить конфиг вручную.

**accounts**: `PASS_MAX_DAYS`/`PASS_MIN_DAYS`/`PASS_WARN_AGE`/`UMASK` в
`login.defs` (safe, влияет только на новые аккаунты). Аудит пустых
паролей в `/etc/shadow` и не-root аккаунтов с UID 0 (report-only —
whyhard никогда не блокирует/удаляет аккаунты автоматически).

**banner**: легальное предупреждение о мониторинге в `/etc/issue` и
`/etc/issue.net` (safe, текст в коде, легко адаптировать под свою
организацию).

**services**: `telnet`, `rsh`, `rlogin`, `rexec`, `tftp` — если активны,
останавливаются и отключаются только с `--apply-risky`. Модуль
пропускается целиком на системах без `systemd`.

## Сборка

```bash
CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o whyhard ./cmd/whyhard
file whyhard   # ELF 64-bit ... statically linked
```

## Запуск

```bash
./whyhard.sh                  # audit — только чтение, ничего не меняет
sudo ./whyhard.sh --apply        # + все safe-фиксы
sudo ./whyhard.sh --apply-risky  # + risky-фиксы (внимательно прочитайте вывод)
sudo ./whyhard.sh --apply --report /var/log/whyhard.txt
```

`whyhard.sh` — единая точка входа: собирает бинарник при первом запуске
(если нужно) и сразу выполняет (`exec`).

Exit code: `0`, если не осталось непокрытых находок с severity
`high`/`critical` — удобно для cron/CI (`whyhard --apply || alert`).

## Известные ограничения MVP

- `ssh`-модуль парсит `sshd_config` построчно без обработки `Match`-блоков
  — если у вас сложная конфигурация с условными блоками, перепроверьте
  итоговый файл вручную перед `reload`.
- World-writable сканер ограничен 25 находками и несколькими каталогами —
  это не замена полноценному файловому аудиту на больших серверах.
- `services`-модуль покрывает явно легаси-демоны; не пытается угадывать,
  какие современные сервисы вам "не нужны" — это решение специфично для
  каждого сервера и не должно приниматься автоматически.
- Hardening score — приблизительная метрика (доля проверок в норме), не
  сертификация по CIS Benchmark/PCI-DSS и т.п.
