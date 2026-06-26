// Package monitor реализует Модуль Мониторинга Процессов (Monitor Module).
// Каждые N секунд сканирует /proc и для процессов из списка "целевых"
// бинарников (оболочки/интерпретаторы/netcat-семейство) проверяет два
// независимых сигнала reverse shell:
//
//  1. (основной, низкий false-positive) — живой сетевой сокет на
//     stdin/stdout/stderr процесса. Это и есть техническая суть reverse
//     shell: дублирование файлового дескриптора сокета на стандартные
//     потоки. У легитимных процессов такого практически не бывает.
//  2. (вторичный) — якорные regex-сигнатуры классических one-liner'ов,
//     но ТОЛЬКО для коротких cmdline. Длинные "простыни" (скрипты,
//     heredoc, текст со случайным упоминанием паттерна) не матчатся —
//     именно так в первой версии агент убил легитимный процесс, в
//     cmdline которого встретилась строка "/dev/tcp/" внутри комментария.
//
// Найденные PID отправляются в Response Module через переданный канал.
package monitor

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"whysentry/internal/logger"
	"whysentry/internal/response"
)

// suspiciousNames — целевые бинарники. Детект работает ТОЛЬКО для
// процессов, чьё реальное имя exe (или comm как fallback) входит в этот
// список. Любой другой процесс (компилятор, тест-раннер, текстовый
// редактор и т.п.) пропускается мгновенно, ещё до чтения cmdline —
// это и есть требование "проверяй только целевые бинарники".
var suspiciousNames = map[string]bool{
	"sh": true, "bash": true, "ash": true, "dash": true, "zsh": true, "ksh": true,
	"python": true, "python2": true, "python3": true,
	"perl": true, "perl5": true,
	"ruby": true, "php": true, "lua": true, "lua5.1": true,
	"nc": true, "ncat": true, "netcat": true, "ncat.openbsd": true, "socat": true,
	"busybox": true, "telnet": true, "awk": true, "gawk": true,
}

// sigRule — именованное regex-правило для якорного (anchored) детекта.
// В отличие от голого substring-поиска, каждый паттерн привязан к
// конкретной синтаксической форме реальной reverse-shell техники, а не
// просто к словам, которые могут случайно встретиться в тексте/комментарии.
type sigRule struct {
	name string
	re   *regexp.Regexp
}

var anchoredRules = []sigRule{
	// bash/sh: ... >& /dev/tcp/<host>/<port> ... — классический one-liner.
	{"dev-tcp-udp-redirect", regexp.MustCompile(`/dev/(tcp|udp)/[\w.\-]+/\d{1,5}`)},
	// nc/ncat/netcat -e /bin/sh — explicit shell exec через netcat.
	{"nc-exec-flag", regexp.MustCompile(`\b(nc|ncat|netcat)\b[^|;&\n]{0,40}-e\s*/bin/(sh|bash|ash)`)},
	// python pty.spawn("/bin/sh") — типичный TTY upgrade в reverse shell.
	{"python-pty-spawn", regexp.MustCompile(`pty\.spawn\(`)},
	// python: создание сокета + .connect( — связка, не просто слово "socket".
	{"python-socket-connect", regexp.MustCompile(`socket\.socket\([^)]*\)[\s\S]{0,80}\.connect\(`)},
	// python: создание сокета + dup2 — дублирование fd сокета на stdio.
	{"python-socket-dup2", regexp.MustCompile(`socket\.socket\([^)]*\)[\s\S]{0,120}dup2`)},
	// perl: IO::Socket(::INET) в связке с new/exec.
	{"perl-io-socket", regexp.MustCompile(`(?i)io::socket(::inet)?[\s\S]{0,80}(new|exec)`)},
	// php: stream_socket_client(...) в связке с exec/system/popen.
	{"php-stream-socket-client", regexp.MustCompile(`stream_socket_client\([\s\S]{0,80}(exec|system|popen)`)},
	// bash -i ... >& /dev/tcp/ — интерактивный шелл с редиректом на сокет.
	{"bash-interactive-dev-tcp", regexp.MustCompile(`bash\s+-i[\s\S]{0,40}>&\s*/dev/tcp/`)},
}

// maxCmdlineForPatternMatch — anchored-паттерны применяются только если
// длина cmdline не превышает этот порог. Реальные one-liner'ы компактные
// (обычно < 200 символов). Длинные блобы (multi-line скрипты, heredoc,
// тест-харнессы) сознательно исключены из проверки паттернов — для них
// остаётся только сигнал socket-stdio (см. ниже), который не зависит от
// длины cmdline и не даёт такого false positive.
const maxCmdlineForPatternMatch = 320

// Module — Monitor Module.
type Module struct {
	Interval time.Duration
	Out      chan response.Finding
	// killed — PID, по которым уже отправлена команда на kill (чтобы не
	// дублировать Finding между тиками, пока ядро обрабатывает SIGKILL).
	killed map[int]bool
	// warned — PID, по которым уже залогирован low-confidence паттерн,
	// чтобы не спамить одним и тем же предупреждением каждые 2-3 секунды,
	// пока процесс жив. Не блокирует дальнейшую проверку socket-stdio —
	// если позже появится подтверждённый сокет, kill всё равно сработает.
	warned map[int]bool
}

// New создаёт Monitor Module с заданным интервалом опроса и каналом вывода
// находок (как правило — Findings из response.Module).
func New(interval time.Duration, out chan response.Finding) *Module {
	return &Module{
		Interval: interval,
		Out:      out,
		killed:   make(map[int]bool),
		warned:   make(map[int]bool),
	}
}

func (m *Module) Name() string { return "monitor" }

// Start запускает периодическое сканирование /proc до отмены ctx.
func (m *Module) Start(ctx context.Context) error {
	ticker := time.NewTicker(m.Interval)
	defer ticker.Stop()

	m.scan()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			m.scan()
		}
	}
}

// scan проходит по всем PID-директориям в /proc за один тик.
func (m *Module) scan() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		logger.Error("[monitor] cannot read /proc: %v", err)
		return
	}

	live := make(map[int]bool, len(entries))

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // не PID-директория (self, net, и т.п.)
		}
		live[pid] = true
		m.inspect(pid)
	}

	// чистим карты состояния от PID, которые уже не существуют в /proc
	for pid := range m.killed {
		if !live[pid] {
			delete(m.killed, pid)
		}
	}
	for pid := range m.warned {
		if !live[pid] {
			delete(m.warned, pid)
		}
	}
}

// inspect — основная логика детекта для одного PID.
//
// Tier 1 (auto-kill, высокая уверенность): подтверждённый сетевой сокет
// на stdin/stdout/stderr. Это техническая суть reverse shell — finding
// отправляется в Response Module немедленно.
//
// Tier 2 (low-confidence, без авто-kill): якорный regex-паттерн в
// коротком cmdline. Текстовый анализ командной строки в принципе не
// может надёжно отличить "паттерн упомянут в комментарии/тексте" от
// "паттерн реально исполняется" (именно так в прошлой версии агент
// убил легитимный процесс) — поэтому такие совпадения только логируются
// для ручного разбора/SOAR-эскалации и НЕ приводят к kill.
func (m *Module) inspect(pid int) {
	if m.killed[pid] {
		return
	}

	exeName := procExeBase(pid)
	commName := procComm(pid)
	target := exeName
	if target == "" {
		target = commName
	}

	if !suspiciousNames[target] && !suspiciousNames[commName] {
		return // не целевой бинарник — дальше не смотрим вообще
	}

	cmdlineRaw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil || len(cmdlineRaw) == 0 {
		return // процесс без cmdline (kernel thread) либо уже исчез
	}
	cmdline := strings.TrimSpace(strings.ReplaceAll(string(cmdlineRaw), "\x00", " "))
	if cmdline == "" {
		return
	}

	// Tier 1: реальный сетевой сокет на stdio — финальный вердикт.
	if sockFD, ok := socketStdio(pid); ok {
		m.killAndFlag(pid, target, cmdline, "socket-stdio("+sockFD+")")
		return
	}

	// Tier 2: якорные паттерны, только для компактных cmdline, только
	// до первого предупреждения по этому PID (анти-спам).
	if m.warned[pid] || len(cmdline) > maxCmdlineForPatternMatch {
		return
	}
	for _, rule := range anchoredRules {
		if rule.re.MatchString(cmdline) {
			m.warned[pid] = true
			logger.Warn(
				"[monitor] low-confidence match (NO action taken) PID %d (%s): pattern=%s cmdline=%q — "+
					"requires manual triage or socket-stdio confirmation before kill",
				pid, target, rule.name, cmdline,
			)
			return
		}
	}
}

// killAndFlag — Tier 1: высокоуверенное срабатывание, отправляется в
// Response Module на немедленный SIGKILL.
func (m *Module) killAndFlag(pid int, name, cmdline, reason string) {
	logger.Warn(
		"[monitor] CONFIRMED reverse-shell signature PID %d (%s): reason=%s cmdline=%q",
		pid, name, reason, cmdline,
	)
	m.killed[pid] = true
	m.Out <- response.Finding{
		PID:     pid,
		Name:    name,
		Cmdline: cmdline,
		Reason:  reason,
	}
}

// socketStdio проверяет fd 0/1/2 процесса. Если хотя бы один из них —
// сетевой сокет (а не tty/файл/pipe), возвращает его дескриптор вида
// "socket:[12345]" и true. Требует доступа к /proc/[pid]/fd (root —
// либо тот же uid, что у целевого процесса).
func socketStdio(pid int) (string, bool) {
	base := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	for _, fd := range []string{"0", "1", "2"} {
		link, err := os.Readlink(filepath.Join(base, fd))
		if err != nil {
			continue // нет доступа / fd не существует — пропускаем
		}
		if strings.HasPrefix(link, "socket:") {
			return link, true
		}
	}
	return "", false
}

// procExeBase возвращает базовое имя реального бинарника процесса через
// /proc/[pid]/exe (надёжнее, чем comm, который усечён до 15 символов и
// легче подделывается через argv[0]). Пустая строка — если недоступно
// (например, zombie-процесс или недостаточно прав).
func procExeBase(pid int) string {
	link, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return ""
	}
	return filepath.Base(link)
}

// procComm читает короткое имя процесса из /proc/[pid]/comm (fallback,
// если /proc/[pid]/exe недоступен).
func procComm(pid int) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(data))
}
