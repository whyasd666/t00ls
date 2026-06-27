package checks

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"whyhard/internal/core"
)

// criticalPerm — файл/паттерн и максимально допустимые права (umask-стиль:
// "не шире чем"). Это стандартные Unix-перманы, безопасные для принудительной
// установки — никогда не ломают легитимную работу системы.
type criticalPerm struct {
	path    string // конкретный путь либо glob-паттерн (filepath.Glob)
	maxMode os.FileMode
	sev     core.Severity
	detail  string
}

var criticalPerms = []criticalPerm{
	{"/etc/shadow", 0600, core.SeverityCritical, "хэши паролей — не должны быть читаемы кем-либо кроме root"},
	{"/etc/gshadow", 0600, core.SeverityCritical, "хэши паролей групп"},
	{"/etc/passwd", 0644, core.SeverityLow, "должен быть читаем всеми, но не writable группой/others"},
	{"/etc/group", 0644, core.SeverityLow, "аналогично /etc/passwd"},
	{"/etc/ssh/ssh_host_*_key", 0600, core.SeverityCritical, "приватные host-ключи SSH"},
	{"/boot/grub/grub.cfg", 0600, core.SeverityMedium, "может содержать пароли/параметры загрузки"},
	{"/boot/grub2/grub.cfg", 0600, core.SeverityMedium, "то же самое (RHEL-family путь)"},
}

// worldWritableScanRoots — каталоги, где проверяем наличие world-writable
// файлов без sticky bit (классический вектор для подмены файлов другим
// локальным пользователем). Это report-only: автоматически "разруливать"
// права на произвольные файлы слишком рискованно для авто-фикса.
var worldWritableScanRoots = []string{"/etc", "/usr", "/opt", "/var/www"}

// safeTmpDirs — каталоги, для которых проверяем флаги монтирования
// noexec/nosuid/nodev. RiskRisky: remount может сломать легитимные
// приложения, которые исполняют файлы из /tmp.
var safeTmpDirs = []string{"/tmp", "/var/tmp", "/dev/shm"}

type FilesystemModule struct{}

func NewFilesystem() *FilesystemModule { return &FilesystemModule{} }

func (m *FilesystemModule) Name() string { return "filesystem" }

func (m *FilesystemModule) Run(mode core.Mode) []core.Finding {
	var findings []core.Finding

	findings = append(findings, m.checkCriticalPerms(mode)...)
	findings = append(findings, m.scanWorldWritable()...)
	findings = append(findings, m.checkTmpMountFlags(mode)...)

	return findings
}

func (m *FilesystemModule) checkCriticalPerms(mode core.Mode) []core.Finding {
	var findings []core.Finding

	for _, cp := range criticalPerms {
		matches, err := filepath.Glob(cp.path)
		if err != nil || len(matches) == 0 {
			continue // файла нет на этом дистрибутиве/сетапе — не ошибка
		}

		for _, path := range matches {
			info, err := os.Stat(path)
			if err != nil {
				findings = append(findings, core.Finding{
					Module: m.Name(), Check: path, Severity: cp.sev, Risk: core.RiskSafe,
					Status: core.StatusError, Detail: err.Error(),
				})
				continue
			}

			mode64 := info.Mode().Perm()
			if mode64&^cp.maxMode == 0 {
				findings = append(findings, core.Finding{
					Module: m.Name(), Check: path, Severity: cp.sev, Risk: core.RiskSafe,
					Status: core.StatusOK, Detail: fmt.Sprintf("%s (%v)", path, mode64),
				})
				continue
			}

			if mode == core.ModeAudit {
				findings = append(findings, core.Finding{
					Module: m.Name(), Check: path, Severity: cp.sev, Risk: core.RiskSafe,
					Status: core.StatusWarn,
					Detail: fmt.Sprintf("%s: текущие права %v, нужно не шире %v — %s", path, mode64, cp.maxMode, cp.detail),
				})
				continue
			}

			if err := os.Chmod(path, cp.maxMode); err != nil {
				findings = append(findings, core.Finding{
					Module: m.Name(), Check: path, Severity: cp.sev, Risk: core.RiskSafe,
					Status: core.StatusError, Detail: fmt.Sprintf("chmod не удался: %v", err),
				})
				continue
			}
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: path, Severity: cp.sev, Risk: core.RiskSafe,
				Status: core.StatusFixed, Detail: fmt.Sprintf("%s: %v -> %v", path, mode64, cp.maxMode),
			})
		}
	}

	return findings
}

// scanWorldWritable — рекурсивный обход с лимитом глубины/числа находок,
// чтобы не превратить аудит в многочасовой обход всей ФС. Всегда
// report-only: правильное исправление зависит от назначения файла и
// требует решения человека.
func (m *FilesystemModule) scanWorldWritable() []core.Finding {
	var findings []core.Finding
	const maxReport = 25
	found := 0

	for _, root := range worldWritableScanRoots {
		if found >= maxReport {
			break
		}
		if _, err := os.Stat(root); err != nil {
			continue
		}

		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if found >= maxReport {
				return filepath.SkipAll
			}
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			perm := info.Mode().Perm()
			isWorldWritable := perm&0002 != 0
			hasSticky := info.Mode()&fs.ModeSticky != 0
			if isWorldWritable && !hasSticky && info.Mode().IsRegular() {
				found++
				findings = append(findings, core.Finding{
					Module: m.Name(), Check: "world-writable:" + path,
					Severity: core.SeverityMedium, Risk: core.RiskReportOnly,
					Status: core.StatusWarn,
					Detail: fmt.Sprintf("%s доступен на запись всем (%v), без sticky bit — требует ручного разбора", path, perm),
				})
			}
			return nil
		})
	}

	if found == 0 {
		findings = append(findings, core.Finding{
			Module: m.Name(), Check: "world-writable-scan", Severity: core.SeverityInfo, Risk: core.RiskReportOnly,
			Status: core.StatusOK, Detail: fmt.Sprintf("world-writable файлов без sticky bit не найдено в %v", worldWritableScanRoots),
		})
	}

	return findings
}

// checkTmpMountFlags проверяет noexec/nosuid/nodev для /tmp, /var/tmp,
// /dev/shm через /proc/mounts. RiskRisky: remount может сломать ПО,
// которое легитимно исполняет файлы из tmp-каталогов (некоторые
// инсталляторы, JIT-кэши и т.п.) — поэтому фиксится только с --apply-risky.
func (m *FilesystemModule) checkTmpMountFlags(mode core.Mode) []core.Finding {
	var findings []core.Finding

	mounts, err := parseProcMounts()
	if err != nil {
		findings = append(findings, core.Finding{
			Module: m.Name(), Check: "mount-flags", Severity: core.SeverityLow, Risk: core.RiskRisky,
			Status: core.StatusError, Detail: fmt.Sprintf("не удалось прочитать /proc/mounts: %v", err),
		})
		return findings
	}

	wantFlags := []string{"noexec", "nosuid", "nodev"}

	for _, dir := range safeTmpDirs {
		mp, ok := mounts[dir]
		if !ok {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: "mount:" + dir, Severity: core.SeverityLow, Risk: core.RiskRisky,
				Status: core.StatusOK, Detail: fmt.Sprintf("%s — отдельная точка монтирования не найдена (часть корня), пропускаем", dir),
			})
			continue
		}

		missing := missingFlags(mp.options, wantFlags)
		if len(missing) == 0 {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: "mount:" + dir, Severity: core.SeverityLow, Risk: core.RiskRisky,
				Status: core.StatusOK, Detail: fmt.Sprintf("%s смонтирован с %v", dir, wantFlags),
			})
			continue
		}

		if mode != core.ModeApplyRisky {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: "mount:" + dir, Severity: core.SeverityMedium, Risk: core.RiskRisky,
				Status: core.StatusSkippedRisky,
				Detail: fmt.Sprintf("%s: отсутствуют флаги %v — может сломать ПО, исполняющее файлы из tmp; требует --apply-risky", dir, missing),
			})
			continue
		}

		if err := remountWithFlags(dir, wantFlags); err != nil {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: "mount:" + dir, Severity: core.SeverityMedium, Risk: core.RiskRisky,
				Status: core.StatusError, Detail: fmt.Sprintf("remount не удался: %v", err),
			})
			continue
		}
		findings = append(findings, core.Finding{
			Module: m.Name(), Check: "mount:" + dir, Severity: core.SeverityMedium, Risk: core.RiskRisky,
			Status: core.StatusFixed, Detail: fmt.Sprintf("%s: добавлены флаги %v (remount,)", dir, missing),
		})
	}

	return findings
}

type mountPoint struct {
	device  string
	target  string
	fstype  string
	options []string
}

func parseProcMounts() (map[string]mountPoint, error) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return nil, err
	}
	result := make(map[string]mountPoint)
	for _, line := range splitLines(string(data)) {
		fields := fieldsOf(line)
		if len(fields) < 4 {
			continue
		}
		mp := mountPoint{
			device:  fields[0],
			target:  fields[1],
			fstype:  fields[2],
			options: splitComma(fields[3]),
		}
		result[mp.target] = mp
	}
	return result, nil
}

func missingFlags(have []string, want []string) []string {
	set := make(map[string]bool, len(have))
	for _, h := range have {
		set[h] = true
	}
	var missing []string
	for _, w := range want {
		if !set[w] {
			missing = append(missing, w)
		}
	}
	return missing
}

// remountWithFlags выполняет `mount -o remount,<flags> <dir>` через
// внешний бинарник mount(8) — переопределять системный вызов mount(2)
// с нуля для MVP избыточно, а сам mount есть на любом Linux без исключений.
func remountWithFlags(dir string, flags []string) error {
	args := []string{"-o", "remount," + joinComma(flags), dir}
	return runCommand("mount", args, 10*time.Second)
}

// --- мелкие строковые хелперы без лишних зависимостей ---

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func fieldsOf(s string) []string {
	var fields []string
	cur := ""
	for _, r := range s {
		if r == ' ' || r == '\t' {
			if cur != "" {
				fields = append(fields, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		fields = append(fields, cur)
	}
	return fields
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}
