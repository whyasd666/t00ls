// Package checks содержит модули проверок/фиксов whyhard: sysctl,
// filesystem, ssh, accounts, banner, services. Каждый модуль реализует
// core.Module и сам решает, какие из своих находок относятся к
// core.RiskSafe (можно фиксить в ModeApply) и какие к core.RiskRisky
// (фиксится только в ModeApplyRisky).
package checks

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"whyhard/internal/core"
)

// sysctlParam — один параметр ядра: ключ в формате sysctl (net.ipv4...)
// и желаемое hardening-значение.
type sysctlParam struct {
	key    string
	want   string
	sev    core.Severity
	detail string
}

// sysctlHardeningSet — набор сетевых/ядерных параметров, безопасных для
// применения практически на любом сервере без риска что-то сломать.
// Параметры, которые МОГУТ сломать легитимные сетапы (net.ipv4.ip_forward
// и т.п. для роутеров/NAT-хостов), сознательно не включены — whyhard
// никогда не трогает форвардинг трафика.
var sysctlHardeningSet = []sysctlParam{
	{"net.ipv4.conf.all.accept_redirects", "0", core.SeverityHigh, "ICMP redirects могут подменить маршрутизацию (MITM)"},
	{"net.ipv4.conf.default.accept_redirects", "0", core.SeverityHigh, "ICMP redirects (default iface)"},
	{"net.ipv4.conf.all.send_redirects", "0", core.SeverityMedium, "хост не должен отправлять ICMP redirects, если это не роутер"},
	{"net.ipv4.conf.all.accept_source_route", "0", core.SeverityHigh, "source-routed пакеты — классический вектор IP-спуфинга"},
	{"net.ipv4.conf.default.accept_source_route", "0", core.SeverityHigh, "source-routed пакеты (default iface)"},
	{"net.ipv4.conf.all.rp_filter", "1", core.SeverityMedium, "reverse path filtering против IP-спуфинга"},
	{"net.ipv4.icmp_echo_ignore_broadcasts", "1", core.SeverityLow, "защита от smurf-атак"},
	{"net.ipv4.icmp_ignore_bogus_error_responses", "1", core.SeverityLow, "шум в логах от bogus ICMP"},
	{"net.ipv4.tcp_syncookies", "1", core.SeverityMedium, "защита от SYN-flood"},
	{"net.ipv6.conf.all.accept_redirects", "0", core.SeverityMedium, "ICMP redirects (IPv6)"},
	{"net.ipv6.conf.all.accept_source_route", "0", core.SeverityMedium, "source-routed пакеты (IPv6)"},
	{"kernel.randomize_va_space", "2", core.SeverityHigh, "полный ASLR — усложняет memory-corruption эксплойты"},
	{"kernel.dmesg_restrict", "1", core.SeverityMedium, "непривилегированные пользователи не должны читать dmesg (утечка адресов/инфы)"},
	{"kernel.kptr_restrict", "2", core.SeverityMedium, "скрытие адресов ядра из /proc"},
	{"fs.protected_hardlinks", "1", core.SeverityMedium, "защита от hardlink-based privesc/symlink атак"},
	{"fs.protected_symlinks", "1", core.SeverityMedium, "защита от symlink-атак в общих каталогах (/tmp)"},
	{"fs.suid_dumpable", "0", core.SeverityHigh, "core dump SUID-процессов может содержать секреты в памяти"},
}

// managedSysctlFile — куда whyhard пишет свои параметры. Отдельный файл,
// никогда не трогаем существующие /etc/sysctl.conf или другие *.conf —
// это безопасно и легко откатить (просто удалить файл).
const managedSysctlFile = "/etc/sysctl.d/99-whyhard.conf"

type SysctlModule struct{}

func NewSysctl() *SysctlModule { return &SysctlModule{} }

func (m *SysctlModule) Name() string { return "sysctl" }

func (m *SysctlModule) Run(mode core.Mode) []core.Finding {
	var findings []core.Finding

	current := make(map[string]string, len(sysctlHardeningSet))
	for _, p := range sysctlHardeningSet {
		val, err := readSysctl(p.key)
		if err != nil {
			if strings.HasPrefix(p.key, "net.ipv6.") && os.IsNotExist(err) {
				// IPv6 полностью отключён в ядре/контейнере — это валидная
				// конфигурация (часто встречается в контейнерах), а не ошибка.
				findings = append(findings, core.Finding{
					Module: m.Name(), Check: p.key, Severity: core.SeverityInfo, Risk: core.RiskSafe,
					Status: core.StatusOK, Detail: "IPv6 отключён в системе — параметр неприменим",
				})
				continue
			}
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: p.key, Severity: p.sev, Risk: core.RiskSafe,
				Status: core.StatusError, Detail: fmt.Sprintf("не удалось прочитать /proc/sys: %v", err),
			})
			continue
		}
		current[p.key] = val

		if val == p.want {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: p.key, Severity: p.sev, Risk: core.RiskSafe,
				Status: core.StatusOK, Detail: fmt.Sprintf("= %s", val),
			})
			continue
		}

		// Нарушение найдено.
		if mode == core.ModeAudit {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: p.key, Severity: p.sev, Risk: core.RiskSafe,
				Status: core.StatusWarn,
				Detail: fmt.Sprintf("= %s (нужно %s) — %s", val, p.want, p.detail),
			})
			continue
		}

		// ModeApply / ModeApplyRisky: применяем live через /proc/sys —
		// это RiskSafe-фикс, форвардинг трафика мы не трогаем, поэтому
		// применяется в обоих apply-режимах.
		if err := writeSysctlLive(p.key, p.want); err != nil {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: p.key, Severity: p.sev, Risk: core.RiskSafe,
				Status: core.StatusError, Detail: fmt.Sprintf("не удалось применить live: %v", err),
			})
			continue
		}
		current[p.key] = p.want
		findings = append(findings, core.Finding{
			Module: m.Name(), Check: p.key, Severity: p.sev, Risk: core.RiskSafe,
			Status: core.StatusFixed, Detail: fmt.Sprintf("%s -> %s", val, p.want),
		})
	}

	// Персистентность через /etc/sysctl.d — только если что-то реально
	// фиксили (apply-режимы) и хотя бы один параметр был live-применён.
	if mode != core.ModeAudit {
		if err := persistSysctlFile(current); err != nil {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: "persist:" + managedSysctlFile, Severity: core.SeverityLow, Risk: core.RiskSafe,
				Status: core.StatusError, Detail: fmt.Sprintf("не удалось записать %s: %v", managedSysctlFile, err),
			})
		} else {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: "persist:" + managedSysctlFile, Severity: core.SeverityInfo, Risk: core.RiskSafe,
				Status: core.StatusFixed, Detail: fmt.Sprintf("параметры сохранены персистентно в %s", managedSysctlFile),
			})
		}
	}

	return findings
}

// readSysctl читает значение параметра через /proc/sys (не требует root,
// работает одинаково на любом дистрибутиве, не зависит от наличия
// бинарника sysctl(8)).
func readSysctl(key string) (string, error) {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// writeSysctlLive применяет значение немедленно через /proc/sys.
func writeSysctlLive(key, val string) error {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	return os.WriteFile(path, []byte(val+"\n"), 0644)
}

// persistSysctlFile перезаписывает управляемый whyhard файл
// /etc/sysctl.d/99-whyhard.conf целиком (идемпотентно — старое
// содержимое неважно, мы единственный владелец этого файла).
func persistSysctlFile(values map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(managedSysctlFile), 0755); err != nil {
		return err
	}

	var b strings.Builder
	fmt.Fprintln(&b, "# managed by whyhard — do not edit by hand, changes will be overwritten")
	fmt.Fprintln(&b, "# regenerate with: sudo ./whyhard.sh --apply")
	for _, p := range sysctlHardeningSet {
		if v, ok := values[p.key]; ok {
			fmt.Fprintf(&b, "%s = %s\n", p.key, v)
		}
	}

	tmp := managedSysctlFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, managedSysctlFile)
}

// readKeyValueFile — общий хелпер для парсинга конфигов вида "key value"
// или "key=value" с поддержкой '#' комментариев. Используется и другими
// модулями (ssh, accounts), поэтому объявлен здесь, в checks-пакете.
func readKeyValueFile(path string, sep string) (map[string]string, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	result := make(map[string]string)
	var rawLines []string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		rawLines = append(rawLines, line)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		parts := strings.SplitN(trimmed, sep, 2)
		if len(parts) != 2 {
			// строки вида "PasswordAuthentication no" разделены пробелом,
			// а не sep — fallback на Fields для конфигов типа sshd_config
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 {
				result[fields[0]] = strings.Join(fields[1:], " ")
			}
			continue
		}
		result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return result, rawLines, scanner.Err()
}
