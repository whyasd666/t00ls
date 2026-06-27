package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"whyhard/internal/core"
)

// sshDirective — одна директива sshd_config: желаемое значение и тир риска.
//
// RiskSafe-директивы не могут оборвать текущую SSH-сессию администратора
// при ошибке (X11Forwarding, MaxAuthTries и т.п.) — поэтому фиксятся уже
// в ModeApply. RiskRisky-директивы (PermitRootLogin, PasswordAuthentication)
// теоретически могут заблокировать доступ при неудачном сценарии — фиксятся
// только в ModeApplyRisky, причём PasswordAuthentication дополнительно
// проверяется на наличие хоть одного authorized_keys в системе (см. ниже).
var sshDirectives = []struct {
	key    string
	want   string
	sev    core.Severity
	risk   core.Risk
	detail string
}{
	{"Protocol", "2", core.SeverityLow, core.RiskSafe, "SSHv1 уязвим, в современном OpenSSH уже не поддерживается, но фиксируем явно"},
	{"X11Forwarding", "no", core.SeverityLow, core.RiskSafe, "X11 forwarding редко нужен на сервере, лишняя поверхность атаки"},
	{"MaxAuthTries", "3", core.SeverityLow, core.RiskSafe, "ограничение попыток аутентификации за соединение"},
	{"LoginGraceTime", "30", core.SeverityLow, core.RiskSafe, "не держать незавершённые соединения долго открытыми"},
	{"ClientAliveInterval", "300", core.SeverityLow, core.RiskSafe, "обрыв зависших/неактивных сессий"},
	{"ClientAliveCountMax", "2", core.SeverityLow, core.RiskSafe, "пара с ClientAliveInterval"},
	{"PermitEmptyPasswords", "no", core.SeverityCritical, core.RiskSafe, "пустые пароли — критическая дыра, безопасно отключать всегда"},
	{"IgnoreRhosts", "yes", core.SeverityMedium, core.RiskSafe, "rhosts-аутентификация устарела и уязвима"},
	{"HostbasedAuthentication", "no", core.SeverityMedium, core.RiskSafe, "аналогично rhosts"},
	{"PermitRootLogin", "no", core.SeverityHigh, core.RiskRisky, "прямой root-доступ по SSH — повышает ущерб от компрометации ключа/пароля"},
	{"PasswordAuthentication", "no", core.SeverityHigh, core.RiskRisky, "брутфорс пароля — один из самых частых векторов компрометации серверов"},
}

const sshdConfigPath = "/etc/ssh/sshd_config"

type SSHModule struct{}

func NewSSH() *SSHModule { return &SSHModule{} }

func (m *SSHModule) Name() string { return "ssh" }

func (m *SSHModule) Run(mode core.Mode) []core.Finding {
	var findings []core.Finding

	if _, err := os.Stat(sshdConfigPath); err != nil {
		findings = append(findings, core.Finding{
			Module: m.Name(), Check: "sshd_config", Severity: core.SeverityInfo, Risk: core.RiskReportOnly,
			Status: core.StatusOK, Detail: "sshd_config не найден — OpenSSH-сервер, видимо, не установлен, пропускаем модуль",
		})
		return findings
	}

	current, rawLines, err := readKeyValueFile(sshdConfigPath, " ")
	if err != nil {
		findings = append(findings, core.Finding{
			Module: m.Name(), Check: "sshd_config", Severity: core.SeverityMedium, Risk: core.RiskSafe,
			Status: core.StatusError, Detail: fmt.Sprintf("не удалось прочитать %s: %v", sshdConfigPath, err),
		})
		return findings
	}

	// Для risky-директивы PasswordAuthentication нужна доп. проверка:
	// если в системе нет ни одного authorized_keys, отключение пароля
	// заблокирует SSH-доступ вообще для всех. anyAuthorizedKeys считается
	// один раз и используется как доп. условие безопасности.
	hasKeys := anyAuthorizedKeysPresent()

	toApply := make(map[string]string) // директивы, которые реально нужно дописать в файл
	changed := false

	for _, d := range sshDirectives {
		val, exists := lookupDirective(current, d.key)

		if exists && strings.EqualFold(val, d.want) {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: d.key, Severity: d.sev, Risk: d.risk,
				Status: core.StatusOK, Detail: fmt.Sprintf("%s %s", d.key, val),
			})
			continue
		}

		curDisplay := val
		if !exists {
			curDisplay = "(не задано, default зависит от сборки OpenSSH)"
		}

		if mode == core.ModeAudit {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: d.key, Severity: d.sev, Risk: d.risk,
				Status: core.StatusWarn,
				Detail: fmt.Sprintf("%s: %s (нужно %s) — %s", d.key, curDisplay, d.want, d.detail),
			})
			continue
		}

		if d.risk == core.RiskRisky && mode != core.ModeApplyRisky {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: d.key, Severity: d.sev, Risk: d.risk,
				Status: core.StatusSkippedRisky,
				Detail: fmt.Sprintf("%s: %s -> %s пропущено, нужен --apply-risky (риск потери SSH-доступа при ошибке)", d.key, curDisplay, d.want),
			})
			continue
		}

		if d.key == "PasswordAuthentication" && d.want == "no" && !hasKeys {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: d.key, Severity: d.sev, Risk: d.risk,
				Status: core.StatusSkippedUnsafe,
				Detail: "не найдено ни одного authorized_keys в системе — отключение пароля заблокирует SSH-доступ полностью, фикс пропущен. Настройте ключевую аутентификацию хотя бы для одного пользователя перед повторным запуском",
			})
			continue
		}

		toApply[d.key] = d.want
		changed = true
		findings = append(findings, core.Finding{
			Module: m.Name(), Check: d.key, Severity: d.sev, Risk: d.risk,
			Status: core.StatusFixed, Detail: fmt.Sprintf("%s: %s -> %s", d.key, curDisplay, d.want),
		})
	}

	if changed {
		if err := applySSHDirectives(rawLines, toApply); err != nil {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: "sshd_config:write", Severity: core.SeverityMedium, Risk: core.RiskRisky,
				Status: core.StatusError, Detail: fmt.Sprintf("не удалось записать %s: %v", sshdConfigPath, err),
			})
		} else {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: "sshd_config:write", Severity: core.SeverityInfo, Risk: core.RiskRisky,
				Status: core.StatusFixed,
				Detail: "конфиг изменён, backup сохранён рядом (*.whyhard.bak.<timestamp>). " +
					"ВАЖНО: проверьте `sshd -t` и перезагрузите конфиг (`systemctl reload sshd`) вручную — " +
					"whyhard НИКОГДА не делает restart/reload сам, чтобы не оборвать вашу текущую сессию",
			})
		}
	}

	return findings
}

// lookupDirective — поиск директивы регистронезависимо (sshd_config
// директивы регистронезависимы согласно man sshd_config).
func lookupDirective(m map[string]string, key string) (string, bool) {
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

// anyAuthorizedKeysPresent проверяет /root/.ssh/authorized_keys и
// /home/*/.ssh/authorized_keys на существование непустого файла.
func anyAuthorizedKeysPresent() bool {
	candidates := []string{"/root/.ssh/authorized_keys"}
	if homeDirs, err := filepath.Glob("/home/*/.ssh/authorized_keys"); err == nil {
		candidates = append(candidates, homeDirs...)
	}
	for _, c := range candidates {
		info, err := os.Stat(c)
		if err == nil && info.Size() > 0 {
			return true
		}
	}
	return false
}

// applySSHDirectives комментирует существующие строки с нужными ключами
// (регистронезависимо, по первому слову в строке) и дописывает блок
// whyhard в конец файла. Backup создаётся всегда перед первой правкой.
func applySSHDirectives(rawLines []string, toApply map[string]string) error {
	backupPath := fmt.Sprintf("%s.whyhard.bak.%d", sshdConfigPath, time.Now().Unix())
	original := strings.Join(rawLines, "\n") + "\n"
	if err := os.WriteFile(backupPath, []byte(original), 0600); err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}

	var out strings.Builder
	skippingManagedBlock := false
	for _, line := range rawLines {
		trimmed := strings.TrimSpace(line)

		// Вырезаем все предыдущие whyhard managed-блоки целиком — иначе
		// при повторных запусках (--apply, потом --apply-risky, потом
		// снова --apply) конфиг накапливал бы блоки один за другим.
		if strings.HasPrefix(trimmed, "# --- whyhard managed block") {
			skippingManagedBlock = true
			continue
		}
		if skippingManagedBlock {
			if strings.HasPrefix(trimmed, "# --- end whyhard managed block") {
				skippingManagedBlock = false
			}
			continue
		}

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			out.WriteString(line)
			out.WriteString("\n")
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			out.WriteString(line)
			out.WriteString("\n")
			continue
		}
		if _, managed := caseInsensitiveLookup(toApply, fields[0]); managed {
			out.WriteString("# [whyhard] disabled, see managed block below -> ")
			out.WriteString(line)
			out.WriteString("\n")
			continue
		}
		out.WriteString(line)
		out.WriteString("\n")
	}

	// Объединяем директивы, которые уже стояли в предыдущем managed-блоке
	// (нужно их сохранить), с новыми toApply из текущего запуска — иначе
	// повторный --apply без --apply-risky "забыл" бы ранее применённые
	// risky-директивы, потому что они не входят в toApply этого запуска.
	merged := mergeManagedDirectives(rawLines, toApply)

	out.WriteString("\n# --- whyhard managed block (")
	out.WriteString(time.Now().Format(time.RFC3339))
	out.WriteString(") ---\n")
	for _, d := range sshDirectives {
		if v, ok := merged[d.key]; ok {
			fmt.Fprintf(&out, "%s %s\n", d.key, v)
		}
	}
	out.WriteString("# --- end whyhard managed block ---\n")

	tmp := sshdConfigPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(out.String()), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, sshdConfigPath)
}

// mergeManagedDirectives читает директивы из УЖЕ существующих whyhard
// managed-блоков в исходном файле и объединяет их с toApply текущего
// запуска (toApply имеет приоритет при конфликте — это свежие значения).
// Без этого, например, --apply-risky применил бы PermitRootLogin no,
// а следующий обычный --apply (без risky) перезаписал бы managed-блок
// и "потерял" бы это значение, хотя пользователь его не отменял.
func mergeManagedDirectives(rawLines []string, toApply map[string]string) map[string]string {
	merged := make(map[string]string)
	inBlock := false
	for _, line := range rawLines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# --- whyhard managed block") {
			inBlock = true
			continue
		}
		if strings.HasPrefix(trimmed, "# --- end whyhard managed block") {
			inBlock = false
			continue
		}
		if !inBlock || trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 {
			merged[fields[0]] = strings.Join(fields[1:], " ")
		}
	}
	for k, v := range toApply {
		merged[k] = v
	}
	return merged
}

func caseInsensitiveLookup(m map[string]string, key string) (string, bool) {
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}
