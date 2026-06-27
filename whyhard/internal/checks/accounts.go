package checks

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"whyhard/internal/core"
)

const loginDefsPath = "/etc/login.defs"

// loginDefsPolicy — параметры password policy в login.defs. Влияют
// только на НОВЫЕ аккаунты и плановое истечение паролей — никогда не
// обрывают текущие сессии и не блокируют существующих пользователей
// прямо в момент применения, поэтому весь модуль — RiskSafe.
var loginDefsPolicy = []struct {
	key    string
	want   string
	cmp    string // "max" (текущее значение должно быть <= want) / "min" (>= want) / "eq"
	sev    core.Severity
	detail string
}{
	{"PASS_MAX_DAYS", "90", "max", core.SeverityMedium, "пароли должны периодически меняться"},
	{"PASS_MIN_DAYS", "1", "min", core.SeverityLow, "защита от мгновенного возврата к старому паролю"},
	{"PASS_WARN_AGE", "7", "min", core.SeverityLow, "пользователь должен получать предупреждение перед истечением пароля"},
	{"UMASK", "027", "eq", core.SeverityMedium, "новые файлы не должны быть доступны на запись/чтение группе others по умолчанию"},
}

type AccountsModule struct{}

func NewAccounts() *AccountsModule { return &AccountsModule{} }

func (m *AccountsModule) Name() string { return "accounts" }

func (m *AccountsModule) Run(mode core.Mode) []core.Finding {
	var findings []core.Finding

	findings = append(findings, m.checkLoginDefs(mode)...)
	findings = append(findings, m.checkEmptyPasswords()...)
	findings = append(findings, m.checkDuplicateRootUID()...)

	return findings
}

func (m *AccountsModule) checkLoginDefs(mode core.Mode) []core.Finding {
	var findings []core.Finding

	if _, err := os.Stat(loginDefsPath); err != nil {
		findings = append(findings, core.Finding{
			Module: m.Name(), Check: "login.defs", Severity: core.SeverityInfo, Risk: core.RiskSafe,
			Status: core.StatusOK, Detail: fmt.Sprintf("%s не найден — пропускаем (нет shadow-utils?)", loginDefsPath),
		})
		return findings
	}

	current, rawLines, err := readKeyValueFile(loginDefsPath, " ")
	if err != nil {
		findings = append(findings, core.Finding{
			Module: m.Name(), Check: "login.defs", Severity: core.SeverityLow, Risk: core.RiskSafe,
			Status: core.StatusError, Detail: err.Error(),
		})
		return findings
	}

	toApply := make(map[string]string)
	changed := false

	for _, p := range loginDefsPolicy {
		valStr, exists := current[p.key]
		ok := exists && compareNumericOrEqual(valStr, p.want, p.cmp)

		if ok {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: p.key, Severity: p.sev, Risk: core.RiskSafe,
				Status: core.StatusOK, Detail: fmt.Sprintf("%s %s", p.key, valStr),
			})
			continue
		}

		display := valStr
		if !exists {
			display = "(не задано)"
		}

		if mode == core.ModeAudit {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: p.key, Severity: p.sev, Risk: core.RiskSafe,
				Status: core.StatusWarn,
				Detail: fmt.Sprintf("%s: %s (нужно %s %s) — %s", p.key, display, p.cmp, p.want, p.detail),
			})
			continue
		}

		toApply[p.key] = p.want
		changed = true
		findings = append(findings, core.Finding{
			Module: m.Name(), Check: p.key, Severity: p.sev, Risk: core.RiskSafe,
			Status: core.StatusFixed, Detail: fmt.Sprintf("%s: %s -> %s", p.key, display, p.want),
		})
	}

	if changed {
		if err := applyLoginDefs(rawLines, toApply); err != nil {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: "login.defs:write", Severity: core.SeverityLow, Risk: core.RiskSafe,
				Status: core.StatusError, Detail: err.Error(),
			})
		} else {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: "login.defs:write", Severity: core.SeverityInfo, Risk: core.RiskSafe,
				Status: core.StatusFixed, Detail: "login.defs обновлён, backup сохранён рядом (*.whyhard.bak.<timestamp>)",
			})
		}
	}

	return findings
}

// checkEmptyPasswords — report-only: whyhard никогда не блокирует
// аккаунты автоматически, это решение требует контекста, которого у
// инструмента нет (сервисный аккаунт? временно отключенный пароль?).
func (m *AccountsModule) checkEmptyPasswords() []core.Finding {
	var findings []core.Finding

	data, err := os.ReadFile("/etc/shadow")
	if err != nil {
		findings = append(findings, core.Finding{
			Module: m.Name(), Check: "empty-passwords", Severity: core.SeverityInfo, Risk: core.RiskReportOnly,
			Status: core.StatusError, Detail: fmt.Sprintf("нет доступа к /etc/shadow (нужен root): %v", err),
		})
		return findings
	}

	var offenders []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		user, hash := fields[0], fields[1]
		if hash == "" {
			offenders = append(offenders, user)
		}
	}

	if len(offenders) == 0 {
		findings = append(findings, core.Finding{
			Module: m.Name(), Check: "empty-passwords", Severity: core.SeverityInfo, Risk: core.RiskReportOnly,
			Status: core.StatusOK, Detail: "аккаунтов с пустым полем пароля в /etc/shadow не найдено",
		})
		return findings
	}

	findings = append(findings, core.Finding{
		Module: m.Name(), Check: "empty-passwords", Severity: core.SeverityCritical, Risk: core.RiskReportOnly,
		Status: core.StatusWarn,
		Detail: fmt.Sprintf("аккаунты с ПУСТЫМ паролем (вход без пароля!): %s — заблокируйте (passwd -l) или задайте пароль вручную", strings.Join(offenders, ", ")),
	})
	return findings
}

// checkDuplicateRootUID — report-only: наличие второго аккаунта с UID 0
// часто означает backdoor, но автоматическое удаление аккаунта — слишком
// разрушительное действие для авто-фикса любого тира.
func (m *AccountsModule) checkDuplicateRootUID() []core.Finding {
	var findings []core.Finding

	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		findings = append(findings, core.Finding{
			Module: m.Name(), Check: "duplicate-root-uid", Severity: core.SeverityInfo, Risk: core.RiskReportOnly,
			Status: core.StatusError, Detail: err.Error(),
		})
		return findings
	}

	var rootLike []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		name, uidStr := fields[0], fields[2]
		if uidStr == "0" && name != "root" {
			rootLike = append(rootLike, name)
		}
	}

	if len(rootLike) == 0 {
		findings = append(findings, core.Finding{
			Module: m.Name(), Check: "duplicate-root-uid", Severity: core.SeverityInfo, Risk: core.RiskReportOnly,
			Status: core.StatusOK, Detail: "других аккаунтов с UID 0 кроме root не найдено",
		})
		return findings
	}

	findings = append(findings, core.Finding{
		Module: m.Name(), Check: "duplicate-root-uid", Severity: core.SeverityCritical, Risk: core.RiskReportOnly,
		Status: core.StatusWarn,
		Detail: fmt.Sprintf("найдены НЕ-root аккаунты с UID 0 (возможный backdoor): %s — требует немедленного ручного расследования", strings.Join(rootLike, ", ")),
	})
	return findings
}

func compareNumericOrEqual(have, want, cmp string) bool {
	if cmp == "eq" {
		return have == want
	}
	haveN, err1 := strconv.Atoi(have)
	wantN, err2 := strconv.Atoi(want)
	if err1 != nil || err2 != nil {
		return have == want
	}
	switch cmp {
	case "max":
		return haveN <= wantN && haveN > 0
	case "min":
		return haveN >= wantN
	default:
		return have == want
	}
}

func applyLoginDefs(rawLines []string, toApply map[string]string) error {
	backupPath := fmt.Sprintf("%s.whyhard.bak.%d", loginDefsPath, time.Now().Unix())
	if err := os.WriteFile(backupPath, []byte(strings.Join(rawLines, "\n")+"\n"), 0600); err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}

	var out strings.Builder
	handled := make(map[string]bool)

	for _, line := range rawLines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			out.WriteString(line + "\n")
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 {
			if newVal, ok := toApply[fields[0]]; ok {
				fmt.Fprintf(&out, "%s\t%s\n", fields[0], newVal)
				handled[fields[0]] = true
				continue
			}
		}
		out.WriteString(line + "\n")
	}

	for key, val := range toApply {
		if !handled[key] {
			fmt.Fprintf(&out, "%s\t%s\n", key, val)
		}
	}

	tmp := loginDefsPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(out.String()), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, loginDefsPath)
}
