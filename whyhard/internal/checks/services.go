package checks

import (
	"fmt"
	"strings"
	"time"

	"whyhard/internal/core"
)

// legacyInsecureServices — демоны, передающие учётные данные/команды
// открытым текстом или исторически известные дырявыми. Если активны —
// это почти всегда забытый легаси-сервис, а не осознанное решение,
// поэтому остановка вынесена в RiskRisky (а не RiskReportOnly): фикс
// детерминирован и почти наверняка ожидаем, но мы всё равно требуем
// явный --apply-risky, т.к. останавливаем работающую службу.
var legacyInsecureServices = []struct {
	unit   string
	sev    core.Severity
	detail string
}{
	{"telnet.socket", core.SeverityCritical, "Telnet передаёt пароли открытым текстом"},
	{"rsh.socket", core.SeverityCritical, "rsh — устаревшая, без шифрования и нормальной аутентификации"},
	{"rlogin.socket", core.SeverityCritical, "rlogin — аналогично rsh"},
	{"rexec.socket", core.SeverityCritical, "rexec — аналогично rsh"},
	{"tftp.socket", core.SeverityHigh, "TFTP без аутентификации, часто открыт наружу по ошибке"},
}

type ServicesModule struct{}

func NewServices() *ServicesModule { return &ServicesModule{} }

func (m *ServicesModule) Name() string { return "services" }

func (m *ServicesModule) Run(mode core.Mode) []core.Finding {
	var findings []core.Finding

	if !commandExists("systemctl") {
		findings = append(findings, core.Finding{
			Module: m.Name(), Check: "systemctl", Severity: core.SeverityInfo, Risk: core.RiskReportOnly,
			Status: core.StatusOK, Detail: "systemctl не найден (не systemd, например Alpine/OpenRC) — проверка легаси-сервисов пропущена для этой версии",
		})
		return findings
	}

	for _, svc := range legacyInsecureServices {
		active := isUnitActive(svc.unit)

		if !active {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: svc.unit, Severity: svc.sev, Risk: core.RiskRisky,
				Status: core.StatusOK, Detail: fmt.Sprintf("%s не активен", svc.unit),
			})
			continue
		}

		if mode != core.ModeApplyRisky {
			status := core.StatusWarn
			if mode != core.ModeAudit {
				status = core.StatusSkippedRisky
			}
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: svc.unit, Severity: svc.sev, Risk: core.RiskRisky,
				Status: status,
				Detail: fmt.Sprintf("%s АКТИВЕН — %s. Остановка требует --apply-risky", svc.unit, svc.detail),
			})
			continue
		}

		if err := runCommand("systemctl", []string{"disable", "--now", svc.unit}, 15*time.Second); err != nil {
			findings = append(findings, core.Finding{
				Module: m.Name(), Check: svc.unit, Severity: svc.sev, Risk: core.RiskRisky,
				Status: core.StatusError, Detail: fmt.Sprintf("не удалось остановить/выключить: %v", err),
			})
			continue
		}
		findings = append(findings, core.Finding{
			Module: m.Name(), Check: svc.unit, Severity: svc.sev, Risk: core.RiskRisky,
			Status: core.StatusFixed, Detail: fmt.Sprintf("%s остановлен и отключён (disable --now)", svc.unit),
		})
	}

	return findings
}

func isUnitActive(unit string) bool {
	out := commandOutputAllowError("systemctl", []string{"is-active", unit}, 5*time.Second)
	return strings.TrimSpace(out) == "active"
}
