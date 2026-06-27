// Command whyhard — кросс-дистрибутивный инструмент Linux hardening
// (audit + fix), построен по тем же архитектурным принципам, что и
// WhySentry: Core Engine + независимые модули, явное разделение
// "безопасных" и "рискованных" действий.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"whyhard/internal/banner"
	"whyhard/internal/checks"
	"whyhard/internal/core"
	"whyhard/internal/logger"
	"whyhard/internal/report"
)

const version = "0.1.0-mvp"

func main() {
	applyFlag := flag.Bool("apply", false, "применить безопасные (RiskSafe) фиксы: sysctl, права файлов, password policy, баннеры")
	applyRiskyFlag := flag.Bool("apply-risky", false, "дополнительно применить рискованные (RiskRisky) фиксы: sshd_config, остановка легаси-сервисов — требует понимания, что можно потерять SSH-доступ при ошибке конфигурации")
	reportPath := flag.String("report", "", "путь для сохранения текстового отчёта (по умолчанию: ./whyhard-report-<timestamp>.txt)")
	showVersion := flag.Bool("version", false, "показать версию и выйти")
	flag.Parse()

	if *showVersion {
		fmt.Println("whyhard " + version)
		return
	}

	mode := core.ModeAudit
	modeLabel := "audit (read-only)"
	switch {
	case *applyRiskyFlag:
		mode = core.ModeApplyRisky
		modeLabel = "apply-risky (safe + risky fixes)"
	case *applyFlag:
		mode = core.ModeApply
		modeLabel = "apply (safe fixes only)"
	}

	banner.Print(version, modeLabel)

	if os.Geteuid() != 0 {
		logger.Warn("[main] не запущено от root — часть проверок (shadow, sshd_config, sysctl write) будет неполной или завершится ошибкой")
	}
	if mode == core.ModeApplyRisky {
		logger.Warn("[main] РЕЖИМ --apply-risky: будут применены изменения, способные ограничить удалённый доступ " +
			"(PermitRootLogin/PasswordAuthentication, остановка легаси-сервисов). whyhard НЕ перезапускает sshd сам " +
			"и проверяет наличие authorized_keys перед отключением пароля — но финальная ответственность за доступность сервера на вас")
		time.Sleep(2 * time.Second) // небольшая пауза, чтобы предупреждение точно попалось на глаза
	}

	engine := core.NewEngine()
	engine.Register(checks.NewSysctl())
	engine.Register(checks.NewFilesystem())
	engine.Register(checks.NewSSH())
	engine.Register(checks.NewAccounts())
	engine.Register(checks.NewBanner())
	engine.Register(checks.NewServices())

	findings := engine.Run(mode)

	report.PrintSummary(findings)

	outPath := *reportPath
	if outPath == "" {
		outPath = fmt.Sprintf("whyhard-report-%s.txt", time.Now().Format("20060102-150405"))
	}
	if err := report.WriteFile(outPath, findings, mode); err != nil {
		logger.Error("[main] не удалось сохранить отчёт в %s: %v", outPath, err)
	} else {
		logger.Info("[main] полный отчёт сохранён: %s", outPath)
	}

	os.Exit(exitCode(findings))
}

// exitCode — 0, если не осталось непокрытых high/critical находок
// (полезно для CI/cron: `whyhard --apply || alert`), иначе 1.
func exitCode(findings []core.Finding) int {
	for _, f := range findings {
		if f.Status == core.StatusOK || f.Status == core.StatusFixed {
			continue
		}
		if f.Severity == core.SeverityHigh || f.Severity == core.SeverityCritical {
			return 1
		}
	}
	return 0
}
