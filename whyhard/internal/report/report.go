// Package report формирует человекочитаемый summary по результатам
// прогона всех модулей whyhard: цветной вывод в терминал, числовой
// score и сохранение полного отчёта в файл.
package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"whyhard/internal/core"
)

const (
	colorReset  = "\x1b[0m"
	colorGray   = "\x1b[38;5;240m"
	colorGreen  = "\x1b[38;5;46m"
	colorYellow = "\x1b[38;5;226m"
	colorRed    = "\x1b[38;5;196m"
	colorMagen  = "\x1b[38;5;201m"
	colorBold   = "\x1b[1m"
)

func statusColor(s core.Status) string {
	switch s {
	case core.StatusOK:
		return colorGreen
	case core.StatusFixed:
		return colorMagen
	case core.StatusWarn, core.StatusSkippedRisky, core.StatusSkippedUnsafe:
		return colorYellow
	case core.StatusError:
		return colorRed
	default:
		return colorGray
	}
}

func statusLabel(s core.Status) string {
	switch s {
	case core.StatusOK:
		return " OK "
	case core.StatusFixed:
		return "FIX "
	case core.StatusWarn:
		return "WARN"
	case core.StatusSkippedRisky:
		return "RISK"
	case core.StatusSkippedUnsafe:
		return "SAFE-SKIP"
	case core.StatusError:
		return "ERR "
	default:
		return string(s)
	}
}

// PrintSummary выводит таблицу находок, сгруппированную по модулям,
// и итоговый score в терминал.
func PrintSummary(findings []core.Finding) {
	fmt.Printf("\n%s%s════════════════════════ WHYHARD REPORT ════════════════════════%s\n\n", colorBold, colorGray, colorReset)

	currentModule := ""
	for _, f := range findings {
		if f.Module != currentModule {
			currentModule = f.Module
			fmt.Printf("%s%s── %s ──%s\n", colorBold, colorGray, currentModule, colorReset)
		}
		fmt.Printf("  %s[%s]%s %-28s %s\n", statusColor(f.Status), statusLabel(f.Status), colorReset, f.Check, f.Detail)
	}

	score, total, ok := Score(findings)
	fmt.Printf("\n%s%s══════════════════════════════════════════════════════════════%s\n", colorBold, colorGray, colorReset)
	fmt.Printf("%sHardening score: %s%d%%%s  (%d/%d проверок в норме)\n", colorBold, scoreColor(score), score, colorReset, ok, total)
	fmt.Println(scoreVerdict(score))
}

func scoreColor(score int) string {
	switch {
	case score >= 90:
		return colorGreen
	case score >= 70:
		return colorYellow
	default:
		return colorRed
	}
}

func scoreVerdict(score int) string {
	switch {
	case score >= 90:
		return colorGreen + "Хорошо защищено. Проверьте оставшиеся WARN/RISK вручную." + colorReset
	case score >= 70:
		return colorYellow + "Есть заметные дыры — рекомендуется sudo ./whyhard.sh --apply, затем разобрать risky-находки." + colorReset
	default:
		return colorRed + "Система слабо защищена. Срочно прогоните --apply и разберите критичные находки." + colorReset
	}
}

// Score считает процент находок в статусе OK или Fixed относительно
// всех проверяемых находок (info-находки о самой системе не считаются
// нарушением и не портят score, но всё равно входят в total для честности —
// за исключением чисто служебных записей типа "persist:..." и "...write").
func Score(findings []core.Finding) (score int, total int, ok int) {
	for _, f := range findings {
		if isServiceRecord(f.Check) {
			continue
		}
		total++
		if f.Status == core.StatusOK || f.Status == core.StatusFixed {
			ok++
		}
	}
	if total == 0 {
		return 100, 0, 0
	}
	return ok * 100 / total, total, ok
}

func isServiceRecord(check string) bool {
	return strings.Contains(check, ":write") || strings.HasPrefix(check, "persist:")
}

// WriteFile сохраняет полный отчёт (без ANSI-цветов) в текстовый файл.
func WriteFile(path string, findings []core.Finding, mode core.Mode) error {
	var b strings.Builder
	fmt.Fprintf(&b, "whyhard report — %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "mode: %s\n\n", modeLabel(mode))

	currentModule := ""
	for _, f := range findings {
		if f.Module != currentModule {
			currentModule = f.Module
			fmt.Fprintf(&b, "\n== %s ==\n", currentModule)
		}
		fmt.Fprintf(&b, "[%s] (%s/%s) %s — %s\n", f.Status, f.Severity, f.Risk, f.Check, f.Detail)
	}

	score, total, ok := Score(findings)
	fmt.Fprintf(&b, "\nHardening score: %d%% (%d/%d)\n", score, ok, total)

	return os.WriteFile(path, []byte(b.String()), 0644)
}

func modeLabel(mode core.Mode) string {
	switch mode {
	case core.ModeApply:
		return "apply"
	case core.ModeApplyRisky:
		return "apply-risky"
	default:
		return "audit"
	}
}
