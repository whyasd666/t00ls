// Package core описывает общий контракт модулей whyhard и базовые типы
// для отчёта о находках (Finding). В отличие от WhySentry (который — демон
// с долгоживущими горутинами), whyhard — однопроходный аудит/фиксер:
// каждый модуль выполняется один раз и возвращает список находок.
package core

// Mode определяет, что разрешено делать модулям с системой.
type Mode int

const (
	// ModeAudit — только чтение состояния системы, никаких изменений.
	// Режим по умолчанию.
	ModeAudit Mode = iota
	// ModeApply — применяет "безопасные" фиксы (Risk == RiskSafe):
	// sysctl, права на файлы, password policy, баннеры. Эти изменения
	// не могут оборвать текущую сессию администратора.
	ModeApply
	// ModeApplyRisky — дополнительно применяет "рискованные" фиксы
	// (Risk == RiskRisky): правки sshd_config, остановка сервисов.
	// Такие изменения теоретически могут привести к потере удалённого
	// доступа при ошибке конфигурации — поэтому требуют отдельного флага.
	ModeApplyRisky
)

// Severity — серьёзность найденной проблемы.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Risk — категория риска для автоматического применения фикса.
type Risk string

const (
	// RiskSafe — фикс не может нарушить доступ/работу системы
	// (sysctl, права файлов, login.defs, баннеры).
	RiskSafe Risk = "safe"
	// RiskRisky — фикс потенциально может ограничить доступ
	// (PasswordAuthentication no, PermitRootLogin no, stop службы).
	RiskRisky Risk = "risky"
	// RiskReportOnly — whyhard никогда не фиксит это автоматически
	// ни в каком режиме (например, удаление чужих файлов/аккаунтов) —
	// только отчёт для ручного разбора администратором.
	RiskReportOnly Risk = "report-only"
)

// Status — итоговый статус находки после прогона модуля.
type Status string

const (
	StatusOK            Status = "ok"             // уже соответствует hardening-политике
	StatusFixed         Status = "fixed"          // было нарушение, исправлено в этом запуске
	StatusWarn          Status = "warn"           // нарушение есть, требует ручного действия
	StatusSkippedRisky  Status = "skipped-risky"  // нарушение есть, фикс risky и не применён (нужен --apply-risky)
	StatusSkippedUnsafe Status = "skipped-unsafe" // фикс risky пропущен из-за доп. проверки безопасности (напр. нет SSH-ключей)
	StatusError         Status = "error"          // не удалось проверить/исправить (ошибка ОС/прав)
)

// Finding — одна проверка одного модуля с результатом.
type Finding struct {
	Module   string
	Check    string
	Severity Severity
	Risk     Risk
	Status   Status
	Detail   string
}

// Module — контракт для всех проверок whyhard.
type Module interface {
	Name() string
	// Run выполняет все проверки модуля в соответствии с режимом mode
	// и возвращает список находок. Не должен паниковать на ошибках ОС —
	// в случае проблемы конкретной проверки возвращается Finding со
	// статусом StatusError, остальные проверки модуля продолжаются.
	Run(mode Mode) []Finding
}
