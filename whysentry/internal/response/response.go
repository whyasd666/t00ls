// Package response реализует Модуль Реагирования (Response Module).
// Принимает находки от Monitor (и в перспективе от любых других модулей,
// например будущего модуля YARA/файловой целостности) через канал и
// мгновенно завершает процесс-нарушитель syscall.Kill(pid, SIGKILL).
package response

import (
	"context"
	"syscall"
	"time"

	"whysentry/internal/logger"
)

// Finding описывает обнаруженную угрозу, переданную в Response Module.
type Finding struct {
	PID     int
	Name    string // имя процесса (comm)
	Cmdline string // полная командная строка
	Reason  string // что именно сработало (паттерн/правило)
}

// Module — Response Module. Findings — точка входа для других модулей.
type Module struct {
	Findings chan Finding
}

// New создаёт Response Module с буферизованным каналом находок.
func New() *Module {
	return &Module{
		Findings: make(chan Finding, 128),
	}
}

func (m *Module) Name() string { return "response" }

// Start блокируется в цикле, обрабатывая находки до отмены ctx.
func (m *Module) Start(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case f := <-m.Findings:
			m.handle(f)
		}
	}
}

func (m *Module) handle(f Finding) {
	err := syscall.Kill(f.PID, syscall.SIGKILL)
	ts := time.Now().Format(time.RFC3339)

	if err != nil {
		logger.Error(
			"[response] FAILED to terminate PID %d (%s): %v | cmdline=%q | reason=%s",
			f.PID, f.Name, err, f.Cmdline, f.Reason,
		)
		return
	}

	logger.Kill(
		"[response] TERMINATED PID %d (%s) at %s | cmdline=%q | reason=%s",
		f.PID, f.Name, ts, f.Cmdline, f.Reason,
	)
}
