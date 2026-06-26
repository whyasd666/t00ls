// Package audit реализует Модуль Аудита (Audit Module).
// На старте агента сканирует ключевые каталоги файловой системы и ищет
// бинарники с установленным SUID-битом, сверяя их с списком потенциально
// опасных программ (классические GTFOBins-кандидаты для privesc).
package audit

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"

	"whysentry/internal/logger"
)

// dangerousSUID — короткий список бинарников, чьё наличие с SUID-битом
// почти всегда означает быстрый путь к root (см. GTFOBins). Список
// расширяемый — это просто map, легко дополнить под конкретный дистрибутив.
var dangerousSUID = map[string]bool{
	"find":    true,
	"vim":     true,
	"vi":      true,
	"nano":    true,
	"pkexec":  true,
	"awk":     true,
	"gawk":    true,
	"nmap":    true,
	"perl":    true,
	"python":  true,
	"python3": true,
	"bash":    true,
	"cp":      true,
	"less":    true,
	"more":    true,
	"env":     true,
	"tar":     true,
}

// scanRoots — каталоги, где имеет смысл искать SUID-бинарники.
// Не сканируем весь "/" по умолчанию — это дорого и шумно (всякие /proc,
// /sys виртуальные деревья), да и подавляющее большинство SUID-бинарников
// живёт именно здесь на любом дистрибутиве (Ubuntu/Debian/RHEL-family/Alpine).
var scanRoots = []string{"/usr", "/bin", "/sbin", "/usr/local", "/opt"}

// Module — Audit Module. Одноразовый: Start выполняет sweep и завершается.
type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return "audit" }

// Start выполняет один проход по scanRoots в поисках SUID-файлов.
// Возвращается сразу после завершения скана (не блокирует Engine).
func (m *Module) Start(ctx context.Context) error {
	logger.Info("[audit] starting SUID privilege-escalation sweep...")

	var totalFound, totalDangerous int

	for _, root := range scanRoots {
		if _, err := os.Stat(root); err != nil {
			continue // каталога нет на этом дистрибутиве — пропускаем
		}

		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			select {
			case <-ctx.Done():
				return filepath.SkipAll
			default:
			}

			if walkErr != nil {
				return nil // permission denied и т.п. — не фатально, просто пропускаем
			}
			if d.IsDir() {
				return nil
			}

			info, err := d.Info()
			if err != nil {
				return nil
			}
			if info.Mode()&os.ModeSetuid == 0 {
				return nil
			}

			totalFound++
			base := filepath.Base(path)

			if dangerousSUID[base] {
				totalDangerous++
				logger.Warn(
					"[audit] DANGEROUS SUID binary found: %s (mode=%s) — potential privesc vector",
					path, info.Mode(),
				)
			} else {
				logger.Info("[audit] SUID binary: %s (mode=%s)", path, info.Mode())
			}
			return nil
		})
		if err != nil {
			logger.Error("[audit] walk error in %s: %v", root, err)
		}
	}

	logger.Info(
		"[audit] sweep complete: %d SUID binaries found, %d flagged as dangerous",
		totalFound, totalDangerous,
	)
	return nil
}
