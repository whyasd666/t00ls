package checks

import (
	"context"
	"os/exec"
	"time"
)

// runCommand запускает внешний бинарник с таймаутом. Используется только
// там, где переписывать функциональность через syscall напрямую
// избыточно для MVP (mount(8), systemctl(1)) — оба гарантированно
// присутствуют на поддерживаемых дистрибутивах (systemd) либо проверка
// их наличия предшествует вызову.
func runCommand(name string, args []string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Run()
}

// commandOutput — то же самое, но возвращает stdout (для is-active/is-enabled).
func commandOutput(name string, args []string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	return string(out), err
}

// commandOutputAllowError — как commandOutput, но не считает ошибкой
// ненулевой exit code (нужно для `systemctl is-active`, который
// возвращает != 0 для inactive/unknown юнитов, но печатает осмысленный
// статус в stdout).
func commandOutputAllowError(name string, args []string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, _ := cmd.CombinedOutput()
	return string(out)
}
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
