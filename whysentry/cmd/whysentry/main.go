// Command whysentry — точка входа агента. Собирает Core Engine,
// регистрирует модули (Response, Monitor, Audit) и обрабатывает
// graceful shutdown по SIGINT/SIGTERM.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"whysentry/internal/audit"
	"whysentry/internal/banner"
	"whysentry/internal/core"
	"whysentry/internal/logger"
	"whysentry/internal/monitor"
	"whysentry/internal/response"
)

const version = "0.1.0-mvp"

func main() {
	banner.Print(version)

	if os.Geteuid() != 0 {
		logger.Warn("[main] not running as root — process kill and full SUID scan may fail (run with sudo)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	engine := core.NewEngine()

	// Response регистрируется первым, чтобы канал Findings уже принимал
	// сообщения к моменту, когда Monitor начнёт первый scan.
	respModule := response.New()
	monModule := monitor.New(2*time.Second, respModule.Findings)
	auditModule := audit.New()

	engine.Register(respModule)
	engine.Register(monModule)
	engine.Register(auditModule)

	logger.Info("[main] WhySentry engine starting — 3 modules registered")
	engine.Run(ctx)
	engine.Wait()
	logger.Info("[main] WhySentry shutdown complete")
}
