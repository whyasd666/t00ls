// Package logger предоставляет минималистичный цветной логгер для консоли.
// Палитра выдержана в той же эстетике, что и остальные t00ls/whysentry.
package logger

import (
	"fmt"
	"os"
	"sync"
	"time"
)

const (
	colorReset  = "\x1b[0m"
	colorGray   = "\x1b[38;5;240m"
	colorCyan   = "\x1b[38;5;51m"
	colorGreen  = "\x1b[38;5;46m"
	colorYellow = "\x1b[38;5;226m"
	colorRed    = "\x1b[38;5;196m"
	colorMagen  = "\x1b[38;5;201m"
)

var mu sync.Mutex

func ts() string {
	return time.Now().Format("15:04:05.000")
}

func write(out *os.File, color, tag, format string, a ...interface{}) {
	mu.Lock()
	defer mu.Unlock()
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintf(out, "%s[%s]%s %s[%s]%s %s\n", colorGray, ts(), colorReset, color, tag, colorReset, msg)
}

// Info — обычные информационные события (старт модулей, статистика).
func Info(format string, a ...interface{}) {
	write(os.Stdout, colorCyan, "INFO", format, a...)
}

// OK — проверка прошла, система уже в нужном состоянии.
func OK(format string, a ...interface{}) {
	write(os.Stdout, colorGreen, " OK ", format, a...)
}

// Fixed — нарушение найдено и исправлено в этом запуске.
func Fixed(format string, a ...interface{}) {
	write(os.Stdout, colorMagen, "FIX ", format, a...)
}

// Warn — нарушение найдено, авто-фикс не применён (report-only/risky/unsafe).
func Warn(format string, a ...interface{}) {
	write(os.Stdout, colorYellow, "WARN", format, a...)
}

// Error — сбои самих проверок (ошибки доступа к ОС и т.п.).
func Error(format string, a ...interface{}) {
	write(os.Stderr, colorRed, "ERR ", format, a...)
}
