// Package logger предоставляет минималистичный цветной логгер для консоли.
// Цветовая схема выдержана в той же эстетике, что и остальные t00ls
// (acid-red / terminal hacker vibe), без внешних зависимостей.
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

// Warn — подозрительные находки, требующие внимания, но не приведшие к действию.
func Warn(format string, a ...interface{}) {
	write(os.Stdout, colorYellow, "WARN", format, a...)
}

// Error — сбои модулей, ошибки доступа к /proc, ошибки kill().
func Error(format string, a ...interface{}) {
	write(os.Stderr, colorRed, "ERR ", format, a...)
}

// Kill — успешное завершение процесса-нарушителя модулем Response.
func Kill(format string, a ...interface{}) {
	write(os.Stdout, colorMagen, "KILL", format, a...)
}
