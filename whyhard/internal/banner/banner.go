// Package banner печатает стартовый ASCII-арт whyhard.
package banner

import "fmt"

const (
	red    = "\x1b[38;5;196m"
	green  = "\x1b[38;5;46m"
	gray   = "\x1b[38;5;240m"
	yellow = "\x1b[38;5;226m"
	reset  = "\x1b[0m"
)

const art = `
▄▄      ▄▄ ▄▄    ▄▄ ▄▄▄    ▄▄▄ ▄▄    ▄▄     ▄▄     ▄▄▄▄▄▄    ▄▄▄▄▄
██      ██ ██    ██  ██▄  ▄██  ██    ██    ████    ██▀▀▀▀██  ██▀▀▀██
▀█▄ ██ ▄█▀ ██    ██   ██▄▄██   ██    ██    ████    ██    ██  ██    ██
 ██ ██ ██  ████████    ▀██▀    ████████   ██  ██   ███████   ██    ██
 ███▀▀███  ██    ██     ██     ██    ██   ██████   ██  ▀██▄  ██    ██
 ███  ███  ██    ██     ██     ██    ██  ▄██  ██▄  ██    ██  ██▄▄▄██
 ▀▀▀  ▀▀▀  ▀▀    ▀▀     ▀▀     ▀▀    ▀▀  ▀▀    ▀▀  ▀▀    ▀▀▀ ▀▀▀▀▀
`

// Print выводит баннер, версию и режим запуска.
func Print(version, modeLabel string) {
	fmt.Print(red + art + reset)
	fmt.Printf("%s    [ cross-distro Linux hardening // CIS-style audit+fix // CVC ]%s\n", gray, reset)
	fmt.Printf("%s    static binary // no CGO // any-distro // any-init%s\n", gray, reset)
	fmt.Printf("%s    version %s%s%s · mode: %s%s%s\n\n", gray, green, version, gray, yellow, modeLabel, reset)
}
