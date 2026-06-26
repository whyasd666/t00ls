// Package banner печатает стартовый ASCII-арт WhySentry.
package banner

import "fmt"

const (
	red   = "\x1b[38;5;196m"
	gray  = "\x1b[38;5;240m"
	green = "\x1b[38;5;46m"
	reset = "\x1b[0m"
)

const art = `
 ██╗    ██╗██╗░░██╗██╗░░░██╗░██████╗███████╗███╗░░██╗████████╗██████╗░██╗░░░██╗
 ██║    ██║██║░░██║╚██╗░██╔╝██╔════╝██╔════╝████╗░██║╚══██╔══╝██╔══██╗╚██╗░██╔╝
 ██║ █╗ ██║███████║░╚████╔╝░╚█████╗░█████╗░░██╔██╗██║░░░██║░░░██████╔╝░╚████╔╝░
 ██║███╗██║██╔══██║░░╚██╔╝░░░╚═══██╗██╔══╝░░██║╚████║░░░██║░░░██╔══██╗░░╚██╔╝░░
 ╚███╔███╔╝██║░░██║░░░██║░░░██████╔╝███████╗██║░╚███║░░░██║░░░██║░░██║░░░██║░░░
 ░╚══╝╚══╝░╚═╝░░╚═╝░░░╚═╝░░░╚═════╝░╚══════╝╚═╝░░╚══╝░░░╚═╝░░░╚═╝░░╚═╝░░░╚═╝░░░
`

// Print выводит стартовый банер с версией и кратким описанием агента.
func Print(version string) {
	fmt.Print(red + art + reset)
	fmt.Printf("%s    [ host intrusion containment // EDR-SOAR-lite // CVC ]%s\n", gray, reset)
	fmt.Printf("%s    static binary // no CGO // any-distro // any-init%s\n", gray, reset)
	fmt.Printf("%s    version %s%s%s\n\n", gray, green, version, reset)
}
