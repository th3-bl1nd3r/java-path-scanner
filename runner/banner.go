package runner

import "github.com/projectdiscovery/gologger"

const version = "1.0.0"

const banner = `
     ██╗██████╗ ███████╗
     ██║██╔══██╗██╔════╝
     ██║██████╔╝███████╗
██   ██║██╔═══╝ ╚════██║
╚█████╔╝██║     ███████║
 ╚════╝ ╚═╝     ╚══════╝
`

// ShowBanner prints the ASCII art banner.
func ShowBanner() {
	gologger.Print().Msgf("%s", banner)
	gologger.Print().Msgf("\t\tjps v%s\n\n", version)
	gologger.Print().Msgf("Java Path Scanner - Discover exposed Java service endpoints\n\n")
}
