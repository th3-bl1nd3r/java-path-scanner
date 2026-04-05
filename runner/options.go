package runner

import (
	"os"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

// Options holds all CLI configuration.
type Options struct {
	// Input
	Target string
	List   string

	// Configuration
	TechFilter    string
	BypassLevel   string
	NoFingerprint bool
	NoDeepChecks  bool

	// Rate Limit
	RateLimit   int
	Concurrency int
	Timeout     int
	Delay       string

	// Network
	Proxy           string
	Headers         goflags.StringSlice
	NoSSLVerify     bool
	FollowRedirects bool

	// Output
	Output   string
	JSON     bool
	Markdown string
	HTML     string
	Silent   bool
	Verbose  bool
	NoColor  bool

	// Misc
	AcceptTerms bool
	Version     bool
}

// ParseOptions creates and parses CLI options using goflags.
func ParseOptions() *Options {
	options := &Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("jps - Java Path Scanner for bug bounty and penetration testing")

	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&options.Target, "target", "u", "", "Target URL to scan"),
		flagSet.StringVarP(&options.List, "list", "l", "", "File containing target URLs (one per line)"),
	)

	flagSet.CreateGroup("config", "Configuration",
		flagSet.StringVar(&options.TechFilter, "tech", "", "Technology filter (comma-separated, e.g. spring,tomcat)"),
		flagSet.StringVar(&options.BypassLevel, "bypass-level", "passive", "Bypass technique level (passive/moderate/aggressive)"),
		flagSet.BoolVar(&options.NoFingerprint, "no-fingerprint", false, "Skip technology fingerprinting"),
		flagSet.BoolVar(&options.NoDeepChecks, "no-deep-checks", false, "Skip deep vulnerability checks"),
	)

	flagSet.CreateGroup("rate", "Rate Limit",
		flagSet.IntVar(&options.RateLimit, "rate-limit", 50, "Max requests per second"),
		flagSet.IntVarP(&options.Concurrency, "concurrency", "c", 50, "Max concurrent requests"),
		flagSet.IntVar(&options.Timeout, "timeout", 10, "Request timeout in seconds"),
		flagSet.StringVar(&options.Delay, "delay", "", "Delay between requests (e.g. 100ms, 1s)"),
	)

	flagSet.CreateGroup("network", "Network",
		flagSet.StringVar(&options.Proxy, "proxy", "", "HTTP/SOCKS5 proxy URL"),
		flagSet.StringSliceVarP(&options.Headers, "header", "H", nil, "Custom headers (repeatable)", goflags.StringSliceOptions),
		flagSet.BoolVar(&options.NoSSLVerify, "no-ssl-verify", false, "Disable SSL certificate verification"),
		flagSet.BoolVar(&options.FollowRedirects, "follow-redirects", false, "Follow HTTP redirects"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "Output file for results"),
		flagSet.BoolVar(&options.JSON, "json", false, "Write output in JSONL format"),
		flagSet.StringVar(&options.Markdown, "markdown", "", "Write markdown report to file"),
		flagSet.StringVar(&options.HTML, "html", "", "Write HTML report to file"),
		flagSet.BoolVar(&options.Silent, "silent", false, "Show only results in output"),
		flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "Show verbose output"),
		flagSet.BoolVar(&options.NoColor, "no-color", false, "Disable colored output"),
	)

	flagSet.CreateGroup("misc", "Misc",
		flagSet.BoolVar(&options.AcceptTerms, "accept-terms", false, "Accept legal disclaimer (required)"),
		flagSet.BoolVar(&options.Version, "version", false, "Show version information"),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("Could not parse flags: %s", err)
	}

	if options.Version {
		gologger.Info().Msgf("jps v%s", version)
		os.Exit(0)
	}

	// Configure logging
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	} else if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}

	options.validate()

	return options
}

func (o *Options) validate() {
	if o.Target == "" && o.List == "" {
		gologger.Fatal().Msg("No target specified. Use -u or -l to provide targets.")
	}

	if !o.AcceptTerms {
		gologger.Fatal().Msg("You must accept the legal disclaimer with --accept-terms.\n" +
			"This tool is for authorized security testing only.\n" +
			"Unauthorized access to computer systems is illegal.")
	}

	switch o.BypassLevel {
	case "passive", "moderate", "aggressive":
		// valid
	default:
		gologger.Fatal().Msgf("Invalid bypass level: %s. Use passive, moderate, or aggressive.", o.BypassLevel)
	}
}
