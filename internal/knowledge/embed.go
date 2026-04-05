package knowledge

import "embed"

//go:embed data/config/paths.yaml
var PathsYAML []byte

//go:embed data/config/default_config.yaml
var DefaultConfigYAML []byte

//go:embed data/knowledge/vulns.json
var VulnsJSON []byte

//go:embed data/knowledge/bypasses.yaml
var BypassesYAML []byte

//go:embed data/knowledge/fingerprints.yaml
var FingerprintsYAML []byte

//go:embed data/templates/report.html
var ReportHTMLTemplate string

//go:embed data
var DataFS embed.FS
