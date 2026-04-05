# JPS - Java Path Scanner

Fast, single-binary Java service endpoint discovery tool for bug bounty and penetration testing. Built following [ProjectDiscovery](https://github.com/projectdiscovery) tool conventions.

```
     ██╗██████╗ ███████╗
     ██║██╔══██╗██╔════╝
     ██║██████╔╝███████╗
██   ██║██╔═══╝ ╚════██║
╚█████╔╝██║     ███████║
 ╚════╝ ╚═╝     ╚══════╝  v1.0.0
```

## Features

- **Technology Fingerprinting** — Detects 29 Java technologies (Spring Boot, Tomcat, Liferay, JBoss, WebLogic, Jenkins, OFBiz, ActiveMQ, Flink, Hadoop YARN, Keycloak, and more) via headers, cookies, error pages, and active probes
- **Path Discovery** — 309 paths across 29 technology groups with context prefix expansion
- **Access Control Bypass** — 15 bypass techniques across 3 levels (passive/moderate/aggressive) including path parameter injection, URL encoding, double encoding, unicode normalization, header overrides, and reverse proxy misalignment
- **Vulnerability Correlation** — 56 CVEs mapped to discovered endpoints with CVSS scores and exploitation details
- **Deep Analysis** — Automated checks for heapdump secrets, actuator env extraction, Swagger API enumeration, Jolokia RCE, Nacos auth bypass, and more
- **Secret Detection** — Scans responses for passwords, API keys, JDBC URLs, JWT tokens, and other sensitive data
- **WAF Detection** — Identifies Cloudflare, AWS WAF, Akamai, Imperva, F5, ModSecurity, and others
- **Multiple Output Formats** — Console (colorized PD-style), JSONL, Markdown, HTML report
- **Single Binary** — All knowledge files embedded via `go:embed`, zero runtime dependencies

## Installation

```bash
go install github.com/th3-bl1nd3r/java-path-scanner/cmd/jps@latest
```

Or build from source:

```bash
git clone https://github.com/th3-bl1nd3r/java-path-scanner.git
cd java-path-scanner/java-path-scanner-go
make build
```

## Usage

```bash
# Basic scan
jps -u https://target.com --accept-terms

# Scan with aggressive bypass techniques
jps -u https://target.com --bypass-level aggressive --accept-terms

# Scan multiple targets from file
jps -l targets.txt --accept-terms

# Generate HTML report
jps -u https://target.com --html report.html --accept-terms

# JSONL output for piping to other tools
jps -u https://target.com --json -o results.jsonl --accept-terms

# Filter by technology
jps -u https://target.com --tech spring_boot_actuator,tomcat --accept-terms

# Use proxy and custom headers
jps -u https://target.com --proxy http://127.0.0.1:8080 -H "Authorization: Bearer token" --accept-terms
```

## Flags

```
INPUT:
   -u, -target string   Target URL to scan
   -l, -list string     File containing target URLs (one per line)

CONFIGURATION:
   -tech string             Technology filter (comma-separated)
   -bypass-level string     Bypass level: passive, moderate, aggressive (default "passive")
   -no-fingerprint          Skip technology fingerprinting
   -no-deep-checks          Skip deep vulnerability checks

RATE LIMIT:
   -rate-limit int       Max requests per second (default 50)
   -c, -concurrency int  Max concurrent requests (default 50)
   -timeout int          Request timeout in seconds (default 10)
   -delay string         Delay between requests (e.g. 100ms, 1s)

NETWORK:
   -proxy string              HTTP/SOCKS5 proxy URL
   -H, -header string[]       Custom headers (can be repeated)
   -no-ssl-verify             Disable SSL certificate verification
   -follow-redirects          Follow HTTP redirects

OUTPUT:
   -o, -output string    Output file for results
   -json                 Write output in JSONL format
   -markdown string      Write markdown report to file
   -html string          Write HTML report to file
   -silent               Show only results
   -v, -verbose          Verbose output
   -no-color             Disable colored output

MISC:
   -accept-terms         Accept legal disclaimer (required)
   -version              Show version
```

## Scan Pipeline

JPS runs a 5-phase scan pipeline per target:

1. **Fingerprint** — Detect technologies via response headers, cookies, error pages, and active probes
2. **Path Discovery** — Bruteforce endpoints relevant to detected technologies using a worker pool
3. **Bypass Attempts** — Test access control bypasses on 403 paths using path normalization, header injection, and method override techniques
4. **Vulnerability Correlation** — Map discovered endpoints to known CVEs with severity and exploitation info
5. **Deep Checks** — Automated analysis of high-value endpoints (heapdump verification, actuator env secret extraction, Swagger endpoint enumeration, etc.)

## Console Output

```
[critical] [spring_boot_actuator] https://target.com/actuator/env [200] [1234 bytes] [secrets:2]
[critical] [spring_boot_actuator] https://target.com/actuator/heapdump [200] [52428800 bytes]
[high]     [bypass:path_parameter] https://target.com/admin;.css [200] [was:403]
[medium]   [swagger_api_docs] https://target.com/swagger-ui.html [200] [2345 bytes]
```

## Supported Technologies

| Technology | Paths | Key CVEs |
|---|---|---|
| Spring Boot Actuator | 32 | CVE-2022-22965 (Spring4Shell), heapdump, env exposure |
| Spring Cloud | 7 | CVE-2022-22947 (Gateway SpEL), CVE-2022-22963 (Function SpEL) |
| Apache Tomcat | 12 | CVE-2025-24813, CVE-2024-50379, CVE-2024-52316, default creds |
| Liferay Portal | 20 | CVE-2020-7961, CVE-2019-16891 (deserialization RCE) |
| JBoss/WildFly | 11 | Invoker servlet deserialization |
| Oracle WebLogic | 10 | CVE-2020-14882, CVE-2024-20931 |
| Jenkins | 16 | CVE-2024-23897 (file read), script console |
| Atlassian | 17 | CVE-2023-22527, CVE-2023-22515, CVE-2023-22518 |
| Apache OFBiz | 10 | CVE-2023-49070, CVE-2023-51467 (pre-auth RCE) |
| Apache ActiveMQ | 9 | CVE-2023-46604 (OpenWire RCE, CVSS 10.0) |
| Apache Flink | 7 | CVE-2020-17518 (file upload traversal) |
| Hadoop YARN | 12 | Unauthenticated RCE via ResourceManager |
| Apache Spark | 6 | CVE-2022-33891 (command injection) |
| Apache Shiro | 3 | CVE-2016-4437 (rememberMe deserialization) |
| Keycloak | 7 | CVE-2024-3656 (unguarded admin API) |
| Nexus Repository | 6 | CVE-2024-4956 (path traversal) |
| Elasticsearch | 13 | Unauthenticated access |
| Apache Solr | 6 | CVE-2023-50386 |
| Swagger/OpenAPI | 15 | API documentation exposure |
| Jolokia | 8 | JMX RCE via MBean operations |
| Alibaba Druid | 9 | Monitor unauthorized access |
| Alibaba Nacos | 8 | CVE-2021-29441, default JWT secret |
| XXL-Job | 4 | Default credentials, Groovy RCE |
| Adobe ColdFusion | 7 | CVE-2023-26360, CVE-2023-38205 |
| GlassFish | 3 | Path traversal, file read |
| Eclipse Jetty | 4 | Path traversal to WEB-INF |
| Apache Struts | 6 | CVE-2017-5638, CVE-2023-50164, CVE-2024-53677 |
| Prometheus/Metrics | 7 | Metrics exposure |
| Generic | 24 | .env, .git, GraphQL, H2 console |

## Bypass Techniques

| Level | Techniques |
|---|---|
| **Passive** | Trailing slash, URL encoding, double encoding, case variation, dot insertion, path parameter (`;`), null byte |
| **Moderate** | + Backslash substitution, header override (`X-Original-URL`, `X-Forwarded-For`), method override, hop-by-hop header abuse |
| **Aggressive** | + Unicode normalization (overlong UTF-8), reverse proxy misalignment, chunked transfer tricks, wildcard matching |

Includes curated bypass chains for: Nginx→Tomcat, Spring Security, AWS ALB, Liferay behind Akamai WAF.

## Project Structure

```
cmd/jps/              Entry point
runner/               CLI options, banner, 5-phase scan orchestrator
pkg/httpclient/       retryablehttp + rawhttp wrappers with rate limiting
pkg/fingerprint/      Technology detection engine
pkg/scanner/          Path bruteforcer with worker pool
pkg/bypass/           Access control bypass engine
pkg/validator/        Response validation, secret detection, deep analysis
pkg/urlutil/          URL building and normalization
pkg/output/           Console, JSONL, Markdown, HTML reporters
internal/knowledge/   Embedded knowledge base (paths, vulns, bypasses, fingerprints)
```

## Legal Disclaimer

This tool is designed for **authorized security testing only**. Always obtain proper authorization before scanning any target. The `--accept-terms` flag is required to acknowledge this.

## License

MIT
