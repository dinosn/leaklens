# LeakLens

LeakLens is a web-aware secrets scanner for source code, Git history, local files, direct URLs, and modern JavaScript-heavy web applications.

It is our own tool and repository. It started from the original [Praetorian Titus](https://github.com/praetorian-inc/titus) codebase, keeps the high-performance secret scanning engine and rule lineage, and adds a web-app workflow around crawling, JavaScript discovery, source-map recovery, and JS intelligence artifacts.

LeakLens uses [ProjectDiscovery Katana](https://github.com/projectdiscovery/katana) for crawling. The JS intelligence layer is inspired by concepts from PortSwigger [js-miner](https://github.com/PortSwigger/js-miner), but it is implemented in LeakLens as a separate informational layer. LeakLens secret findings still come from the scanner rule engine.

Use LeakLens only on codebases, repositories, and websites you are authorized to test.

## Current Focus

- CLI scanning for files, directories, Git repositories, direct URLs, and crawled websites.
- Secret detection with optional live validation.
- Web crawling for JS/JSON discovery using Katana.
- URL repair for same-host JS paths that are resolved too deeply by crawlers.
- JS intelligence for endpoints, source maps, cloud URLs, subdomains, dependencies, and opt-in dependency-confusion checks.
- Go library usage for embedding the scanner in other internal tools.

## Install

LeakLens supports two install paths:

- Install from source with `go install`.
- Build locally with optional Vectorscan/Hyperscan acceleration.

### Go Install

`go install` installs directly from the GitHub repository and writes the binary to `$(go env GOPATH)/bin`.
Make sure that directory is in your `PATH`.
Use `@main` to install the latest tested LeakLens branch.

Pure-Go install:

```bash
go install github.com/dinosn/leaklens/cmd/leaklens@main
```

Accelerated install with Vectorscan/Hyperscan:

```bash
CGO_ENABLED=1 go install -tags vectorscan github.com/dinosn/leaklens/cmd/leaklens@main
```

### Local Build

Build the portable pure-Go binary:

```bash
make build-pure
```

The binary is written to:

```bash
dist/leaklens
```

Build with Vectorscan/Hyperscan acceleration:

```bash
make build
```

The default `make build` target uses CGO and the `vectorscan` build tag. It requires a compatible native library and `pkg-config`.

Install native dependencies:

```bash
# macOS
brew install vectorscan pkg-config

# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y pkg-config libhyperscan-dev

# Fedora/RHEL
sudo dnf install -y pkgconf-pkg-config hyperscan-devel
```

On macOS, Homebrew installs Vectorscan under the active Homebrew prefix. If `pkg-config` cannot find `libhs`, export the package-config path:

```bash
export PKG_CONFIG_PATH="$(brew --prefix vectorscan)/lib/pkgconfig:$PKG_CONFIG_PATH"
```

Use matching architectures for Go and the native library. For example, an x86_64 Go toolchain cannot link an arm64 Homebrew Vectorscan library. If the architecture does not match, either install a matching Go toolchain/native library pair or use `make build-pure`.

On Apple Silicon, this linker error means Go is running as `amd64` while Homebrew Vectorscan is `arm64`:

```text
ld: warning: ignoring file '/opt/homebrew/.../libhs.dylib': found architecture 'arm64', required architecture 'x86_64'
Undefined symbols for architecture x86_64: "_hs_*"
```

Preferred fix: use an arm64 Go toolchain with the arm64 Homebrew libraries:

```bash
brew install go vectorscan pkg-config
export PATH="/opt/homebrew/bin:$PATH"
go env -u GOARCH
go env -u GOOS
export PKG_CONFIG_PATH="$(brew --prefix vectorscan)/lib/pkgconfig:$PKG_CONFIG_PATH"
CGO_ENABLED=1 go install -tags vectorscan github.com/dinosn/leaklens/cmd/leaklens@main
```

Fallback without native acceleration:

```bash
CGO_ENABLED=0 go install github.com/dinosn/leaklens/cmd/leaklens@main
```

## Version and Updates

Check the installed build:

```bash
leaklens version
```

Check GitHub for the latest `main` branch build:

```bash
leaklens update
```

LeakLens also performs a short `main` branch check when a command starts. The automatic notification is written to stderr so scan output stays parseable. This matches the documented `go install ...@main` install path and reports whether the installed binary is built from the latest `main` commit. If the current build cannot be mapped to a commit, normal scans stay quiet and `leaklens update` reports that state explicitly.

Disable the automatic check for scripted runs:

```bash
leaklens --no-update-check scan path/to/source
LEAKLENS_NO_UPDATE_CHECK=true leaklens scan path/to/source
```

## Quick Start

```bash
# Scan a file
leaklens scan path/to/file.txt

# Scan a directory
leaklens scan path/to/source

# Scan Git history
leaklens scan --git path/to/repo

# Scan a direct URL
leaklens scan https://example.com/static/app.js

# Scan URLs from a file
leaklens scan --url-file urls.txt

# Crawl a website and scan discovered JS/JSON files
leaklens scan --crawl https://example.com

# Crawl with JS intelligence and source-map rescanning
leaklens scan --crawl --js-intel https://example.com

# Validate detected secrets against provider APIs
leaklens scan path/to/source --validate
```

By default, scan results are printed in human format and stored in `leaklens.ds`. Use `--output :memory:` when you do not want a datastore.

## Website Testing

Default web-app crawl profile:

```bash
leaklens scan --crawl https://example.com
```

This default profile enables:

- standard crawling without launching Chrome
- `--crawl-js-crawl=true`
- `--crawl-depth=3`
- `--crawl-concurrency=2`
- `--crawl-rate-limit=3`
- `--crawl-timeout=2m`
- `--crawl-extensions=js,json`
- `--crawl-scope=rdn`

To save crawled files as a readable website-style directory tree while scanning:

```bash
leaklens scan --crawl https://example.com/app/ --download-dir downloaded-site
```

Downloaded URL contents are saved under `downloaded-site/<host>/<path>`. Query strings are preserved in the filename, so `app.js` and `app.js?v=63` are stored separately.

Use headless crawling only when the standard crawler misses browser-rendered assets:

```bash
leaklens scan --crawl --crawl-headless https://example.com
```

For richer web-app triage:

```bash
leaklens scan --crawl --js-intel https://example.com
```

For applications where JavaScript-discovered relative paths are resolved under the wrong directory, set the application root explicitly:

```bash
leaklens scan --crawl --js-intel \
  --crawl-base-url https://example.com/app/ \
  https://example.com/app/static/js/main.js
```

LeakLens keeps the crawler-discovered URL as the primary candidate and then tries same-host repaired candidates. When a fallback succeeds, human output shows a `repaired:` line.

## JS Intelligence

Enable the JS intelligence layer with:

```bash
leaklens scan --crawl --js-intel https://example.com
```

This layer reports supporting artifacts. It does not replace the normal LeakLens secret rules.

| Artifact | Behavior |
| --- | --- |
| Endpoints | Extracts URL-like values from `fetch`, `importScripts`, HTTP method calls, and URL/path properties. |
| Cloud URLs | Finds common S3, GCS, Azure Blob, and DigitalOcean Spaces URLs. |
| Subdomains | Extracts domain-like hostnames from JS/JSON content. |
| Dependencies | Extracts package names from `package.json`, lockfile package paths, imports, requires, and `node_modules` references. |
| Source maps | Detects external source-map references and decodes inline source maps. Embedded `sourcesContent` files are rescanned with normal LeakLens rules. |
| Generic secret heuristic | Optional low-confidence JS assignment heuristic. Values are masked in JS-intel output. |
| Dependency-confusion candidate | Optional active npm registry check. Reports packages that return `404` from the configured registry. |

Useful examples:

```bash
# Include masked low-confidence generic JS assignments
leaklens scan --crawl --js-intel --js-intel-generic-secrets https://example.com

# Actively check discovered npm packages for public-registry misses
leaklens scan --crawl --js-intel --js-intel-npm-check https://example.com

# Disable inline source-map parsing while keeping other JS intelligence
leaklens scan --crawl --js-intel --js-intel-source-maps=false https://example.com
```

For `json` and `sarif` scan output, source-map-derived secret matches are included through the normal result path. Informational JS intelligence is currently printed in human output only, so machine-readable secret outputs stay stable.

## Scan Command

```bash
leaklens scan [target] [flags]
```

Targets can be:

- A local file or directory.
- A local Git repository.
- A direct HTTP(S) URL.
- A GitHub repository reference such as `github.com/org/repo`.
- A GitLab project reference such as `gitlab.com/group/project`.

### Core Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--output` | `leaklens.ds` | Output datastore path. Use `:memory:` for in-memory only. |
| `--format` | `human` | Output format: `human`, `json`, or `sarif`. |
| `--rules` | | Path to a custom rule file or directory. |
| `--rules-include` | | Include rules matching regex patterns, comma-separated. |
| `--rules-exclude` | | Exclude rules matching regex patterns, comma-separated. |
| `--git` | `false` | Treat the target as a Git repository and enumerate history. |
| `--max-file-size` | `10485760` | Maximum file size to scan in bytes. |
| `--include-hidden` | `false` | Include hidden files and directories. |
| `--context-lines` | `3` | Lines of context before and after matches. Use `0` to disable. |
| `--incremental` | `false` | Skip already-scanned blobs. |
| `--validate` | `false` | Validate detected secrets against provider APIs. |
| `--validate-workers` | `4` | Concurrent validation workers. |
| `--workers` | CPU count | Parallel scan workers. |
| `--store-blobs` | `false` | Store file contents under the datastore blob directory. |
| `--download-dir` | | Write downloaded URL contents to a directory that preserves the website path structure. |
| `--url-file` | | File containing URLs to scan, one per line. Use `-` for stdin. |
| `--sqlite-row-limit` | `1000` | Max rows per SQLite table when extraction is enabled. Use `0` for unlimited. |

### Extraction Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--extract` | | Extract text from binary files. Supported values include `xlsx`, `docx`, `pdf`, `zip`, or `all`. |
| `--extract-max-size` | `10MB` | Max uncompressed size per extracted file. |
| `--extract-max-total` | `100MB` | Max total bytes to extract from one archive. |
| `--extract-max-depth` | `5` | Max nested archive depth. |

### Crawl Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--crawl` | `false` | Enable crawl mode. |
| `--crawl-depth` | `3` | Maximum crawl depth. |
| `--crawl-concurrency` | `2` | Concurrent crawl workers. |
| `--crawl-rate-limit` | `3` | Maximum crawl requests per second. |
| `--crawl-host-rate-limit` | `0` | Maximum requests per second per host. `0` uses `--crawl-rate-limit`. |
| `--crawl-timeout` | `2m` | Maximum crawl duration. |
| `--crawl-headless` | `false` | Use a headless browser for JS-heavy sites. |
| `--crawl-js-crawl` | `true` | Parse JavaScript files for additional endpoints. |
| `--crawl-extensions` | `js,json` | File extensions to collect and scan. |
| `--crawl-scope` | `rdn` | Scope: `rdn`, `dn`, or `fqdn`. |
| `--crawl-base-url` | | Application base URL for repairing JS-discovered relative paths. |
| `--crawl-max-domain-pages` | `0` | Maximum pages to crawl per domain. `0` is unlimited. |
| `--crawl-chrome-data-dir` | | Chrome user-data-dir for preserving sessions. |
| `--crawl-chrome-ws-url` | | Chrome DevTools websocket URL for attaching to an existing browser. |
| `--crawl-system-chrome-path` | | Chrome or Chromium binary path. |
| `--crawl-use-installed-chrome` | `false` | Use installed Chrome instead of Katana-managed Chrome. |
| `--crawl-no-incognito` | `false` | Run headless crawl without an incognito context. |
| `--crawl-no-sandbox` | `false` | Run headless Chrome with `--no-sandbox`. Auto-enabled when LeakLens launches headless Chrome as root. |
| `--crawl-automatic-form-fill` | `false` | Enable Katana automatic form filling and submission. |
| `--crawl-auth` | | `username:password` for Katana automatic login. |

### JS Intelligence Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--js-intel` | `false` | Extract JS intelligence artifacts and rescan inline source-map sources. |
| `--js-intel-source-maps` | `true` | Parse inline source maps and scan embedded sources when `--js-intel` is enabled. |
| `--js-intel-generic-secrets` | `false` | Enable low-confidence JS-style generic secret heuristics. |
| `--js-intel-npm-check` | `false` | Actively check discovered npm packages for public-registry misses. |

## GitHub and GitLab

Direct repository references work through `scan`:

```bash
leaklens scan github.com/org/repo
leaklens scan gitlab.com/group/project
```

Use dedicated commands for org, user, group, and token-aware workflows:

```bash
# GitHub repository
leaklens github org/repo

# GitHub organization
leaklens github --org my-org --token "$GITHUB_TOKEN"

# GitLab project
leaklens gitlab group/project

# GitLab group
leaklens gitlab --group my-group --token "$GITLAB_TOKEN"
```

Important flags:

| Flag | GitHub | GitLab | Description |
| --- | --- | --- | --- |
| `--token` | yes | yes | API token. Optional for public projects. |
| `--git` | yes | yes | Scan full Git history. |
| `--no-clone` | yes | yes | Fetch files via API instead of cloning. Requires token and does not scan Git history. |
| `--org` | yes | no | Scan all repositories in a GitHub organization. |
| `--user` | yes | yes | Scan repositories/projects for a user. |
| `--group` | no | yes | Scan all GitLab projects in a group. |
| `--url` | no | yes | GitLab base URL. Default is `gitlab.com`. |
| `--output` | yes | yes | Output database path. Default is `leaklens.db`. |
| `--format` | yes | yes | Output format: `human` or `json`. |

## Reports and Exploration

Scan results are stored in a datastore unless `--output :memory:` is used.

```bash
# Human report from default datastore
leaklens report

# JSON report
leaklens report --format json

# SARIF report
leaklens report --format sarif

# Report from a specific datastore
leaklens report --datastore path/to/leaklens.ds

# TUI exploration
leaklens explore --datastore path/to/leaklens.ds
```

## Rules

```bash
# List built-in rules
leaklens rules list

# Scan with only matching rules
leaklens scan path/to/source --rules-include "aws,gcp"

# Exclude noisy rules
leaklens scan path/to/source --rules-exclude "generic"

# Use custom rules
leaklens scan path/to/source --rules path/to/rules.yaml
```

## Go Library

```bash
go get github.com/dinosn/leaklens
```

```go
package main

import (
	"fmt"
	"log"

	"github.com/dinosn/leaklens"
)

func main() {
	scanner, err := leaklens.NewScanner()
	if err != nil {
		log.Fatal(err)
	}
	defer scanner.Close()

	matches, err := scanner.ScanString(`aws_access_key_id = AKIAIOSFODNN7EXAMPLE`)
	if err != nil {
		log.Fatal(err)
	}

	for _, match := range matches {
		fmt.Printf("%s at offset %d\n", match.RuleName, match.Location.Offset.Start)
	}
}
```

## Output Formats

LeakLens supports:

- `human`: grouped per-file output with a summary.
- `json`: machine-readable matches.
- `sarif`: SARIF 2.1.0 output with tool name `leaklens`.

Examples:

```bash
leaklens scan path/to/source --format json
leaklens scan path/to/source --format sarif
```

## Validation

Validation is disabled by default. When enabled, LeakLens attempts provider-specific checks for supported secret types:

```bash
leaklens scan path/to/source --validate --validate-workers 8
```

Validation can make outbound requests to provider APIs. Use it only when that is acceptable for the engagement.

## Build and Test

```bash
# Pure-Go portable binary
make build-pure

# Accelerated build when compatible Vectorscan/Hyperscan is installed
make build

# Static binary
make build-static

# Tests
go test ./...
```

If macOS blocks the default Go cache in a restricted environment, use explicit caches:

```bash
GOCACHE=/private/tmp/go-build-leaklens \
GOMODCACHE=/private/tmp/go-mod-leaklens \
go test ./...
```

## Attribution

LeakLens builds on and credits:

- [Praetorian Titus](https://github.com/praetorian-inc/titus): original scanner foundation and Go implementation lineage.
- [NoseyParker](https://github.com/praetorian-inc/noseyparker) and [Kingfisher](https://github.com/mongodb/kingfisher): detection-rule lineage.
- [ProjectDiscovery Katana](https://github.com/projectdiscovery/katana): crawling engine used by `--crawl`.
- [PortSwigger js-miner](https://github.com/PortSwigger/js-miner): inspiration for JS intelligence concepts such as endpoint, dependency, source-map, and JavaScript artifact discovery.

LeakLens is maintained independently in this repository.

## License

This project follows the repository license. Keep upstream attribution when redistributing derivative work.
