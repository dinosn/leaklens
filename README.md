# LeakLens

LeakLens is a web-aware secrets scanner for source code, Git history, local files, direct URLs, and modern JavaScript-heavy web applications.

The idea started from the original [Praetorian Titus](https://github.com/praetorian-inc/titus) codebase. LeakLens keeps the high-performance secret scanning engine and rule lineage, then extends that foundation into a web-app workflow around crawling, JavaScript discovery, source-map recovery, JS intelligence artifacts, and AI-assisted review.

LeakLens crawling is based on [ProjectDiscovery Katana](https://github.com/projectdiscovery/katana), with LeakLens-specific discovery and repair logic layered on top. The crawler now augments Katana output with direct HTML asset extraction, JavaScript bundle expansion, lazy chunk discovery, same-host URL repair, escaped-path normalization, and downloaded-asset mirroring before scanning. JS intelligence remains a separate informational layer; LeakLens secret findings still come from the scanner rule engine.

Use LeakLens only on codebases, repositories, and websites you are authorized to test.

## Current Focus

- CLI scanning for files, directories, Git repositories, direct URLs, and crawled websites.
- Secret detection with optional live validation.
- Katana-based web crawling with LeakLens-specific JS/JSON/source-map discovery and URL repair.
- URL repair for same-host JS paths that are resolved too deeply by crawlers.
- JS intelligence for endpoints, source maps, cloud URLs, subdomains, dependencies, and opt-in dependency-confusion checks.
- Go library usage for embedding the scanner in other internal tools.

## Install

LeakLens supports two install paths:

- Install from source with `go install`.
- Build locally with optional Vectorscan/Hyperscan acceleration.

### Go Install

`go install` installs from the GitHub repository and writes the binary to `$(go env GOPATH)/bin`.
Make sure that directory is in your `PATH`.

Use a tagged release for stable version output:

```bash
CGO_ENABLED=1 go install -tags vectorscan github.com/dinosn/leaklens/cmd/leaklens@v0.2.4
```

Use `@main` to install the latest tested LeakLens branch. The `@main` examples use `GOPROXY=direct` so the moving branch is resolved from GitHub instead of a possibly stale Go module proxy response. Main builds display as `main@<commit>` in `leaklens version`.

Pure-Go install:

```bash
GOPROXY=direct go install github.com/dinosn/leaklens/cmd/leaklens@main
```

Accelerated install with Vectorscan/Hyperscan:

```bash
GOPROXY=direct CGO_ENABLED=1 go install -tags vectorscan github.com/dinosn/leaklens/cmd/leaklens@main
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
GOPROXY=direct CGO_ENABLED=1 go install -tags vectorscan github.com/dinosn/leaklens/cmd/leaklens@main
```

Fallback without native acceleration:

```bash
GOPROXY=direct CGO_ENABLED=0 go install github.com/dinosn/leaklens/cmd/leaklens@main
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

Install the latest `main` branch build directly:

```bash
leaklens update --install
```

`leaklens update --install` preserves the current build mode. A binary built with Vectorscan/Hyperscan runs the vectorscan `go install` command, while a portable binary runs the normal `go install` command. Both use `GOPROXY=direct` so `main` is resolved from GitHub.

Tagged installs report the tag, such as `v0.2.4`. Main branch installs report `main@<commit>` instead of Go's raw pseudo-version.

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

# Crawl a website and scan discovered JS/JSON/source-map files
leaklens scan --crawl https://example.com

# Crawl with JS intelligence
leaklens scan --crawl --js-intel https://example.com

# Validate detected secrets against provider APIs
leaklens scan path/to/source --validate
```

By default, scan results are printed in human format and kept in memory. Use `--output leaklens.ds` or another path when you want a datastore for later reporting.

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
- `--crawl-timeout=5m`
- `--crawl-extensions=js,json,map`
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
| Source maps | Crawl mode discovers external `.map` files and probes sibling `.js.map` files for discovered JavaScript assets. Standalone map files and embedded `sourcesContent` entries are rescanned with normal LeakLens rules. JS intelligence also decodes inline source maps when enabled. |
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
| `--output` | `:memory:` | Output datastore path. Use a path such as `leaklens.ds` when you want a persistent datastore. |
| `--format` | `human` | Output format: `human`, `json`, or `sarif`. |
| `--rules` | | Path to a custom rule file or directory. |
| `--rules-include` | | Include rules matching regex patterns, comma-separated. |
| `--rules-exclude` | | Exclude rules matching regex patterns, comma-separated. |
| `--git` | `false` | Treat the target as a Git repository and enumerate history. |
| `--max-file-size` | `20971520` | Maximum file size to scan. Accepts bytes or `KB`, `MB`, `GB`. |
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
| `--crawl-timeout` | `5m` | Maximum crawl duration. |
| `--crawl-headless` | `false` | Use a headless browser for JS-heavy sites. |
| `--crawl-js-crawl` | `true` | Parse JavaScript files for additional endpoints. |
| `--crawl-extensions` | `js,json,map` | File extensions to collect and scan. |
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

### AI-Assisted JS Review

LeakLens can run an optional AI-assisted review after the normal deterministic scan. This is intended for authorized validation and remediation work over JavaScript, TypeScript, JSON, and source-map artifacts. The scanner rules still run first and remain the deterministic source of secret findings. The AI layer is a second-stage analyst that reviews the collected files, explains application behavior, proposes additional secret candidates, and writes owner-facing test plans.

AI review works with crawled sites, direct URL scans, URL-file scans, local files, local directories, local Git repositories, and cloned GitHub/GitLab targets. For URL and crawl scans, `--ai` automatically enables downloaded-file storage. If `--download-dir` is not supplied, LeakLens creates one under the AI report directory.

Provider configuration is environment-only so API keys are not exposed in command lines:

```bash
export LEAKLENS_AI_PROVIDER=openai        # openai or anthropic
export LEAKLENS_AI_MODEL=your-model-name
export LEAKLENS_OPENAI_API_KEY=...
export LEAKLENS_ANTHROPIC_API_KEY=...
export LEAKLENS_AI_TIMEOUT=5m             # optional per provider request timeout
export LEAKLENS_AI_RETRIES=3              # optional transient provider retry count
export LEAKLENS_AI_CHUNK_CHARS=60000      # optional max redacted characters per AI chunk
export LEAKLENS_AI_CONCURRENCY=3          # optional parallel AI chunk reviews
```

Examples:

```bash
leaklens scan --crawl --ai https://example.com
leaklens scan --ai --ai-mode secrets path/to/downloaded-site
leaklens scan --ai --ai-mode appsec --ai-report-dir reports/example path/to/app
leaklens scan --crawl --ai --ai-cloud-redaction expanded https://example.com
```

AI flags:

| Flag | Default | Description |
| --- | --- | --- |
| `--ai` | `false` | Run AI-assisted JS/JSON/source-map analysis after scanning. |
| `--ai-mode` | `all` | AI analysis mode: `secrets`, `appsec`, or `all`. |
| `--ai-report-dir` | | Directory for AI artifacts. Default: `leaklens-ai/<target>-<timestamp>`. |
| `--ai-cloud-redaction` | `standard` | Cloud redaction mode: `standard` or `expanded`. Target URLs and hostnames are always redacted in both modes. |
| `--ai-progress` | `text` | AI progress output: `text` or `quiet`. A JSON-lines progress artifact is always written. |
| `--ai-resume` | `false` | Reuse completed AI response checkpoints from the same `--ai-report-dir`. |

AI artifacts:

| File | Description |
| --- | --- |
| `leaklens-ai-report.md` | Markdown report with scope, coverage, AI findings, curl-style validation ideas, locations, and remediation notes. |
| `corpus-manifest.json` | Local manifest of every file selected for AI review, its cloud-redacted path, size, line count, and chunk count. |
| `ai-progress.ndjson` | Machine-readable progress events for long-running AI analysis. |
| `ai-redaction-map.json` | Local-only mapping from redacted cloud placeholders back to real origins, hostnames, and file paths. Do not upload this file to third parties. |
| `ai-chunks/` | Checkpointed provider responses for completed overview and file-chunk reviews. These are reused by `--ai-resume`. |

AI provider resilience:

- Transient provider failures such as request timeouts, HTTP 408, HTTP 429, and HTTP 5xx responses are retried according to `LEAKLENS_AI_RETRIES`.
- A failed overview or file chunk no longer aborts the whole scan after the local corpus is built. LeakLens writes a partial Markdown report, records failed stages in `AI Failures`, and preserves successful responses in `ai-chunks/`.
- To continue a long run, rerun the same scan with the same `--ai-report-dir --ai-resume`. Completed checkpoints are reused and only missing chunks are sent to the provider.
- File chunks are reviewed in parallel according to `LEAKLENS_AI_CONCURRENCY`. Set it to `1` for serial provider calls or lower it if the provider rate-limits the run.
- With `--ai-progress=text`, high-signal AI observations from completed overview and chunk responses are printed immediately as `AI insight:` lines while the full report is still being built.
- Use `LEAKLENS_AI_TIMEOUT` for slow provider responses and `LEAKLENS_AI_CHUNK_CHARS` to reduce request size for models or networks that time out on large chunks. The default chunk size is `60000` characters, matching the original AI chunking behavior.

Cloud redaction behavior:

- Target URLs and hostnames are always redacted before provider submission. This is not bypassable by flags.
- URL paths are preserved so AI can still reason about endpoints. For example, `https://www.example.com/api/admin/config` is sent as `TARGET_ORIGIN_1/api/admin/config`.
- Third-party origins are also redacted, for example `https://cdn.vendor.com/lib.js` becomes `EXTERNAL_ORIGIN_1/lib.js`.
- Local absolute paths are replaced with file placeholders before provider submission.

`--ai-cloud-redaction standard` redacts obvious credentials, authorization headers, cookie values, secret-bearing query values, and generic high-entropy strings before provider submission. It keeps variable names, function names, endpoint paths, HTTP methods, and structural context.

`--ai-cloud-redaction expanded` still redacts target origins, hostnames, local filesystem paths, authorization headers, cookie values, and obvious credential assignments, but preserves URL endpoint paths and more non-URL JavaScript context. For example, `https://www.example.com/api/files/upload` is sent and reported as `TARGET_ORIGIN_1/api/files/upload`, not as a generic redacted upload endpoint. Use this mode when deeper AI reasoning over config and string literals is needed. It does not disable target origin or hostname redaction.

LeakLens does not execute AI-generated curl commands. The report contains validation plans only. Active testing may be added later behind a separate explicit option.

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

Scan results are kept in memory unless `--output` is set to a datastore path.

```bash
# Human report from leaklens.ds
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
