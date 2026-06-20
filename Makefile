# LeakLens Makefile
# Build automation for secrets scanner

.PHONY: all build build-pure build-static test vet lint clean integration-test static-test check-vectorscan

VERSION ?= dev
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

# Vectorscan/Hyperscan acceleration (default: enabled)
# Override with CGO_ENABLED=0 or make build-pure for pure-Go fallback
CGO_ENABLED ?= 1
GO_TAGS ?= vectorscan

# Clear vectorscan tag when CGO is disabled (vectorscan requires CGO)
ifeq ($(CGO_ENABLED),0)
  GO_TAGS :=
endif

# Build -tags flag (empty when GO_TAGS is empty to avoid bare "-tags" argument)
ifneq ($(GO_TAGS),)
  TAGS_FLAG := -tags $(GO_TAGS)
else
  TAGS_FLAG :=
endif

# Auto-detect vectorscan pkg-config path on macOS (Homebrew)
VECTORSCAN_PREFIX := $(shell brew --prefix vectorscan 2>/dev/null)
ifneq ($(VECTORSCAN_PREFIX),)
  export PKG_CONFIG_PATH := $(VECTORSCAN_PREFIX)/lib/pkgconfig:$(PKG_CONFIG_PATH)
endif

# Detect whether vectorscan is available for the build
VECTORSCAN_AVAILABLE := $(shell pkg-config --exists libhs 2>/dev/null && echo 1 || echo 0)

# Determine if the vectorscan check is needed for this build
ifeq ($(CGO_ENABLED),1)
  ifneq ($(findstring vectorscan,$(GO_TAGS)),)
    BUILD_NEEDS_VECTORSCAN := 1
  endif
endif

# Default target
all: build test vet

# Build the project (with Vectorscan/Hyperscan acceleration by default)
ifdef BUILD_NEEDS_VECTORSCAN
BUILD_DEPS := check-vectorscan
else
BUILD_DEPS :=
endif

build: $(BUILD_DEPS)
	@mkdir -p dist
	GOWORK=off CGO_ENABLED=$(CGO_ENABLED) go build $(TAGS_FLAG) $(LDFLAGS) -o dist/leaklens ./cmd/leaklens

# Check vectorscan/hyperscan availability and attempt auto-install if missing
check-vectorscan:
ifeq ($(VECTORSCAN_AVAILABLE),0)
	@echo ""
	@echo "=== Vectorscan/Hyperscan not found ==="
	@echo ""
	@echo "Attempting to install automatically..."
	@if [ "$$(uname)" = "Darwin" ]; then \
		brew install vectorscan && \
		export PKG_CONFIG_PATH="$$(brew --prefix vectorscan)/lib/pkgconfig:$$PKG_CONFIG_PATH" && \
		echo "[vectorscan] Installed successfully via Homebrew" || \
		(echo "" && \
		echo "Vectorscan is required for the default build (10-100x faster scanning)." && \
		echo "Install it manually:" && \
		echo "" && \
		echo "  macOS (Homebrew):  brew install vectorscan" && \
		echo "  Ubuntu/Debian:     sudo apt-get install libhyperscan-dev" && \
		echo "  Fedora/RHEL:       sudo dnf install hyperscan-devel" && \
		echo "" && \
		echo "Or build without vectorscan (slower, but no dependencies):" && \
		echo "  make build-pure" && \
		echo "" && \
		exit 1); \
	else \
		sudo apt-get install -y libhyperscan-dev && \
		echo "[vectorscan] Installed successfully via apt-get" || \
		(echo "" && \
		echo "Vectorscan is required for the default build (10-100x faster scanning)." && \
		echo "Install it manually:" && \
		echo "" && \
		echo "  macOS (Homebrew):  brew install vectorscan" && \
		echo "  Ubuntu/Debian:     sudo apt-get install libhyperscan-dev" && \
		echo "  Fedora/RHEL:       sudo dnf install hyperscan-devel" && \
		echo "" && \
		echo "Or build without vectorscan (slower, but no dependencies):" && \
		echo "  make build-pure" && \
		echo "" && \
		exit 1); \
	fi
else
	@echo "[vectorscan] Found hyperscan via pkg-config"
endif

# Build pure-Go binary (no CGO, no Vectorscan — portable fallback)
build-pure:
	@mkdir -p dist
	GOWORK=off CGO_ENABLED=0 go build $(LDFLAGS) -o dist/leaklens ./cmd/leaklens

# Build statically linked binary (pure Go, no CGO required)
build-static:
	@mkdir -p dist
	GOWORK=off CGO_ENABLED=0 go build \
		$(LDFLAGS) \
		-o dist/leaklens-static ./cmd/leaklens

# Run unit tests
test:
	GOWORK=off CGO_ENABLED=$(CGO_ENABLED) go test $(TAGS_FLAG) -v ./...

# Run integration tests
integration-test: build
	GOWORK=off CGO_ENABLED=$(CGO_ENABLED) go test -tags "integration $(GO_TAGS)" -v ./tests/integration/...

# Run go vet
vet:
	GOWORK=off CGO_ENABLED=$(CGO_ENABLED) go vet $(TAGS_FLAG) ./...

# Run staticcheck (optional)
lint:
	@which staticcheck > /dev/null || (echo "staticcheck not installed" && exit 0)
	GOWORK=off CGO_ENABLED=$(CGO_ENABLED) staticcheck $(TAGS_FLAG) ./...

# Clean build artifacts
clean:
	rm -f leaklens leaklens-static
	rm -f leaklens.db
	rm -rf dist/

# Clean everything
clean-all: clean

# Run static binary test in container (requires build-static and docker)
static-test: build-static
	./scripts/static-binary-test.sh
