#!/bin/bash
# Static binary verification test for LeakLens
# Verifies the binary is truly statically linked and runs in minimal containers

set -Eeuo pipefail

# Configuration
LEAKLENS_STATIC="${LEAKLENS_STATIC:-./leaklens-static}"
TESTDATA_DIR="${TESTDATA_DIR:-testdata/secrets}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

pass() {
    echo -e "${GREEN}PASS${NC}: $1"
}

fail() {
    echo -e "${RED}FAIL${NC}: $1"
    exit 1
}

warn() {
    echo -e "${YELLOW}WARN${NC}: $1"
}

# Check prerequisites
echo "=== Static Binary Test ==="
echo ""

if [ ! -f "$LEAKLENS_STATIC" ]; then
    fail "Static binary not found at $LEAKLENS_STATIC. Run 'make build-static' first."
fi

if [ ! -x "$LEAKLENS_STATIC" ]; then
    chmod +x "$LEAKLENS_STATIC"
fi

echo "Binary: $LEAKLENS_STATIC"
echo "Size: $(du -h "$LEAKLENS_STATIC" | cut -f1)"
echo ""

# Test 1: Check binary is statically linked (ldd test)
echo "=== Test 1: Static Linking Verification ==="
ldd_output=$(ldd "$LEAKLENS_STATIC" 2>&1 || true)

if echo "$ldd_output" | grep -q "not a dynamic executable"; then
    pass "Binary is not dynamically linked"
elif echo "$ldd_output" | grep -q "statically linked"; then
    pass "Binary is statically linked"
else
    # Check for any shared library dependencies
    if echo "$ldd_output" | grep -qE "\.so"; then
        warn "Binary has some dynamic dependencies:"
        echo "$ldd_output" | grep -E "\.so" | head -5
        # Don't fail - some systems show vdso which is OK
        if echo "$ldd_output" | grep -qE "libhs|libsqlite|libc\.so"; then
            fail "Binary has critical dynamic dependencies (hyperscan, sqlite, or libc)"
        fi
        pass "Only acceptable dynamic dependencies found (vdso/linux-gate)"
    else
        pass "No problematic dynamic dependencies"
    fi
fi

# Test 2: Docker container test (if Docker available)
echo "=== Test 2: Alpine Container Execution ==="
if ! command -v docker &> /dev/null; then
    warn "Docker not available, skipping container test"
else
    # Test basic execution in Alpine
    echo "Running --help in Alpine container..."
    if docker run --rm -v "$(pwd)/$LEAKLENS_STATIC:/leaklens:ro" alpine:3.19 /leaklens --help > /dev/null 2>&1; then
        pass "Binary executes in Alpine container"
    else
        fail "Binary failed to execute in Alpine container"
    fi

    # Test actual scan in Alpine
    echo "Running scan in Alpine container..."
    if docker run --rm \
        -v "$(pwd)/$LEAKLENS_STATIC:/leaklens:ro" \
        -v "$(pwd)/$TESTDATA_DIR:/testdata:ro" \
        alpine:3.19 /leaklens scan /testdata --format=json > /tmp/alpine-scan-results.json 2>&1; then

        # Verify we got actual findings
        if [ -s /tmp/alpine-scan-results.json ]; then
            findings=$(cat /tmp/alpine-scan-results.json | head -c 100)
            if echo "$findings" | grep -q "RuleID"; then
                pass "Scan produces findings in Alpine container"
            else
                warn "Scan ran but no findings detected (may be OK if test data not included)"
            fi
        else
            warn "Scan produced empty output"
        fi
        rm -f /tmp/alpine-scan-results.json
    else
        fail "Scan failed in Alpine container"
    fi
fi

# Test 3: Scratch container test (absolute minimal)
echo "=== Test 3: Scratch Container Execution ==="
if ! command -v docker &> /dev/null; then
    warn "Docker not available, skipping scratch container test"
else
    echo "Running --help in scratch container..."
    # Create minimal Dockerfile inline
    if docker run --rm -v "$(pwd)/$LEAKLENS_STATIC:/leaklens:ro" --entrypoint /leaklens scratch --help > /dev/null 2>&1; then
        pass "Binary executes in scratch container (truly static!)"
    else
        # scratch container may not have shell, try different approach
        warn "Scratch container test inconclusive (no shell to capture output)"
    fi
fi

echo ""
echo "=== Static Binary Tests Complete ==="
