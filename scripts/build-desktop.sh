#!/usr/bin/env bash
# ==============================================================================
# Synapse Core Desktop Build Script
# Targets: Linux (x86_64, aarch64), macOS (Intel, Apple Silicon), Windows (x64)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_DIR="${ROOT_DIR}/bin"

echo "=== Building Synapse Core for Desktop ==="
cd "${ROOT_DIR}"

mkdir -p "${BIN_DIR}"

# Build optimized release binary
echo "Running: cargo build --release --bin synapse-core"
cargo build --release --bin synapse-core

# Determine binary name by platform
OS_NAME="$(uname -s | tr '[:upper:]' '[:lower:]')"
TARGET_BIN="${ROOT_DIR}/target/release/synapse-core"
OUTPUT_BIN="${BIN_DIR}/synapse-core"

if [[ "${OS_NAME}" == *"mingw"* || "${OS_NAME}" == *"msys"* || "${OS_NAME}" == *"cygwin"* ]]; then
    TARGET_BIN="${TARGET_BIN}.exe"
    OUTPUT_BIN="${OUTPUT_BIN}.exe"
fi

cp "${TARGET_BIN}" "${OUTPUT_BIN}"

# Strip symbols to achieve compact binary footprint (~5-10MB)
if command -v strip &>/dev/null; then
    echo "Stripping binary symbols with strip..."
    strip "${OUTPUT_BIN}" || true
fi

chmod +x "${OUTPUT_BIN}"

SIZE_BYTES=$(wc -c < "${OUTPUT_BIN}")
SIZE_MB=$(awk "BEGIN {printf \"%.2f\", ${SIZE_BYTES}/1048576}")

echo "=========================================================="
echo "Build Successful!"
echo "Binary Output: ${OUTPUT_BIN}"
echo "Binary Size:   ${SIZE_MB} MB (${SIZE_BYTES} bytes)"
echo "=========================================================="
