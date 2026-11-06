#!/usr/bin/env bash
# ==============================================================================
# Synapse Core Android Build Script
#
# Solves Android 10+ W^X SELinux restriction by compiling the standalone engine
# for Android Linux ABIs and renaming the binary to `libsynapse.so` inside
# `jniLibs/<abi>/` so the Android package manager automatically extracts it
# into `nativeLibraryDir` with executable rights (+x).
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Target ABIs
# arm64-v8a    -> aarch64-linux-android
# armeabi-v7a  -> armv7-linux-androideabi
# x86_64       -> x86_64-linux-android
DEFAULT_JNI_DIR="${ROOT_DIR}/../app/androidApp/src/main/jniLibs"
OUTPUT_DIR="${1:-${DEFAULT_JNI_DIR}}"

echo "=== Building Synapse Core for Android ==="
echo "Output Directory: ${OUTPUT_DIR}"

if ! command -v cargo-ndk &>/dev/null; then
    echo "Notice: 'cargo-ndk' is not detected in PATH."
    echo "To install cargo-ndk: cargo install cargo-ndk"
    echo "Ensure ANDROID_NDK_HOME is configured."
    echo ""
    echo "Creating fallback binary package structure..."
    mkdir -p "${ROOT_DIR}/bin/android/arm64-v8a"
    mkdir -p "${ROOT_DIR}/bin/android/armeabi-v7a"
    mkdir -p "${ROOT_DIR}/bin/android/x86_64"

    # If running on local Linux aarch64 or x86_64, compile local release artifact as reference
    cargo build --release --bin synapse-core
    LOCAL_ARCH="$(uname -m)"
    if [ "${LOCAL_ARCH}" = "aarch64" ]; then
        cp "${ROOT_DIR}/target/release/synapse-core" "${ROOT_DIR}/bin/android/arm64-v8a/libsynapse.so"
    elif [ "${LOCAL_ARCH}" = "x86_64" ]; then
        cp "${ROOT_DIR}/target/release/synapse-core" "${ROOT_DIR}/bin/android/x86_64/libsynapse.so"
    fi
    echo "Reference artifact prepared in ${ROOT_DIR}/bin/android/"
    exit 0
fi

ABIS=("arm64-v8a" "armeabi-v7a" "x86_64")
TARGETS=("aarch64-linux-android" "armv7-linux-androideabi" "x86_64-linux-android")

for i in "${!ABIS[@]}"; do
    ABI="${ABIS[$i]}"
    TARGET="${TARGETS[$i]}"
    DEST_DIR="${OUTPUT_DIR}/${ABI}"
    mkdir -p "${DEST_DIR}"

    echo "--> Compiling for Android ABI: ${ABI} (${TARGET})..."
    rustup target add "${TARGET}" 2>/dev/null || true

    cargo ndk -t "${ABI}" build --release --bin synapse-core

    SRC_BIN="${ROOT_DIR}/target/${TARGET}/release/synapse-core"
    DEST_SO="${DEST_DIR}/libsynapse.so"

    cp "${SRC_BIN}" "${DEST_SO}"
    chmod +x "${DEST_SO}"

    echo "    Output: ${DEST_SO} ($(wc -c < "${DEST_SO}") bytes)"
done

echo "=========================================================="
echo "Android libsynapse.so build completed successfully!"
echo "Destination: ${OUTPUT_DIR}"
echo "=========================================================="
