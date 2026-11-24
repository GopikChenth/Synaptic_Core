#!/usr/bin/env bash
# ==============================================================================
# Synapse Core - Android build
#
# Produces, per ABI, a drop-in jniLibs tree:
#
#   <out>/<abi>/libsynapse.so    the engine executable, spawned by the app from
#                                ApplicationInfo.nativeLibraryDir
#
# Uses the NDK's clang directly (no cargo-ndk), pins 16 KiB page alignment, and
# verifies every artifact with scripts/verify-android-elf.sh. There is deliberately
# no "fallback": a desktop build copied into jniLibs can never run on Android.
#
# Usage:
#   ANDROID_NDK_HOME=/path/to/ndk scripts/build-android.sh [options]
#
# Options:
#   -o, --out DIR        output jniLibs directory   (default: dist/android/jniLibs)
#   -a, --abis LIST      comma-separated ABIs       (default: arm64-v8a,armeabi-v7a,x86_64)
#       --api LEVEL      minimum Android API level  (default: 21)
#       --profile NAME   cargo profile              (default: release)
#   -h, --help
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

OUT_DIR="${ROOT_DIR}/dist/android/jniLibs"
ABIS="arm64-v8a,armeabi-v7a,x86_64"
API_LEVEL="${ANDROID_API_LEVEL:-21}"
PROFILE="release"

usage() { sed -n '3,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--out) OUT_DIR="$2"; shift 2 ;;
        -a|--abis) ABIS="$2"; shift 2 ;;
        --api) API_LEVEL="$2"; shift 2 ;;
        --profile) PROFILE="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown option '$1'" >&2; usage >&2; exit 2 ;;
    esac
done

die() { echo "error: $*" >&2; exit 1; }

# ---- Locate the NDK ---------------------------------------------------------
NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-${ANDROID_NDK:-}}}"
if [[ -z "${NDK}" && -n "${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}" ]]; then
    SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT}}"
    NDK="$(ls -d "${SDK}"/ndk/* 2>/dev/null | sort -V | tail -1 || true)"
fi
[[ -n "${NDK}" && -d "${NDK}" ]] || die "Android NDK not found. Set ANDROID_NDK_HOME (NDK r27c or newer recommended)."

NDK_REV="$(sed -n 's/^Pkg.Revision *= *\([0-9]*\).*/\1/p' "${NDK}/source.properties" 2>/dev/null || true)"
if [[ -n "${NDK_REV}" && "${NDK_REV}" -lt 27 ]]; then
    echo "warning: NDK major version ${NDK_REV} detected; r27+ is recommended for 16 KiB page support." >&2
fi

case "$(uname -s)" in
    Linux*)  HOST_TAG="linux-x86_64"; EXE_SUFFIX="" ;;
    Darwin*) HOST_TAG="darwin-x86_64"; EXE_SUFFIX="" ;;  # universal binaries on Apple Silicon
    MINGW*|MSYS*|CYGWIN*) HOST_TAG="windows-x86_64"; EXE_SUFFIX=".cmd" ;;
    *) die "unsupported host OS $(uname -s)" ;;
esac
TOOLCHAIN="${NDK}/toolchains/llvm/prebuilt/${HOST_TAG}/bin"
[[ -d "${TOOLCHAIN}" ]] || die "NDK toolchain not found at ${TOOLCHAIN}"

AR_BIN="${TOOLCHAIN}/llvm-ar"; [[ "${EXE_SUFFIX}" == ".cmd" ]] && AR_BIN="${AR_BIN}.exe"
export READELF="${TOOLCHAIN}/llvm-readelf"; [[ "${EXE_SUFFIX}" == ".cmd" ]] && READELF="${READELF}.exe"

PAGE_FLAG="-C link-arg=-Wl,-z,max-page-size=16384"

echo "=== Synapse Core: Android build ==="
echo "NDK:      ${NDK} (r${NDK_REV:-?})"
echo "API:      ${API_LEVEL}"
echo "ABIs:     ${ABIS}"
echo "Profile:  ${PROFILE}"
echo "Output:   ${OUT_DIR}"
echo

cd "${ROOT_DIR}"
SUMMARY=()

IFS=',' read -r -a ABI_LIST <<<"${ABIS}"
for ABI in "${ABI_LIST[@]}"; do
    case "${ABI}" in
        arm64-v8a)   TARGET="aarch64-linux-android";   CLANG="aarch64-linux-android${API_LEVEL}-clang" ;;
        armeabi-v7a) TARGET="armv7-linux-androideabi"; CLANG="armv7a-linux-androideabi${API_LEVEL}-clang" ;;
        x86_64)      TARGET="x86_64-linux-android";    CLANG="x86_64-linux-android${API_LEVEL}-clang" ;;
        x86)         TARGET="i686-linux-android";      CLANG="i686-linux-android${API_LEVEL}-clang" ;;
        *) die "unknown ABI '${ABI}' (expected arm64-v8a, armeabi-v7a, x86_64, x86)" ;;
    esac
    CC_PATH="${TOOLCHAIN}/${CLANG}${EXE_SUFFIX}"
    [[ -f "${CC_PATH}" ]] || die "compiler ${CC_PATH} missing (API level ${API_LEVEL} unsupported by this NDK?)"

    echo "--> ${ABI} (${TARGET})"
    rustup target add "${TARGET}" >/dev/null 2>&1 || true

    TARGET_ENV="$(tr '[:lower:]-' '[:upper:]_' <<<"${TARGET}")"
    TARGET_ENV_LC="${TARGET//-/_}"

    (
        export "CARGO_TARGET_${TARGET_ENV}_LINKER=${CC_PATH}"
        export "CC_${TARGET_ENV_LC}=${CC_PATH}"
        export "AR_${TARGET_ENV_LC}=${AR_BIN}"
        export "CARGO_TARGET_${TARGET_ENV}_AR=${AR_BIN}"
        # 16 KiB page alignment, independent of .cargo/config.toml being present.
        # (RUSTFLAGS, if set, overrides per-target flags, so append to it instead.)
        if [[ -n "${RUSTFLAGS:-}" ]]; then
            export RUSTFLAGS="${RUSTFLAGS} ${PAGE_FLAG}"
        else
            export "CARGO_TARGET_${TARGET_ENV}_RUSTFLAGS=${PAGE_FLAG}"
        fi
        cargo build --profile "${PROFILE}" --target "${TARGET}" --bin synapse-core --locked
    )

    PROFILE_DIR="${PROFILE}"; [[ "${PROFILE}" == "dev" ]] && PROFILE_DIR="debug"
    BUILD_DIR="${ROOT_DIR}/target/${TARGET}/${PROFILE_DIR}"
    DEST="${OUT_DIR}/${ABI}"
    mkdir -p "${DEST}"
    cp "${BUILD_DIR}/synapse-core" "${DEST}/libsynapse.so"
    chmod 755 "${DEST}/libsynapse.so"

    "${SCRIPT_DIR}/verify-android-elf.sh" "${ABI}" "${DEST}/libsynapse.so"

    SUMMARY+=("$(printf '%-12s libsynapse.so %8s KiB' "${ABI}" "$(( $(wc -c <"${DEST}/libsynapse.so") / 1024 ))")")
    echo
done

echo "=== Done ==="
printf '%s\n' "${SUMMARY[@]}"
echo
echo "Copy ${OUT_DIR}/* into your app's src/main/jniLibs/ and see docs/android.md"
echo "(useLegacyPackaging = true is REQUIRED so Android extracts the executable)."
