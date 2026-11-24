#!/usr/bin/env bash
# ==============================================================================
# package.sh - produce a release archive (+ .sha256) for one platform.
#
#   scripts/package.sh bin     <binary> <asset-name> [out-dir]
#       -> <out>/<asset-name>.tar.gz   (or .zip for Windows .exe binaries)
#          containing <asset-name>/{synapse-core[.exe], LICENSE, README.md, API.md}
#
#   scripts/package.sh android <jniLibs-dir> <asset-name> [out-dir]
#       -> <out>/<asset-name>.zip containing jniLibs/<abi>/libsynapse.so, LICENSE,
#          ANDROID.md
#
# out-dir defaults to dist/release. Works on Linux, macOS and Windows (Git Bash).
# ==============================================================================
set -euo pipefail

MODE="${1:?usage: package.sh bin|android <input> <asset-name> [out-dir]}"
INPUT="${2:?missing input}"
ASSET="${3:?missing asset name}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${4:-${ROOT_DIR}/dist/release}"

mkdir -p "${OUT_DIR}"
OUT_DIR="$(cd "${OUT_DIR}" && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT
mkdir -p "${STAGE}/${ASSET}"

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}

make_zip() { # <zip-path> <dir-in-stage>
    local zip_path="$1" dir="$2"
    rm -f "${zip_path}"
    if command -v zip >/dev/null 2>&1; then
        (cd "${STAGE}" && zip -qr -X "${zip_path}" "${dir}")
    elif command -v 7z >/dev/null 2>&1; then
        (cd "${STAGE}" && 7z a -tzip -bso0 -bsp0 "${zip_path}" "${dir}")
    else
        echo "error: neither zip nor 7z found" >&2; exit 1
    fi
}

cp "${ROOT_DIR}/LICENSE" "${STAGE}/${ASSET}/LICENSE"

case "${MODE}" in
    bin)
        [[ -f "${INPUT}" ]] || { echo "error: binary not found: ${INPUT}" >&2; exit 1; }
        NAME="synapse-core"
        [[ "${INPUT}" == *.exe ]] && NAME="synapse-core.exe"
        cp "${INPUT}" "${STAGE}/${ASSET}/${NAME}"
        chmod 755 "${STAGE}/${ASSET}/${NAME}"
        cp "${ROOT_DIR}/README.md" "${STAGE}/${ASSET}/README.md"
        cp "${ROOT_DIR}/docs/api-endpoints.md" "${STAGE}/${ASSET}/API.md"
        if [[ "${NAME}" == *.exe ]]; then
            ARCHIVE="${OUT_DIR}/${ASSET}.zip"
            make_zip "${ARCHIVE}" "${ASSET}"
        else
            ARCHIVE="${OUT_DIR}/${ASSET}.tar.gz"
            # Deterministic-ish tarball: fixed owner, sorted entries where supported.
            (cd "${STAGE}" && tar --version 2>/dev/null | grep -q GNU \
                && tar --sort=name --owner=0 --group=0 --numeric-owner -czf "${ARCHIVE}" "${ASSET}" \
                || tar -czf "${ARCHIVE}" "${ASSET}")
        fi
        ;;
    android)
        [[ -d "${INPUT}" ]] || { echo "error: jniLibs dir not found: ${INPUT}" >&2; exit 1; }
        found=0
        for so in "${INPUT}"/*/libsynapse.so; do
            [[ -f "${so}" ]] || continue
            abi="$(basename "$(dirname "${so}")")"
            mkdir -p "${STAGE}/${ASSET}/jniLibs/${abi}"
            cp "${so}" "${STAGE}/${ASSET}/jniLibs/${abi}/libsynapse.so"
            chmod 755 "${STAGE}/${ASSET}/jniLibs/${abi}/libsynapse.so"
            found=$((found + 1))
        done
        [[ ${found} -gt 0 ]] || { echo "error: no <abi>/libsynapse.so under ${INPUT}" >&2; exit 1; }
        cp "${ROOT_DIR}/docs/android.md" "${STAGE}/${ASSET}/ANDROID.md"
        cp "${ROOT_DIR}/docs/api-endpoints.md" "${STAGE}/${ASSET}/API.md"
        ARCHIVE="${OUT_DIR}/${ASSET}.zip"
        make_zip "${ARCHIVE}" "${ASSET}"
        ;;
    *) echo "error: mode must be 'bin' or 'android'" >&2; exit 2 ;;
esac

HASH="$(sha256 "${ARCHIVE}")"
printf '%s  %s\n' "${HASH}" "$(basename "${ARCHIVE}")" > "${ARCHIVE}.sha256"
echo "${ARCHIVE}"
echo "sha256: ${HASH}"
