#!/usr/bin/env bash
# ==============================================================================
# verify-android-elf.sh <abi> <libsynapse.so>
#
# Fails loudly on the packaging mistakes that make the Android binary "not work":
#
#   * wrong architecture for the ABI folder           -> "Exec format error"
#   * a desktop (glibc) build copied into jniLibs     -> "No such file or directory"
#                                                        (interpreter /lib/ld-linux* is
#                                                        absent on Android)
#   * LOAD segments aligned to 4 KiB                   -> fails on 16 KiB-page devices,
#                                                        rejected by Google Play
#   * not position-independent                         -> refused by bionic
# ==============================================================================
set -euo pipefail

ABI="${1:?usage: verify-android-elf.sh <abi> <libsynapse.so>}"
EXE="${2:?missing path to libsynapse.so}"

READELF="${READELF:-}"
if [[ -z "${READELF}" ]]; then
    for c in llvm-readelf readelf; do
        if command -v "$c" >/dev/null 2>&1; then READELF="$c"; break; fi
    done
fi
[[ -n "${READELF}" ]] || { echo "error: llvm-readelf/readelf not found (set READELF=...)" >&2; exit 2; }

case "${ABI}" in
    arm64-v8a)   MACHINE="AArch64"; CLASS="ELF64"; LINKER="/system/bin/linker64" ;;
    x86_64)      MACHINE="X86-64|Advanced Micro Devices X86-64"; CLASS="ELF64"; LINKER="/system/bin/linker64" ;;
    armeabi-v7a) MACHINE="ARM"; CLASS="ELF32"; LINKER="/system/bin/linker" ;;
    x86)         MACHINE="80386|Intel 80386"; CLASS="ELF32"; LINKER="/system/bin/linker" ;;
    *) echo "error: unknown ABI '${ABI}'" >&2; exit 2 ;;
esac
MIN_ALIGN=16384

FAILED=0
pass() { printf '  \033[32mok\033[0m    %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAILED=1; }

check_common() {
    local f="$1" header
    [[ -f "$f" ]] || { fail "$f does not exist"; return; }
    header="$("${READELF}" -h "$f" 2>/dev/null)" || { fail "$f is not an ELF file"; return; }

    grep -Eq "Class:[[:space:]]+${CLASS}" <<<"$header" \
        && pass "class ${CLASS}" || fail "expected ${CLASS} for ${ABI}"
    grep -Eq "Machine:[[:space:]]+(${MACHINE})" <<<"$header" \
        && pass "machine matches ${ABI}" \
        || fail "machine is '$(grep -E 'Machine:' <<<"$header" | sed 's/.*Machine:[[:space:]]*//')', expected ${ABI}"
    grep -Eq "Type:[[:space:]]+DYN" <<<"$header" \
        && pass "position independent (ET_DYN)" || fail "not position independent"

    local aligns bad=0 a
    aligns="$("${READELF}" -lW "$f" | awk '$1=="LOAD"{print $NF}')"
    for a in $aligns; do
        if (( a < MIN_ALIGN )); then bad=1; fi
    done
    if [[ -z "$aligns" ]]; then
        fail "no LOAD segments found"
    elif (( bad )); then
        fail "LOAD segment alignment $(tr '\n' ' ' <<<"$aligns")< ${MIN_ALIGN} (16 KiB page devices / Google Play)"
    else
        pass "16 KiB page aligned"
    fi
}

echo "Verifying ${ABI}: $(basename "${EXE}")"
check_common "${EXE}"
INTERP="$("${READELF}" -lW "${EXE}" 2>/dev/null | sed -n 's/.*Requesting program interpreter: \(.*\)\]/\1/p')"
if [[ "${INTERP}" == "${LINKER}" ]]; then
    pass "interpreter ${LINKER} (bionic)"
else
    fail "interpreter is '${INTERP:-none}', expected ${LINKER} - this is not an Android build"
fi

exit "${FAILED}"
