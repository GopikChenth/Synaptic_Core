#!/usr/bin/env bash
# ==============================================================================
# smoke-test-android.sh <libsynapse.so> [expected-version]
#
# Runs the engine binary on a connected Android device/emulator (via adb) exactly
# as an app would: exec'd as an unprivileged process with no $HOME, talking HTTP
# on loopback. Then runs scripts/smoke-test.sh against it through `adb forward`.
#
# Used by the release pipeline inside reactivecircus/android-emulator-runner.
# ==============================================================================
set -euo pipefail

BIN="${1:?usage: smoke-test-android.sh <libsynapse.so> [expected-version]}"
EXPECT_VERSION="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DEV_DIR=/data/local/tmp/synapse-smoke
PORT="${SYNAPSE_SMOKE_PORT:-18090}"
TOKEN="android-smoke-$RANDOM$RANDOM"

adb_sh() { adb shell "$@" | tr -d '\r'; }

on_exit() {
    local rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "----- device console.log -----"
        adb_sh "cat ${DEV_DIR}/console.log 2>/dev/null | tail -n 80" || true
        echo "----- device engine logs -----"
        adb_sh "cat ${DEV_DIR}/home/logs/*.log 2>/dev/null | tail -n 80" || true
        echo "----- logcat (tail) -----"
        adb logcat -d -t 200 2>/dev/null | grep -iE 'synapse|linker|avc:|crash' | tail -n 60 || true
    fi
    adb forward --remove "tcp:${PORT}" >/dev/null 2>&1 || true
    adb_sh "pkill -f ${DEV_DIR}/synapse 2>/dev/null; rm -rf ${DEV_DIR}" >/dev/null 2>&1 || true
    exit $rc
}
trap on_exit EXIT

adb wait-for-device
for _ in $(seq 1 120); do
    [[ "$(adb_sh getprop sys.boot_completed)" == "1" ]] && break
    sleep 1
done

echo "== Device"
echo "  model:     $(adb_sh getprop ro.product.model)"
echo "  android:   $(adb_sh getprop ro.build.version.release) (API $(adb_sh getprop ro.build.version.sdk))"
echo "  abi:       $(adb_sh getprop ro.product.cpu.abi)"
echo "  page size: $(adb_sh getconf PAGE_SIZE 2>/dev/null || echo '?')"

adb_sh "rm -rf ${DEV_DIR}; mkdir -p ${DEV_DIR}/home ${DEV_DIR}/sync"
adb push "${BIN}" "${DEV_DIR}/synapse" >/dev/null
adb_sh "chmod 755 ${DEV_DIR}/synapse"

echo "== Exec"
VERSION_OUT="$(adb_sh "${DEV_DIR}/synapse --version")"
echo "  ${VERSION_OUT}"
[[ "${VERSION_OUT}" == synapse-core* ]] || { echo "FAIL: binary did not execute"; exit 1; }
if [[ -n "${EXPECT_VERSION}" && "${VERSION_OUT}" != *"${EXPECT_VERSION#v}"* ]]; then
    echo "FAIL: expected version ${EXPECT_VERSION}"; exit 1
fi

# Android has no usable $HOME for apps: without --home the engine must refuse with code 3
# instead of crashing on a read-only path.
code="$(adb_sh "cd / && unset SYNAPSE_HOME; ${DEV_DIR}/synapse >/dev/null 2>&1; echo \$?" | tail -n 1)"
if [[ "${code}" == "3" ]]; then
    echo "  PASS  missing --home exits with code 3"
else
    echo "  FAIL  missing --home exited with '${code}', expected 3"; exit 1
fi

echo "== Launch"
# Every fd of the background process must be redirected, or `adb shell` never returns.
adb_sh "SYNAPSE_TOKEN=${TOKEN} nohup ${DEV_DIR}/synapse \
    --home ${DEV_DIR}/home --port ${PORT} --log-dir ${DEV_DIR}/home/logs --quiet \
    --device-name android-smoke </dev/null >${DEV_DIR}/console.log 2>&1 &"

RUNTIME=""
for _ in $(seq 1 150); do
    RUNTIME="$(adb_sh "cat ${DEV_DIR}/home/runtime.json 2>/dev/null" || true)"
    if jq -e .api_url >/dev/null 2>&1 <<<"${RUNTIME}"; then break; fi
    RUNTIME=""
    sleep 0.2
done
[[ -n "${RUNTIME}" ]] || { echo "FAIL: engine not ready within 30s"; exit 1; }
DEV_PID="$(jq -r .pid <<<"${RUNTIME}")"
echo "  ready: $(jq -r .api_url <<<"${RUNTIME}") (pid ${DEV_PID}, device name $(jq -r .device_name <<<"${RUNTIME}"))"

adb forward "tcp:${PORT}" "tcp:${PORT}" >/dev/null

"${SCRIPT_DIR}/smoke-test.sh" \
    --url "http://127.0.0.1:${PORT}" \
    --token "${TOKEN}" \
    --folder-path "${DEV_DIR}/sync" \
    ${EXPECT_VERSION:+--expect-version "${EXPECT_VERSION}"} \
    --shutdown

echo "== Process exit"
for _ in $(seq 1 75); do
    if [[ "$(adb_sh "[ -d /proc/${DEV_PID} ] && echo alive || echo gone")" == "gone" ]]; then
        echo "  PASS  engine process exited after shutdown"
        if [[ -z "$(adb_sh "ls ${DEV_DIR}/home/runtime.json 2>/dev/null")" ]]; then
            echo "  PASS  runtime.json removed"
            exit 0
        fi
        echo "  FAIL  runtime.json left behind"; exit 1
    fi
    sleep 0.2
done
echo "  FAIL  engine still running 15s after shutdown"
exit 1
