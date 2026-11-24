#!/usr/bin/env bash
# ==============================================================================
# smoke-test.sh - exercise the engine's HTTP API against a real binary.
#
# This is the contract the client app relies on, so every release artifact runs it
# on its own platform before publishing.
#
#   Launch a local binary, test it, shut it down through the API:
#     scripts/smoke-test.sh --bin target/release/synapse-core [--expect-version 1.2.3]
#
#   Test an already running engine (e.g. on an Android emulator via adb forward):
#     scripts/smoke-test.sh --url http://127.0.0.1:18090 --token T \
#                           --folder-path /data/local/tmp/smoke/sync [--shutdown]
#
# Requires: bash, curl, jq. Works on Linux, macOS and Windows (Git Bash).
# ==============================================================================
set -euo pipefail

BIN=""
URL=""
TOKEN=""
EXPECT_VERSION=""
FOLDER_PATH=""
DO_SHUTDOWN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bin) BIN="$2"; shift 2 ;;
        --url) URL="${2%/}"; shift 2 ;;
        --token) TOKEN="$2"; shift 2 ;;
        --expect-version) EXPECT_VERSION="${2#v}"; shift 2 ;;
        --folder-path) FOLDER_PATH="$2"; shift 2 ;;
        --shutdown) DO_SHUTDOWN=1; shift ;;
        -h|--help) sed -n '3,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "error: unknown option '$1'" >&2; exit 2 ;;
    esac
done
[[ -n "${BIN}" || -n "${URL}" ]] || { echo "error: pass --bin or --url" >&2; exit 2; }
for tool in curl jq; do
    command -v "$tool" >/dev/null || { echo "error: '$tool' is required" >&2; exit 2; }
done

PASS=0
FAIL=0
ok()   { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }

# Windows (Git Bash): JSON bodies need native paths; argv paths are auto-converted.
native_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }

WORK=""
PID=""
cleanup() {
    if [[ -n "${PID}" ]] && kill -0 "${PID}" 2>/dev/null; then kill "${PID}" 2>/dev/null || true; fi
    if [[ -n "${WORK}" && ${FAIL} -eq 0 ]]; then rm -rf "${WORK}"; fi
}
trap cleanup EXIT

dump_logs() {
    [[ -n "${WORK}" ]] || return 0
    echo "----- engine output -----"
    cat "${WORK}/console.log" 2>/dev/null | tail -n 60 || true
    for f in "${WORK}"/home/logs/*.log; do
        [[ -f "$f" ]] && { echo "----- $f -----"; tail -n 60 "$f"; }
    done
    return 0
}

# ---- Launch (local mode) -----------------------------------------------------
if [[ -n "${BIN}" ]]; then
    [[ -x "${BIN}" || -f "${BIN}" ]] || { echo "error: binary not found: ${BIN}" >&2; exit 2; }
    WORK="$(mktemp -d 2>/dev/null || mktemp -d -t synapse-smoke)"
    mkdir -p "${WORK}/home" "${WORK}/sync"
    [[ -n "${TOKEN}" ]] || TOKEN="smoke-$RANDOM$RANDOM$RANDOM"
    [[ -n "${FOLDER_PATH}" ]] || FOLDER_PATH="$(native_path "${WORK}/sync")"
    P2P_PORT=$((20000 + RANDOM % 20000))
    DISC_PORT=$((P2P_PORT + 1))

    echo "== Version"
    VERSION_OUT="$("${BIN}" --version)"
    echo "  ${VERSION_OUT}"
    if [[ -n "${EXPECT_VERSION}" ]]; then
        [[ "${VERSION_OUT}" == *"${EXPECT_VERSION}"* ]] && ok "--version reports ${EXPECT_VERSION}" \
            || bad "--version does not report ${EXPECT_VERSION}"
    fi

    echo "== Launch"
    SYNAPSE_TOKEN="${TOKEN}" "${BIN}" \
        --home "${WORK}/home" \
        --port 0 \
        --p2p-port "${P2P_PORT}" \
        --discovery-port "${DISC_PORT}" \
        --log-dir "${WORK}/home/logs" \
        --device-name smoke-test \
        >"${WORK}/console.log" 2>&1 </dev/null &
    PID=$!

    RUNTIME="${WORK}/home/runtime.json"
    for _ in $(seq 1 200); do
        [[ -s "${RUNTIME}" ]] && jq -e .api_url "${RUNTIME}" >/dev/null 2>&1 && break
        if ! kill -0 "${PID}" 2>/dev/null; then
            wait "${PID}" && code=0 || code=$?
            bad "engine exited during startup (code ${code})"; dump_logs; exit 1
        fi
        sleep 0.1
    done
    if ! jq -e .api_url "${RUNTIME}" >/dev/null 2>&1; then
        bad "runtime.json not published within 20s"; dump_logs; exit 1
    fi
    URL="$(jq -r .api_url "${RUNTIME}")"
    ok "ready at ${URL} (pid $(jq -r .pid "${RUNTIME}"))"
    DO_SHUTDOWN=1
fi

# ---- HTTP helpers ------------------------------------------------------------
BODY=""
STATUS=""
request() { # method path [json-body] [auth=1]
    local method="$1" path="$2" data="${3:-}" auth="${4:-1}"
    local args=(-sS -m 10 -o "${TMP_BODY}" -w '%{http_code}' -X "${method}")
    if [[ "${auth}" == 1 && -n "${TOKEN}" ]]; then args+=(-H "Authorization: Bearer ${TOKEN}"); fi
    if [[ -n "${data}" ]]; then args+=(-H 'Content-Type: application/json' --data "${data}"); fi
    STATUS="$(curl "${args[@]}" "${URL}${path}" || echo 000)"
    BODY="$(cat "${TMP_BODY}" 2>/dev/null || true)"
}
expect() { # description expected-status [jq-assertion]
    local desc="$1" want="$2" filter="${3:-}"
    if [[ "${STATUS}" != "${want}" ]]; then
        bad "${desc}: HTTP ${STATUS}, expected ${want} ${BODY:0:200}"; return
    fi
    if [[ -n "${filter}" ]] && ! jq -e "${filter}" >/dev/null 2>&1 <<<"${BODY}"; then
        bad "${desc}: response failed check '${filter}': ${BODY:0:200}"; return
    fi
    ok "${desc}"
}
TMP_BODY="$(mktemp)"

# ---- API contract ------------------------------------------------------------
echo "== API contract (${URL})"
FOLDER_ID="smoke-$RANDOM"

request GET /api/v1/system/ping "" 0
expect "GET /api/v1/system/ping (no auth)" 200 '.ping == "pong"'
request GET /rest/system/ping "" 0
expect "GET /rest/system/ping (compat)" 200

if [[ -n "${TOKEN}" ]]; then
    request GET /api/v1/system/status "" 0
    expect "GET /api/v1/system/status without token is rejected" 401
fi

request GET /api/v1/system/status
expect "GET /api/v1/system/status" 200 '(.device_id | length) > 0 and (.version | length) > 0'
if [[ -n "${EXPECT_VERSION}" ]]; then
    request GET /api/v1/system/status
    expect "status.version == ${EXPECT_VERSION}" 200 ".version == \"${EXPECT_VERSION}\""
    request GET /api/v1/system/version
    expect "GET /api/v1/system/version == v${EXPECT_VERSION}" 200 ".version == \"v${EXPECT_VERSION}\""
else
    request GET /api/v1/system/version
    expect "GET /api/v1/system/version" 200 '.version | startswith("v")'
fi

request GET /api/v1/folders
expect "GET /api/v1/folders" 200 'type == "array"'

if [[ -n "${FOLDER_PATH}" ]]; then
    payload="$(jq -cn --arg id "${FOLDER_ID}" --arg p "${FOLDER_PATH}" '{folder_id:$id, local_path:$p}')"
    request POST /api/v1/folders "${payload}"
    expect "POST /api/v1/folders (register)" 201 ".folder_id == \"${FOLDER_ID}\""
    request GET "/api/v1/folders/${FOLDER_ID}/status"
    expect "GET /api/v1/folders/:id/status" 200
    request GET /api/v1/folders
    expect "registered folder is listed" 200 "any(.[]; .folder_id == \"${FOLDER_ID}\")"
    request DELETE "/api/v1/folders/${FOLDER_ID}"
    expect "DELETE /api/v1/folders/:id" 204
fi

request GET /api/v1/devices
expect "GET /api/v1/devices" 200
request GET /api/v1/cluster/pending/devices
expect "GET /api/v1/cluster/pending/devices" 200
request GET /api/v1/conflicts
expect "GET /api/v1/conflicts" 200
request GET /api/v1/connections
expect "GET /api/v1/connections" 200

request GET /api/v1/system/status
expect "lifecycle is ready" 200 '.lifecycle == "ready"'

# ---- Restart (only when we're allowed to stop the engine) ---------------------
if [[ "${DO_SHUTDOWN}" == 1 ]]; then
    echo "== Restart"
    request POST /api/v1/system/restart
    expect "POST /api/v1/system/restart" 200 '.lifecycle == "restarting"'
    back=0
    for _ in $(seq 1 200); do
        sleep 0.1
        request GET /api/v1/system/status
        if [[ "${STATUS}" == 200 ]] && jq -e '.lifecycle == "ready"' >/dev/null 2>&1 <<<"${BODY}"; then
            back=1; break
        fi
    done
    [[ ${back} == 1 ]] && ok "engine back on the same address after restart" \
        || bad "engine not ready again within 20s of restart"
    if [[ -n "${PID}" ]] && ! kill -0 "${PID}" 2>/dev/null; then
        bad "process exited during restart (expected in-process restart)"
    fi
fi

# ---- Shutdown ----------------------------------------------------------------
if [[ "${DO_SHUTDOWN}" == 1 ]]; then
    echo "== Graceful shutdown"
    request POST /api/v1/system/shutdown
    expect "POST /api/v1/system/shutdown" 200
    if [[ -n "${PID}" ]]; then
        exited=0
        for _ in $(seq 1 150); do
            if ! kill -0 "${PID}" 2>/dev/null; then exited=1; break; fi
            sleep 0.1
        done
        if [[ ${exited} == 1 ]]; then
            wait "${PID}" && code=0 || code=$?
            PID=""
            [[ ${code} == 0 ]] && ok "engine exited cleanly (code 0)" || bad "engine exit code ${code}"
            [[ ! -e "${RUNTIME}" ]] && ok "runtime.json removed" || bad "runtime.json left behind"
        else
            bad "engine still running 15s after shutdown request"
        fi
    fi
fi

rm -f "${TMP_BODY}"
echo
echo "Result: ${PASS} passed, ${FAIL} failed"
if [[ ${FAIL} -gt 0 ]]; then dump_logs; exit 1; fi
