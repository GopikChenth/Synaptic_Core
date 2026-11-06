#!/usr/bin/env bash
# ==============================================================================
# Synapse Core Live Interactive Demo & Testing Script
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN="${ROOT_DIR}/bin/synapse-core"

if [ ! -f "${BIN}" ]; then
    echo "Binary not found at ${BIN}. Building first..."
    "${SCRIPT_DIR}/build-desktop.sh"
fi

DEMO_DIR="/tmp/synapse_demo_$$"
mkdir -p "${DEMO_DIR}/home"
mkdir -p "${DEMO_DIR}/sync_folder"

PORT=9095
P2P_PORT=9195
DISCOVERY_PORT=21095

echo ""
echo "======================================================================"
echo "         SYNAPSE CORE LIVE DEMONSTRATION & TEST SUITE                 "
echo "======================================================================"
echo "Demo Directory: ${DEMO_DIR}"
echo "API Port:       ${PORT}"
echo ""

cleanup() {
    echo ""
    echo "[Cleanup] Stopping daemon and removing temporary files..."
    if [ -n "${DAEMON_PID:-}" ]; then
        kill -9 "${DAEMON_PID}" 2>/dev/null || true
    fi
    rm -rf "${DEMO_DIR}"
    echo "[Cleanup] Done."
}
trap cleanup EXIT

echo ">>> [1/5] Launching Synapse Core Daemon..."
"${BIN}" -H "${DEMO_DIR}/home" -p "${PORT}" --p2p-port "${P2P_PORT}" --discovery-port "${DISCOVERY_PORT}" run > "${DEMO_DIR}/daemon.log" 2>&1 &
DAEMON_PID=$!

# Wait for daemon to be ready
echo -n "Waiting for daemon to bind to http://127.0.0.1:${PORT}..."
for i in {1..20}; do
    if curl -s "http://127.0.0.1:${PORT}/api/v1/system/status" > /dev/null 2>&1; then
        echo " Ready!"
        break
    fi
    sleep 0.5
done

echo ""
echo ">>> [2/5] Querying System Status Endpoint:"
STATUS_JSON=$(curl -s "http://127.0.0.1:${PORT}/api/v1/system/status")
echo "${STATUS_JSON}" | jq .

echo ""
echo ">>> [3/5] Registering Monitored Sync Folder:"
REGISTER_RESP=$(curl -s -X POST "http://127.0.0.1:${PORT}/api/v1/folders" \
    -H "Content-Type: application/json" \
    -d "{\"folder_id\":\"notes_vault\",\"local_path\":\"${DEMO_DIR}/sync_folder\",\"conflict_policy\":\"THREE_WAY_AUTO\"}")
echo "${REGISTER_RESP}" | jq .

echo ""
echo ">>> [4/5] Creating a local file in sync folder..."
cat << 'EOF' > "${DEMO_DIR}/sync_folder/notes.md"
# Project Overview
Section A: Local Design
Section B: Shared Notes
Section C: Conclusion
EOF
echo "Created: ${DEMO_DIR}/sync_folder/notes.md"

# Wait a moment for watcher to index
sleep 1

echo "Verifying folder status from API:"
curl -s "http://127.0.0.1:${PORT}/api/v1/folders" | jq .

echo ""
echo ">>> [5/5] Running Synapse Core Internal Verification Engine:"
echo "Executing automated test suite (FastCDC, BLAKE3 CAS, Merkle DAG LCA, 3-Way Merge, Virtual Quarantine):"
echo ""
cd "${ROOT_DIR}"
cargo test -- --nocapture

echo ""
echo "======================================================================"
echo "          ALL TESTS PASSED SUCCESSFULLY!                             "
echo "======================================================================"
