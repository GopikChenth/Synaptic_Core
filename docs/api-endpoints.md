# Synapse Core Control Plane: REST & WebSocket API Specification

This document provides the definitive reference for the embedded Synapse Core HTTP REST and WebSocket control plane running on `127.0.0.1:9090` (configurable via `--addr` and `--port`).

The API provides two route sets:
1. **Native Synapse API (`/api/v1/*`)**: Modern RESTful interface exposing 3-way conflict inspection, virtual quarantine resolution, Merkle DAG causality, and FastCDC storage metrics.
2. **Syncthing Compatibility Layer (`/rest/*`)**: Drop-in REST route aliases supporting existing Synapse UI and Kotlin Multiplatform clients (`SyncthingApiClient.kt`) without code modification.

---

## Table of Contents
- [Base Configuration & Authentication](#base-configuration--authentication)
- [Part 1: System & Lifecycle Endpoints](#part-1-system--lifecycle-endpoints)
- [Part 2: Folder Management & Sync Policy](#part-2-folder-management--sync-policy)
- [Part 3: Cluster Devices & Mutual Pairing](#part-3-cluster-devices--mutual-pairing)
- [Part 4: 3-Way Conflicts & Virtual Quarantine](#part-4-3-way-conflicts--virtual-quarantine)
- [Part 5: Syncthing REST Compatibility Matrix](#part-5-syncthing-rest-compatibility-matrix)
- [Part 6: Real-Time WebSocket Event Bus](#part-6-real-time-websocket-event-bus)

---

## Base Configuration & Authentication

- **Default Base URL:** `http://127.0.0.1:9090`
- **Default WebSocket URL:** `ws://127.0.0.1:9090/api/v1/events` (or `ws://127.0.0.1:9090/rest/events`)
- **Content-Type:** `application/json`
- **CORS:** Enabled for all origins (`*`), headers, and HTTP methods (`GET`, `POST`, `DELETE`, `OPTIONS`).

### Optional Authentication
If the daemon is started with `--token <secret>` or `SYNAPSE_TOKEN=<secret>`:
```http
Authorization: Bearer <secret>
```
or via the Syncthing compatibility header:
```http
X-API-Key: <secret>
```

---

## Part 1: System & Lifecycle Endpoints

### 1.1 System Status
Returns engine health, device identity, peer count, monitored folders, and resident memory.

- **Endpoint:** `GET /api/v1/system/status` or `GET /rest/system/status`
- **Response:** `200 OK`
```json
{
  "device_id": "b3f8a910...ed25519_hex",
  "uptime_seconds": 3600,
  "peer_count": 2,
  "sync_state": "IDLE",
  "version": "1.0.0",
  "monitored_folders_count": 3,
  "pending_conflicts_count": 0,
  "memory_footprint_bytes": 18432000,
  "folder_states": { "idle": 2, "error": 1 },
  "lifecycle": "ready"
}
```
`sync_state` is one of `IDLE`, `SCANNING`, `SYNCING`, `PAUSED` (unchanged). `folder_states`
counts folders per runtime state, including `error` and `paused`, which `sync_state`
doesn't distinguish. `lifecycle` is the engine lifecycle state: `starting`, `ready`,
`stopping` or `restarting`. See [state-machines.md](state-machines.md).

### 1.2 System Version
Returns engine version, codename, architecture, and operating system.

- **Endpoint:** `GET /api/v1/system/version` or `GET /rest/system/version`
- **Response:** `200 OK`
```json
{
  "version": "v1.0.0",
  "codename": "Synapse-SynapticCore",
  "os": "linux",
  "arch": "x86_64"
}
```

### 1.3 Ping / Health Check
Simple health probe for monitoring daemons and process wrappers.

- **Endpoint:** `GET /api/v1/system/ping` or `GET /rest/system/ping`
- **Response:** `200 OK`
```json
{
  "ping": "pong"
}
```

### 1.4 System Shutdown
Gracefully stops the continuous synchronization daemon, closes SQLite WAL files, and terminates QUIC endpoints.

- **Endpoint:** `POST /api/v1/system/shutdown` or `POST /rest/system/shutdown`
- **Response:** `200 OK` `{"lifecycle": "stopping"}`. Repeating the call is harmless.

### 1.5 System Restart
Stops the engine and starts it again **in the same process**: same PID, same API
address (also when started with `--port 0`). Storage, folders, watchers and P2P are
reloaded. The WebSocket connection drops; poll `GET /api/v1/system/status` until
`lifecycle` is `ready` again (typically well under a second).

- **Endpoint:** `POST /api/v1/system/restart` or `POST /rest/system/restart`
- **Response:** `200 OK` `{"lifecycle": "restarting"}`
- **`409 Conflict`:** the engine isn't `ready` (e.g. already stopping). The body is a
  state-transition error, see [Errors](#state-transition-errors).
- **`503 Service Unavailable`:** the API router is embedded without an engine loop that
  could restart it.

### 1.6 Peer Connection Statistics
Returns real-time network throughput, transfer metrics, and latency per paired peer.
`is_connected` is `true` only for a paired, unpaused device that was heard from within
the presence TTL (30 s). See the `peer_presence` state machine.

- **Endpoint:** `GET /api/v1/connections` or `GET /rest/system/connections`
- **Response:** `200 OK`
```json
{
  "d51dd809-53132f4c-bd8a751f-5294f5a3": {
    "device_id": "d51dd809-53132f4c-bd8a751f-5294f5a3",
    "address": "192.168.1.42:9190",
    "is_connected": true,
    "in_bps": 1048576,
    "out_bps": 524288,
    "total_in_bytes": 104857600,
    "total_out_bytes": 52428800,
    "latency_ms": 12,
    "client_type": "synapse-core"
  }
}
```

---

## Part 2: Folder Management & Sync Policy

### 2.1 List Monitored Folders
- **Endpoint:** `GET /api/v1/folders` or `GET /rest/system/folders`
- **Response:** `200 OK`
```json
[
  {
    "folder_id": "notes_vault",
    "local_path": "/home/user/Notes",
    "conflict_policy": "THREE_WAY_AUTO",
    "is_paused": false,
    "sync_mode": "SendReceive",
    "pull_order": "Alphabetical",
    "versioning_type": "Staggered",
    "versioning_keep_days": 365,
    "marker_name": ".synapse-folder",
    "files_count": 254
  }
]
```

### 2.2 Register a Monitored Folder
Registers a directory for continuous synchronization, validates mount markers, and starts inotify / FSEvents watcher.

- **Endpoint:** `POST /api/v1/folders` or `POST /rest/system/folders`
- **Request Body:**
```json
{
  "folder_id": "notes_vault",
  "local_path": "/home/user/Notes",
  "conflict_policy": "THREE_WAY_AUTO",
  "sync_mode": "SendReceive",
  "pull_order": "SmallestFirst",
  "versioning_type": "Staggered",
  "versioning_keep_days": 30,
  "marker_name": ".synapse-folder"
}
```
- **Sync Modes:** `SendReceive`, `SendOnly`, `ReceiveOnly`
- **Conflict Policies:** `THREE_WAY_AUTO`, `LWW`, `MANUAL`
- **Pull Orders:** `Alphabetical`, `SmallestFirst`, `LargestFirst`, `NewestFirst`, `OldestFirst` (`random` accepted for Syncthing compatibility; pulls alphabetically)
- **Versioning Types:** `None`, `TrashCan`, `Simple`, `Staggered`
- Matching is case-insensitive and `_` is optional (`SEND_RECEIVE` = `SendReceive`).
  Values are stored exactly as sent.
- **Response:** `201 Created`
- **`400 Bad Request`** for an unknown value. Nothing is stored:
```json
{
  "error": "invalid_field",
  "field": "sync_mode",
  "value": "mirror",
  "allowed": ["SendReceive", "SendOnly", "ReceiveOnly"],
  "message": "Unsupported sync_mode 'mirror'. Accepted values: SendReceive, SendOnly, ReceiveOnly"
}
```

### 2.3 Remove Monitored Folder
- **Endpoint:** `DELETE /api/v1/folders/:id`
- **Response:** `204 No Content`

### 2.4 Pause / Resume Folder Sync
- **Pause:** `POST /api/v1/folders/:id/pause`
- **Resume:** `POST /api/v1/folders/:id/resume`
- **Response:** `200 OK`

### 2.5 Trigger Folder Rescan
Initiates an immediate disk index rescan and Merkle DAG reconciliation.
- **Native:** `POST /api/v1/folders/:id/rescan`
- **Syncthing Query Alias:** `POST /rest/db/scan?folder=notes_vault`
- **Response:** `200 OK`

### 2.6 Folder Status Metrics
- **Native:** `GET /api/v1/folders/:id/status`
- **Syncthing Query Alias:** `GET /rest/db/status?folder=notes_vault`
- **Response:** `200 OK`
```json
{
  "folder_id": "notes_vault",
  "state": "idle",
  "global_files": 254,
  "global_bytes": 10485760,
  "local_files": 254,
  "local_bytes": 10485760,
  "need_files": 0,
  "need_bytes": 0,
  "in_sync_bytes": 10485760,
  "completion_pct": 100.0,
  "sequence": 254
}
```
`state` is `idle`, `scanning`, `syncing`, `paused` or `error`. When it is `error`, the
response also includes `"error": "<reason>"` (e.g. a missing mount-safety marker). A
successful rescan clears it.

### 2.7 Device Folder Completion
Returns completion percentage and byte progress for a remote device.
- **Native:** `GET /api/v1/folders/:id/completion`
- **Syncthing Query Alias:** `GET /rest/db/completion?folder=notes_vault&device=DEVICE_ID`
- **Response:** `200 OK`
```json
{
  "device_id": "d51dd809-53132f4c-bd8a751f-5294f5a3",
  "folder_id": "notes_vault",
  "completion": 100.0,
  "global_bytes": 10485760,
  "need_bytes": 0
}
```

### 2.8 Ignore Patterns (.synapseignore / .stignore)
Retrieve or update ignore rules supporting `(?d)`, `(?i)`, `!`, and globs.

- **Get Ignores:**
  - `GET /api/v1/folders/:id/ignores`
  - `GET /rest/db/ignores?folder=notes_vault`
- **Set Ignores:**
  - `POST /api/v1/folders/:id/ignores`
  - `POST /rest/db/ignores?folder=notes_vault`
- **Payload:**
```json
{
  "ignore": [
    "(?d).git/",
    "(?i)*.log",
    "!important.log",
    "target/**",
    ".DS_Store"
  ]
}
```

---

## Part 3: Cluster Devices & Mutual Pairing

### 3.1 List Paired Devices
- **Endpoint:** `GET /api/v1/devices` or `GET /rest/system/devices`
- **Response:** `200 OK`
```json
[
  {
    "device_id": "K3F7P2X-M4L9Q1W-R6S8T0V-Y2A4C6E",
    "name": "Workstation-Desktop",
    "addresses": ["192.168.1.100:9190", "dynamic"],
    "is_paused": false,
    "is_trusted": true,
    "introducer": false,
    "cert_name": null,
    "created_at": 1730560000,
    "state": "paired",
    "online": true,
    "last_seen_secs": 4
  }
]
```
`state` is `paired` or `paused`. `online` follows the `peer_presence` state machine.
`last_seen_secs` is omitted if the device was never heard from. `GET /api/v1/devices/:id`
returns the same shape.

### 3.2 Add / Pair a Device Manually
- **Endpoint:** `POST /api/v1/devices` or `POST /rest/system/devices`
- **Request Body:**
```json
{
  "device_id": "K3F7P2X-M4L9Q1W-R6S8T0V-Y2A4C6E",
  "name": "Workstation-Desktop",
  "addresses": ["dynamic"]
}
```
- **Response:** `201 Created`
- Adding a device explicitly also clears an earlier rejection or pending request for it.

### 3.3 Remove / Pause / Resume Device
- **Remove:** `DELETE /api/v1/devices/:id`
- **Pause:** `POST /api/v1/devices/:id/pause` (paired → paused)
- **Resume:** `POST /api/v1/devices/:id/resume` (paused → paired)

### 3.4 Mutual Pairing Handshake (Incoming Device Requests)
When an unknown peer requests pairing:
- **List Pending Devices:** `GET /api/v1/cluster/pending/devices` or `GET /rest/cluster/pending/devices`
- **Accept Pairing:** `POST /api/v1/cluster/pending/devices/:id/accept` or `POST /rest/cluster/pending/devices/:id/accept`
- **Reject Pairing:** `POST /api/v1/cluster/pending/devices/:id/reject` or `POST /rest/cluster/pending/devices/:id/reject`
- **List Rejected:** `GET /api/v1/cluster/rejected/devices`
- **Forget a Rejection:** `DELETE /api/v1/cluster/rejected/devices/:id`. Returns `204`, or
  `404` if the device isn't rejected. The device may request pairing again afterwards.

A rejection is remembered: the device is **not** shown as pending again when it keeps
broadcasting discovery packets, and introducers can't re-introduce it.

All pairing actions follow the `device_pairing_lifecycle` state machine:

| Action | From | To | Repeat call |
|---|---|---|---|
| accept | `pending` | `paired` | `200`, no-op |
| reject | `pending` | `rejected` | `200`, no-op |
| pause | `paired` | `paused` | `200`, no-op |
| resume | `paused` | `paired` | `200`, no-op |

An unknown device returns `404`. Any other combination returns `409 Conflict` with a
[state-transition error](#state-transition-errors).

### State transition errors
Invalid lifecycle actions (devices, folder offers, engine restart) return `409 Conflict` with a body
that says what *is* possible, so a UI can disable the right buttons and an agent can
recover without guessing:
```json
{
  "entity": "device",
  "entity_id": "K3F7P2X-…",
  "current_state": "pending",
  "attempted_transition": "paused",
  "allowed_transitions": ["paired", "rejected"],
  "available_actions": ["ACCEPT", "REJECT"],
  "is_terminal": false
}
```

### 3.5 Incoming Remote Folder Invitations
When a paired peer offers to share a folder:
- **List Invitations:** `GET /api/v1/cluster/pending/folders` or `GET /rest/cluster/pending/folders`
- **Accept Invitation:** `POST /api/v1/cluster/pending/folders/:id/accept`
  - Body: `{ "device_id": "DEV_ID", "local_path": "/home/user/SharedFolder" }`
- **Reject Invitation:** `POST /api/v1/cluster/pending/folders/:id/reject`
  - Body: `{ "device_id": "DEV_ID" }`
- **List Rejected:** `GET /api/v1/cluster/rejected/folders`
- **Forget a Rejection:** `DELETE /api/v1/cluster/rejected/folders/:id?device_id=DEV_ID`.
  Returns `204`, or `404` if there is no such rejection.

Offers follow the `folder_offer_lifecycle` state machine, keyed by `(folder_id, device_id)`:

| Action | From | To | Repeat call |
|---|---|---|---|
| accept | `pending` | `accepted` | `200`, no-op |
| reject | `pending` | `rejected` | `200`, no-op |

- Accepting creates the local directory and its mount-safety marker, registers the folder,
  shares it with the offering device and starts the initial scan. An empty `local_path`
  returns `400`.
- A rejected offer is remembered and not staged again. An offer for a folder that is
  already shared with that device is ignored.
- No such offer: `404`. Any other combination: `409` with a
  [state-transition error](#state-transition-errors).

---

## Part 4: 3-Way Conflicts & Virtual Quarantine

### 4.1 List Quarantined Conflicts
Returns conflicts staged in `.synapse/quarantine/<conflict_id>.<ext>` awaiting user resolution.

- **Endpoint:** `GET /api/v1/conflicts`
- **Response:** `200 OK`
```json
[
  {
    "conflict_id": "cnf_90a1b2c3",
    "folder_id": "notes_vault",
    "relative_path": "projects/spec.md",
    "base_revision": "rev_root_001",
    "local_revision": "rev_local_002",
    "remote_revision": "rev_remote_003",
    "staged_payload_path": "/home/user/.synapse/quarantine/cnf_90a1b2c3.md",
    "status": "PENDING",
    "detected_at": 1730560120000000000
  }
]
```

### 4.2 Fetch Raw Versions for Inspection
- `GET /api/v1/conflicts/:id/base` $\rightarrow$ Lowest Common Ancestor (LCA) content
- `GET /api/v1/conflicts/:id/local` $\rightarrow$ Current local working copy
- `GET /api/v1/conflicts/:id/remote` $\rightarrow$ Staged quarantined payload

### 4.3 Inspect Structured 3-Way Diff Hunks
Returns pre-computed diff hunks for side-by-side UI merge viewers.

- **Endpoint:** `GET /api/v1/conflicts/:id/diff`
- **Response:** `200 OK`
```json
{
  "conflict_id": "cnf_90a1b2c3",
  "folder_id": "notes_vault",
  "relative_path": "projects/spec.md",
  "base": "Timeout: 30\n",
  "local": "Timeout: 60\n",
  "remote": "Timeout: 120\n",
  "hunks": [
    {
      "hunk_type": "CONFLICT",
      "base_lines": ["Timeout: 30"],
      "local_lines": ["Timeout: 60"],
      "remote_lines": ["Timeout: 120"]
    }
  ]
}
```

### 4.4 Submit Conflict Resolution Action
- **Endpoint:** `POST /api/v1/conflicts/:id/resolve`
- **Actions:**
  1. `ACCEPT_LOCAL`: Discards quarantine; keeps current local file.
  2. `ACCEPT_REMOTE`: Atomically overwrites local file with quarantined payload.
  3. `CUSTOM_MERGE`: Writes merged text from UI editor and commits a 2-parent merge revision:
     ```json
     { "action": "CUSTOM_MERGE", "merged_content": "Timeout: 90\n" }
     ```
  4. `KEEP_BOTH`: Saves quarantined copy alongside non-destructively (e.g., `spec.conflict-cnf_90a1b2c3.md`).

---

## Part 5: Syncthing REST Compatibility Matrix

Clients targeting Syncthing’s API (such as `SyncthingApiClient.kt`) can interact with Synapse Core using standard `/rest/` paths:

| Syncthing Endpoint | HTTP Method | Synapse Core Equivalent Action |
|---|---|---|
| `/rest/system/status` | `GET` | System health, uptime, and resident memory |
| `/rest/system/version` | `GET` | Core version string, OS, and architecture |
| `/rest/system/ping` | `GET` | Lightweight health ping (`{"ping":"pong"}`) |
| `/rest/system/shutdown` | `POST` | Graceful daemon shutdown |
| `/rest/system/restart` | `POST` | Daemon process restart |
| `/rest/system/connections` | `GET` | Live peer connection statistics & latency |
| `/rest/system/folders` | `GET`, `POST` | List or register synchronized folders |
| `/rest/db/scan?folder=ID` | `POST` | Trigger asynchronous folder rescan |
| `/rest/db/status?folder=ID`| `GET` | Folder file counts, byte totals, and sync state |
| `/rest/db/completion?folder=ID&device=ID` | `GET` | Percentage completion and byte sync progress |
| `/rest/db/ignores?folder=ID`| `GET`, `POST`| Read or update `.synapseignore` / `.stignore` rules |
| `/rest/system/devices` | `GET`, `POST` | List or register cluster peer devices |
| `/rest/cluster/pending/devices` | `GET` | List incoming mutual device pairing requests |
| `/rest/cluster/pending/devices/:id/accept` | `POST` | Approve incoming device pairing request |
| `/rest/cluster/pending/devices/:id/reject` | `POST` | Reject incoming device pairing request |
| `/rest/cluster/pending/folders` | `GET` | List incoming folder invitation requests |
| `/rest/cluster/pending/folders/:id/accept` | `POST` | Accept remote folder invitation with local path |
| `/rest/cluster/pending/folders/:id/reject` | `POST` | Decline remote folder invitation |
| `/rest/events` | `WS` | Real-time WebSocket event stream |

---

## Part 6: Real-Time WebSocket Event Bus

Connect over WebSocket at `ws://127.0.0.1:9090/api/v1/events` or `ws://127.0.0.1:9090/rest/events`.

### Event Types & Payloads

#### 1. `CONFLICT_DETECTED`
Emitted immediately when overlapping edits or binary conflicts are quarantined:
```json
{
  "event": "CONFLICT_DETECTED",
  "data": {
    "conflict_id": "cnf_90a1b2c3",
    "folder_id": "notes_vault",
    "relative_path": "projects/spec.md",
    "mime_type": "text/markdown",
    "local_version": { "author": "Desktop", "mtime": 1730560000, "size": 4210 },
    "remote_version": { "author": "Phone", "mtime": 1730560120, "size": 4350 },
    "auto_merge_attempted": true,
    "overlapping_lines_count": 1
  }
}
```

#### 2. `FOLDER_SCAN_PROGRESS`
Emitted during active directory indexing:
```json
{
  "event": "FOLDER_SCAN_PROGRESS",
  "data": {
    "folder_id": "notes_vault",
    "current_file": "src/main.rs",
    "files_scanned": 120,
    "total_files": 254
  }
}
```

#### 3. `DOWNLOAD_PROGRESS`
Emitted during active FastCDC chunk transfer:
```json
{
  "event": "DOWNLOAD_PROGRESS",
  "data": {
    "folder_id": "notes_vault",
    "relative_path": "video/demo.mp4",
    "bytes_downloaded": 52428800,
    "total_bytes": 104857600,
    "pct": 50.0
  }
}
```

#### 4. `ITEM_FINISHED`
Emitted when a file is synchronized and atomically placed on disk:
```json
{
  "event": "ITEM_FINISHED",
  "data": {
    "folder_id": "notes_vault",
    "relative_path": "projects/spec.md",
    "action": "UPDATE",
    "error": null
  }
}
```

#### 5. `FOLDER_STATE_CHANGED`
Emitted on every folder runtime-state transition. A UI can drive its folder badge
from this event alone. `error` is set when `to` is `"error"`.
```json
{
  "event": "FOLDER_STATE_CHANGED",
  "data": { "folder_id": "notes_vault", "from": "scanning", "to": "error",
            "error": "Safety marker '.synapse-folder' missing! Folder unmounted or corrupted; aborting sync" }
}
```

#### 6. Additional Lifecycle Events
- `DEVICE_PAIRED`: `{ "device_id": "...", "name": "..." }`
- `PEER_CONNECTED`: `{ "peer_id": "...", "addr": "192.168.1.42:9190" }`: a paired peer came online (first contact, or back after going offline)
- `PEER_DISCONNECTED`: `{ "peer_id": "..." }`: a paired peer went silent for longer than the presence TTL
- `SYNC_STARTED`: `{ "folder_id": "notes_vault" }`: folder entered `syncing`
- `SYNC_COMPLETED`: `{ "folder_id": "notes_vault", "files_synced": 5 }`: folder left `syncing`. `files_synced` counts remote revisions applied in that episode
- `CONFLICT_RESOLVED`: `{ "conflict_id": "...", "action": "CUSTOM_MERGE" }`

Send `"ping"` over the WebSocket connection to receive an instant `"pong"` heartbeat.
