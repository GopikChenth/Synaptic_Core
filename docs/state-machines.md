# State machines in Synapse Core

Every entity whose behaviour depends on "what it's doing right now" is a state machine,
whether or not the code says so. This document lists all of them. It covers what each
looks like today, which ones were implicit and how they were fixed, and what's left.

Machine-readable form: `GET /api/v1/system/statemachines` returns every formal machine
with its states, descriptions, allowed transitions and available actions.

## Design rules

1. **Derive, don't set.** If a state can be computed from facts (work in flight,
   persisted config, last heartbeat), compute it. Paired `set(Busy)` … `set(Idle)` calls
   break on the first early `return`, `?` or panic between them.
2. **RAII for "in progress".** Work holds a guard. Dropping the guard ends the state on
   every exit path, and the outcome (success/failure + reason) is recorded explicitly.
3. **One source of truth per fact.** Persisted config (e.g. `is_paused`) stays in SQLite.
   Runtime state stays in memory and is derived on top of it, never copied.
4. **Every transition is observable.** State changes are broadcast on the event bus, so
   UIs and agents react to them instead of polling.
5. **Errors carry a reason.** `error` without "why" is useless to a user and an agent.
6. **Wire compatibility.** Existing values (`"idle"`, `"IDLE"`, `"PENDING"`) never change.
   New information is added as new fields or events.

## Inventory

| # | Machine | Where | Status |
|---|---|---|---|
| 1 | Conflict lifecycle (`PENDING → RESOLVED / IGNORED`) | `state::ConflictStatus`, `conflict/` | Formal. Transitions validated. **Now also typed in Rust and enforced by the database (below)** |
| 2 | **Folder activity** (`idle / scanning / syncing / paused / error`) | `state::runtime::FolderStateTracker` | **Was implicit and buggy. Formalized (below)** |
| 3 | **Peer presence** (`online / offline`) | `state::runtime::PeerPresence` | **Was implicit and wrong. Formalized (below)** |
| 4 | **Device pairing** (`pending → paired ⇄ paused`, `pending → rejected`) | `state::DevicePairingState`, `StorageEngine::device_pairing_state` | **Rejections were forgotten and actions unchecked. Formalized (below)** |
| 5 | Relay session (`disconnected → connecting → joined → invited → active → closed`) | `p2p::relay::RelaySessionState` | Formal, with a transition guard |
| 6 | Swarm chunk download (`pending → in_flight → completed / failed`) | `state::ChunkDownloadState`, `p2p::swarm` | Formal |
| 7 | Conflict pipeline tier (fast-forward → 3-way merge → quarantine) | `state::ConflictPipelineTier` | Formal (classification, not lifecycle) |
| 8 | **Engine lifecycle** (`starting → ready → stopping / restarting`) | `state::runtime::EngineLifecycle`, `main.rs` generations | **Restart was a no-op returning 200. Formalized (below)** |
| 9 | **Folder offers** (`pending → accepted / rejected`) | `state::FolderOfferState`, `StorageEngine::folder_offer_state` | **Accept could create folders from nothing and leave them in `error`. Formalized (below)** |
| 10 | Folder config enums (`sync_mode`, `conflict_policy`, `pull_order`, `versioning_type`) | `state::validate_folder_config` | Not state machines, but unknown values used to be stored and silently replaced by defaults. Now validated (`400` + accepted values) |

---

## 1. Conflict status storage (typed)

**Before.** `QuarantineConflict.status` was a `String` and the column accepted any text.
`list_pending_conflicts` filters on `status = 'PENDING'`, so a row written as `pending`
(or anything else) was invisible in the list while `GET /conflicts/:id` treated it as
pending.

**Now.**
- `QuarantineConflict.status` is a `ConflictStatus`. It serializes to the same strings
  and still compares with `== "PENDING"`.
- At startup, existing rows are normalised (`UPPER(TRIM(status))`). `BEFORE INSERT/UPDATE`
  triggers make the database reject any status outside `PENDING | RESOLVED | IGNORED`.
  SQLite can't add a `CHECK` to an existing table, so triggers give the same guarantee
  without rebuilding it.
- Anything still unrecognised is logged and reported as `PENDING`, so it stays visible.

## 2. Folder activity (formalized)

**Before.** A bare `HashMap<folder, state>` written with `set_folder_state(Scanning)` …
`set_folder_state(Idle)`:

- `index_folder` had about 10 `?` exits between the two calls, and
  `reconcile_remote_revision` had about 12. Any I/O error, bad remote revision or hash
  mismatch left the folder showing **`scanning` or `syncing` forever** (UX: a spinner
  that never stops; AX: an agent waiting forever for `idle`).
- Two concurrent scans (registration scan + watcher + manual rescan): the first to
  finish flipped the folder to `idle` while the second was still running.
- `error` had no reason, and nothing cleared it except another `set`.
- `SYNC_STARTED` / `SYNC_COMPLETED` were documented but **never emitted**.
- The declared transition table was never consulted.

**Now.** State is derived from in-flight work:

```
paused (persisted) > scanning (scans > 0) > syncing (syncs > 0) > error (last scan failed) > idle
```

```rust
let activity = tracker.begin(folder_id, FolderActivityKind::Scan); // -> scanning
let result = (|| { /* any ?, return or panic */ })();
activity.finish_with(result)          // success clears error, failure records the reason
// and if the guard is dropped without finishing: "interrupted before completion"
```

- Overlapping work is counted, so the folder stays `scanning` until the last scan ends.
- A failed scan → `error` with its reason. The next successful scan clears it.
- A failed remote apply doesn't flag the whole folder. It's logged and the folder
  returns to its previous state.
- Every transition emits `FOLDER_STATE_CHANGED {folder_id, from, to, error}`. Entering or
  leaving `syncing` emits `SYNC_STARTED` / `SYNC_COMPLETED {files_synced}`.
- `GET /api/v1/folders/:id/status` adds `"error": "<reason>"` only when in `error`.
- `GET /api/v1/system/status` adds `folder_states` counts. `sync_state` is unchanged.
- An exhaustive test walks every sequence of 5 operations (begin/succeed/fail scan,
  begin/succeed sync, pause, resume) and checks each emitted transition against the
  declared table.

`SyncEngine::set_folder_state` still works as an explicit override (tooling/tests).

## 3. Peer presence (formalized)

**Before.** A peer entered the in-memory peer map on first discovery packet and never
left. `peer_count` only grew, `PEER_DISCONNECTED` was **never emitted**, and
`/api/v1/connections` reported `is_connected = !paused`, so every paired device showed
as connected, including ones that were switched off.

**Now.** `online ⇄ offline` with a 30 s heartbeat TTL (discovery announces every 5 s):

- Any discovery announcement or protocol message → `online`. On a transition,
  `PEER_CONNECTED` fires (also when a peer comes *back*).
- A monitor sweeps every 5 s: silent > 30 s → `offline` + `PEER_DISCONNECTED` (paired
  devices only).
- `peer_count` = peers currently online.
- `/api/v1/connections` → `is_connected` = paired ∧ ¬paused ∧ online.
- `GET /api/v1/devices[/:id]` adds `state` (`paired`/`paused`), `online`,
  `last_seen_secs`.
- **Routing is unchanged.** Offline peers stay in the routing table and still receive
  file notices, so peers reachable outside LAN discovery are not cut off.

## 4. Device pairing (formalized)

**Before.** The state was implied by *which table* a device was in, plus `is_paused`.
Rejecting a request just deleted the pending row, so the device's next discovery
broadcast (every 5 s) staged it again and fired `DEVICE_PENDING`. **A rejected device
kept coming back.** Pause/resume/accept ran without checks: pausing an unknown device
returned `200`, and accepting a non-pending one returned `500`.

**Now.**
- `rejected` is persisted (`rejected_devices` table, created automatically, no migration
  step). Rejected devices are not re-staged by discovery or introducers. Forget the
  rejection with `DELETE /api/v1/cluster/rejected/devices/:id`, or add the device
  explicitly.
- `StorageEngine::device_pairing_state()` derives the single current state.
- Every action is checked against `DevicePairingState::can_transition_to`: `404` unknown
  device, `200` no-op when already in the target state, `409` + `StateTransitionError`
  (with `allowed_transitions` / `available_actions`) otherwise.

## 8. Engine lifecycle (formalized)

**Before.** `POST /system/restart` logged a line and returned `200`. Nothing restarted.

**Now.** `starting → ready → stopping`, plus `ready → restarting`:
- Restart runs a fresh **engine generation in the same process**. Each generation has its
  own Tokio runtime, and dropping it cancels every task it spawned. Nothing leaks, no
  socket stays bound, and the new generation rebinds the **same API address** (also when
  started with `--port 0`). Same PID, so launchers and `--exit-with-parent` are
  unaffected.
- `lifecycle` is reported in `GET /api/v1/system/status`. Restart when not `ready` →
  `409`. A bare router without an engine loop → `503` instead of a fake success.
- The smoke test restarts every release binary (desktop and Android emulator) and checks
  it comes back on the same address.

## 9. Folder offers (formalized)

**Before.** The offer state was implied by row existence:
- `accept` never checked that an offer existed. Accepting any `folder_id` created a local
  folder and shared it with whatever `device_id` was sent.
- The accepted folder got no mount-safety marker, so its first scan refused and it sat in
  `error` until someone created the marker by hand.
- `reject` just deleted the row, so the same offer could come straight back.

**Now.**
- `pending → accepted | rejected`, derived by `StorageEngine::folder_offer_state()` from
  `pending_folders`, `rejected_folders` (new, created automatically) and
  `folder_devices`.
- Accept/reject use the same contract as device pairing: `404` for no offer, `200` no-op
  on repeat, `409` + `StateTransitionError` otherwise. An empty `local_path` returns `400`.
- Accept does the same setup as registering a folder: directory + marker, then tracking
  and the initial scan.
- Rejections are remembered (`GET /api/v1/cluster/rejected/folders`, forget with
  `DELETE …/:id?device_id=`). Offers for folders already shared with that device are
  ignored.

## Observable behaviour changes

All changes are additive (new fields, events and endpoints) except these, which were
wrong before:

| Where | Before | After |
|---|---|---|
| `/api/v1/connections` `is_connected` | `true` for every unpaused paired device | `true` only if heard from in the last 30 s |
| `peer_count` | every peer ever seen since start | peers currently online |
| folder `state` after a failed scan/sync | stuck at `scanning`/`syncing` | `error` (scan, with reason) or back to `idle` (sync) |
| rejected pairing request | reappeared as pending within seconds | stays rejected until forgotten |
| pause/resume/accept/reject on an unknown device | `200` or `500` | `404` |
| invalid pairing action (e.g. pause a pending device) | silently "succeeded" | `409` + allowed transitions |
| `POST /system/restart` | `200`, nothing happened | restarts (`200`), or `409` / `503` when it can't |
| unknown `sync_mode` / `conflict_policy` / `pull_order` / `versioning_type` | stored, then silently treated as the default | `400` with accepted values. Every spelling that worked before still works |
| accept a folder offer that doesn't exist | `200`, folder created anyway | `404` |
| accepted shared folder | first scan failed (no marker) → `error` | marker created, scanned, `idle` |
| rejected folder offer | could be offered again immediately | stays rejected until forgotten |
| conflict row with a non-canonical status (e.g. `pending`) | missing from `GET /conflicts` | normalised at startup and listed |

## Remaining

None of the implicit state machines found in the inventory remain. When adding new
lifecycle state, follow the design rules at the top: derive it, guard work with RAII,
keep one source of truth, emit events, give errors a reason, and register the machine in
`get_all_state_machines()` so `/api/v1/system/statemachines` describes it.
