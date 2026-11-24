# Running Synapse Core on Android

On Android the engine runs as a **separate process**, the same way Syncthing-Android
does it. The engine executable is packaged inside your APK as
`jniLibs/<abi>/libsynapse.so`. The installer extracts it into
`ApplicationInfo.nativeLibraryDir`, the only app-owned location Android 10+ allows
to execute. Your app spawns it and talks to it over `http://127.0.0.1:<port>`.

Get the binaries from a GitHub Release (`synapse-core-<version>-android-jniLibs.zip`)
or build them yourself (below).

---

## 1. Build

Prerequisites: Rust (stable ≥ 1.89) and the **Android NDK r27c or newer**.

```bash
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/27.2.12479018   # adjust
scripts/build-android.sh                       # arm64-v8a, armeabi-v7a, x86_64
scripts/build-android.sh --abis arm64-v8a      # just one ABI
scripts/build-android.sh --api 24 --out ../app/androidApp/src/main/jniLibs
```

On Windows, run the script from Git Bash. The script detects the `windows-x86_64` NDK toolchain.

Output:

```
dist/android/jniLibs/
├── arm64-v8a/   libsynapse.so
├── armeabi-v7a/ libsynapse.so
└── x86_64/      libsynapse.so
```

Every binary is checked before the script reports success:

```
Verifying arm64-v8a: libsynapse.so
  ok    class ELF64
  ok    machine matches arm64-v8a
  ok    position independent (ET_DYN)
  ok    16 KiB page aligned
  ok    interpreter /system/bin/linker64 (bionic)
```

The release pipeline (`.github/workflows/release.yml`) runs the same script, then boots
Android emulators and exercises the HTTP API against the real binary before anything is
published. See [release-pipeline.md](release-pipeline.md).

## 2. Integrate

Example code for the app side lives in [`docs/examples/android/`](examples/android/).
It is reference code for your app, not part of the engine.

1. **Gradle**: see [`build.gradle.kts`](examples/android/build.gradle.kts).
   The line that matters most is:
   ```kotlin
   android { packaging { jniLibs { useLegacyPackaging = true } } }
   ```
2. **Manifest**: merge [`AndroidManifest.xml`](examples/android/AndroidManifest.xml)
   (permissions, foreground service, cleartext config).
3. **Network security config**: copy
   [`network_security_config.xml`](examples/android/network_security_config.xml) to
   `src/main/res/xml/`.
4. **Kotlin**: copy [`SynapseDaemon.kt`](examples/android/SynapseDaemon.kt) (process
   launcher) and optionally [`SynapseSyncService.kt`](examples/android/SynapseSyncService.kt)
   (foreground service) into your app, then:

   ```kotlin
   // Simplest: foreground service manages everything
   SynapseSyncService.start(context)

   // Or drive it yourself (blocking - use Dispatchers.IO)
   val daemon = SynapseDaemon(context)
   val info = withContext(Dispatchers.IO) { daemon.start() }
   println("API at ${info.apiUrl}")          // e.g. http://127.0.0.1:41237
   // ...
   withContext(Dispatchers.IO) { daemon.stop() }
   ```

`SynapseDaemon` starts the binary like this:

```
libsynapse.so --home <filesDir>/synapse --port 0 --log-dir <home>/logs --quiet \
              --exit-on-stdin-close --exit-with-parent --device-name "<Manufacturer Model>"
```

and waits for `<home>/runtime.json`, which the daemon writes only once its API is
accepting connections:

```json
{ "pid": 12345, "version": "1.0.0", "device_id": "…", "device_name": "Google Pixel 8",
  "api_addr": "127.0.0.1:41237", "api_url": "http://127.0.0.1:41237",
  "p2p_port": 9190, "started_at": 1763750000000 }
```

## 3. Engine process contract

| Exit code | Meaning | Typical cause on Android |
|---|---|---|
| 0 | clean shutdown | stdin closed / SIGTERM / parent died |
| 2 | bad command line | launcher passed an unknown flag |
| 3 | configuration error | `--home` missing (Android has no `$HOME`) |
| 4 | home directory locked | previous daemon still shutting down |
| 5 | API port in use | fixed `--port` collides; use `--port 0` |
| 126/127 | cannot execute | wrong ABI, or a desktop build in `jniLibs` |

| Flag | Purpose |
|---|---|
| `--home DIR` / `SYNAPSE_HOME` | data directory (required on Android) |
| `--port 0` | ephemeral API port, published in `runtime.json` |
| `--log-dir DIR`, `--log-max-files N` | daily-rotated log files |
| `--log-level FILTER` / `RUST_LOG` | e.g. `info`, `synapse_core=debug,quinn=warn` |
| `--log-format json` | structured logs |
| `--quiet` | no stdout logging |
| `--exit-on-stdin-close` | exit when the parent closes our stdin (or dies) |
| `--exit-with-parent` | exit when the parent PID goes away |
| `SYNAPSE_TOKEN` | API token (pass via env, not argv) |

## 4. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Cannot run program ".../libsynapse.so": error=2, No such file or directory` and the file is missing from `nativeLibraryDir` | AGP keeps native libs compressed in the APK and doesn't extract them | `useLegacyPackaging = true` |
| `error=2, No such file or directory` but the file **exists** | A desktop (glibc) binary was packaged. Its interpreter `/lib/ld-linux…` doesn't exist on Android. The old `build-android.sh` did this silently when `cargo-ndk` was missing | Rebuild with the NDK. `verify-android-elf.sh` catches this |
| `error=8, Exec format error` | Wrong ABI in the folder (e.g. x86_64 binary in `arm64-v8a/`) | Rebuild. The verifier checks the machine type |
| Works on most phones, fails on Pixel 8+/Android 15 16 KB mode; Play Console warns about 16 KB | 4 KiB-aligned ELF (NDK r26 default) | NDK r27c+ plus the max-page-size flag, which the script sets |
| `error=13, Permission denied` | Binary copied to `filesDir` and executed from there (W^X) | Only execute from `nativeLibraryDir` |
| Daemon exits immediately with code 3 | No `--home` | `SynapseDaemon` passes it. When launching manually, use `filesDir` |
| Daemon starts, then the API stops responding after a while | stdout/stderr pipe never drained. Old builds blocked on log writes once the 64 KiB buffer filled | Fixed in the engine (non-blocking logging). `SynapseDaemon` also drains output |
| `CLEARTEXT communication to 127.0.0.1 not permitted` | Android 9+ cleartext policy | `network_security_config.xml` |
| Second launch fails, port 9090 busy | Orphaned daemon from a crashed app process | `--exit-with-parent --exit-on-stdin-close` (default in `SynapseDaemon`), `--port 0` |
| Peers on the same Wi-Fi never discovered | Device filters broadcast without a MulticastLock | `SynapseSyncService` acquires one. Needs `CHANGE_WIFI_MULTICAST_STATE` |
| `UnsatisfiedLinkError` mentioning `libsynapse.so` | Something called `System.loadLibrary("synapse")`. It's an executable, not a JNI library | Don't load it. Spawn it with `SynapseDaemon` |
| Sync stops after ~6 h on Android 15 | `dataSync` foreground-service time limit | Handled in `onTimeout`. Reschedule with WorkManager |

Logs: `adb shell run-as <your.package> ls files/synapse/logs/`, or
`adb exec-out run-as <your.package> cat files/synapse/logs/console.log`.
