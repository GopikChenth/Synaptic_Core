# Release pipeline

Synapse Core ships as **one engine binary per platform**. Client apps launch it and
drive it over its local HTTP/WebSocket API ([api-endpoints.md](api-endpoints.md)).
The pipeline checks that every binary actually serves that API on its own platform
before anything is published.

```
 push / PR / tag
        │
        ├── CI (.github/workflows/ci.yml): quality gates
        │     fmt · clippy -D warnings · tests (Linux, macOS, Windows) · MSRV 1.89
        │     shellcheck + actionlint · cargo audit
        │
        └── Release Pipeline (.github/workflows/release.yml)
              │
              meta: read version from Cargo.toml; on tags, require tag == v<version>
              │
              ├── desktop ×4 ─ build → linkage check → API smoke test → package
              │     linux-x86_64     x86_64-unknown-linux-musl   (static, any distro)
              │     linux-arm64      aarch64-unknown-linux-musl  (static, native ARM runner)
              │     windows-x64      x86_64-pc-windows-msvc      (static CRT, no VC++ redist)
              │     macos-universal  arm64 + x86_64 via lipo
              │
              ├── android-build ─ NDK r27c → verify-android-elf.sh → package
              │     arm64-v8a · armeabi-v7a · x86_64   (16 KiB aligned, API 21+)
              │     └── android-emulator ×3 ─ run engine as an app would → API smoke test
              │           API 24 (oldest) · API 34 (current) · API 35 16 KiB pages (experimental)
              │
              └── release (tags only, all green)
                    SHA256SUMS.txt · manifest.json · build provenance · GitHub Release
```

## What "tested" means

`scripts/smoke-test.sh` is the API contract test. It runs against every desktop
binary on its own OS, and against the Android binary on emulators through `adb forward`:

- `--version` and `/api/v1/system/version` report the release version
- the engine publishes `runtime.json` with its bound address (`--port 0`)
- auth: `/api/v1/system/ping` is open, every other endpoint returns `401` without the token
- folders: register → status → list → delete
- devices, pending devices, conflicts, connections respond
- `POST /api/v1/system/restart` → the engine comes back `ready` on the same address
- `POST /api/v1/system/shutdown` → process exits with code `0` and removes `runtime.json`

On Android, `scripts/smoke-test-android.sh` also checks that the binary executes as an
unprivileged process and that a missing `--home` exits with code `3` instead of crashing.

Run it locally against any build:

```bash
cargo build --release
scripts/smoke-test.sh --bin target/release/synapse-core
```

## Release artifacts

| File | Contents |
|---|---|
| `synapse-core-<v>-linux-x86_64.tar.gz` | `synapse-core`, `LICENSE`, `README.md`, `API.md` |
| `synapse-core-<v>-linux-arm64.tar.gz` | same |
| `synapse-core-<v>-macos-universal.tar.gz` | same (universal binary) |
| `synapse-core-<v>-windows-x64.zip` | `synapse-core.exe`, docs |
| `synapse-core-<v>-android-jniLibs.zip` | `jniLibs/<abi>/libsynapse.so`, `ANDROID.md`, `API.md` |
| `SHA256SUMS.txt` | checksums of all archives |
| `manifest.json` | machine-readable index for the app (below) |

Every archive also has a [GitHub build provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations).
Verify with `gh attestation verify <file> -R GopikChenth/Synaptic_Core`.

Untagged pushes to `main` upload the same archives as workflow artifacts (kept 14 days),
so any commit can be tested before it is tagged.

## Consuming releases from the app

`manifest.json` lets the app (or its build script) pick and verify the right binary
without hard-coding file names:

```json
{
  "name": "synapse-core",
  "version": "1.1.0",
  "tag": "v1.1.0",
  "commit": "…",
  "published_at": "2026-11-22T10:00:00Z",
  "api": { "base_path": "/api/v1", "version": "v1" },
  "artifacts": [
    { "platform": "windows", "arch": "x64", "target": "x86_64-pc-windows-msvc",
      "file": "synapse-core-1.1.0-windows-x64.zip",
      "url": "https://github.com/GopikChenth/Synaptic_Core/releases/download/v1.1.0/synapse-core-1.1.0-windows-x64.zip",
      "size": 4303842, "sha256": "…" }
  ]
}
```

The latest stable manifest is always at:
`https://github.com/GopikChenth/Synaptic_Core/releases/latest/download/manifest.json`

Recommended app-side flow:
1. Pin an engine version in the app's build config (don't silently float to `latest`).
2. Download the artifact for the target platform from `manifest.json`.
3. **Verify `sha256` before unpacking.** Fail the build on mismatch.
4. Desktop: bundle the binary with the app. Android: unzip `jniLibs/` into the app module
   (binaries can't be downloaded at runtime on Android because of W^X; they must be in
   the APK).
5. At runtime, check `GET /api/v1/system/version` and refuse to talk to an engine whose
   major version you don't support.

## Cutting a release

**From GitHub (recommended):** **Actions → Prepare Release → Run workflow**, enter the
version (e.g. `1.1.0`). Tick *dry run* to only validate. The workflow then:

1. checks the version is valid semver, newer than `Cargo.toml`, and not tagged yet
2. bumps `Cargo.toml` + `Cargo.lock`, commits `chore(release): v1.1.0`, tags `v1.1.0`
3. pushes the commit and tag atomically
4. starts the **Release Pipeline** on the tag: build → API tests on every platform
   (incl. Android emulators) → GitHub Release

**From your machine:**

```bash
scripts/bump-version.sh 1.1.0          # edits Cargo.toml/Cargo.lock, commits, tags v1.1.0
git push origin HEAD --follow-tags     # the tag push starts the Release Pipeline
```

- Versions with a suffix (`1.2.0-beta.1`) are published as **pre-releases** and are not
  marked *latest*, so `releases/latest/download/manifest.json` keeps pointing at the
  last stable release.
- A tag that doesn't match `Cargo.toml` fails the `meta` job before anything is built.
- Each release page starts with a download table, verification commands and app
  integration notes (`scripts/release-notes.py`). GitHub's generated changelog follows,
  grouped by PR label (`breaking`, `feature`, `bug`, `android`, `api`, `ci`;
  `skip-changelog` hides a PR). See `.github/release.yml`.
- Re-running the Release Pipeline for an existing tag updates that release in place.

## Repository settings (one-time)

- **Branch protection on `main`**: require the `CI` and `Release Pipeline` checks.
- **Actions → General → Workflow permissions**: the release job requests
  `contents: write`, `id-token: write` and `attestations: write` itself. No extra
  secrets are needed.
- **Tag protection** (`v*`): only maintainers can push release tags.
- **Prepare Release vs. branch protection**: if `main` requires PRs, either let GitHub
  Actions bypass the rule, or add a fine-grained PAT with `contents: write` as the
  `RELEASE_TOKEN` repository secret. Prepare Release uses it automatically. With it,
  the tag push starts the Release Pipeline directly.

## Not yet covered

- **Code signing / notarization**: macOS Gatekeeper and Windows SmartScreen warn on
  unsigned binaries the first time they are downloaded directly. If your app bundles
  the engine and the app itself is signed, this mostly doesn't matter. Signing the
  engine needs an Apple Developer ID (notarization) and a Windows code-signing
  certificate stored as repository secrets.
- **Android ARM on emulator**: the arm64-v8a and armeabi-v7a builds are verified
  structurally (ELF checks) but executed only on x86_64 emulators. Hosted CI has no
  ARM Android emulators with KVM. Test them on a physical device before major releases.
