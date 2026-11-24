#!/usr/bin/env python3
"""Generate SHA256SUMS.txt and manifest.json for a release directory.

manifest.json is the machine-readable index the client app uses to find the engine
binary for its platform, verify it, and check compatibility:

    {
      "name": "synapse-core",
      "version": "1.2.0",
      "tag": "v1.2.0",
      "commit": "abc123...",
      "published_at": "2026-11-22T10:00:00Z",
      "api": {"base_path": "/api/v1", "version": "v1"},
      "artifacts": [
        {"platform": "linux", "arch": "x86_64", "target": "x86_64-unknown-linux-musl",
         "file": "synapse-core-1.2.0-linux-x86_64.tar.gz",
         "url": "https://github.com/<repo>/releases/download/v1.2.0/...",
         "size": 4200000, "sha256": "..."},
        ...
      ]
    }

Usage: release-manifest.py --dir dist/release --version 1.2.0 --tag v1.2.0 \
                           --repo owner/name [--commit SHA]
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import sys

# asset suffix -> (platform, arch, rust target or ABI list)
KNOWN = {
    "linux-x86_64": ("linux", "x86_64", "x86_64-unknown-linux-musl"),
    "linux-arm64": ("linux", "arm64", "aarch64-unknown-linux-musl"),
    "macos-universal": ("macos", "universal", "aarch64-apple-darwin+x86_64-apple-darwin"),
    "windows-x64": ("windows", "x64", "x86_64-pc-windows-msvc"),
    "android-jniLibs": ("android", "arm64-v8a,armeabi-v7a,x86_64", "android-jniLibs"),
}

ARCHIVE_EXT_RE = re.compile(r"\.(?:tar\.gz|zip)$")


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", required=True, type=pathlib.Path)
    ap.add_argument("--version", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--repo", required=True, help="owner/name on GitHub")
    ap.add_argument("--commit", default="")
    args = ap.parse_args()

    version = args.version.removeprefix("v")
    archives = sorted(
        p for p in args.dir.iterdir() if p.is_file() and (p.name.endswith(".tar.gz") or p.name.endswith(".zip"))
    )
    if not archives:
        print(f"error: no archives in {args.dir}", file=sys.stderr)
        return 1

    prefix = f"synapse-core-{version}-"
    artifacts, sums, errors, seen = [], [], [], set()
    for p in archives:
        if not p.name.startswith(prefix):
            errors.append(f"{p.name}: expected name '{prefix}<platform>.<tar.gz|zip>'")
            continue
        suffix = ARCHIVE_EXT_RE.sub("", p.name[len(prefix):])
        if suffix not in KNOWN:
            errors.append(f"{p.name}: unknown platform suffix '{suffix}'")
            continue
        digest = sha256(p)
        sidecar = p.with_name(p.name + ".sha256")
        if sidecar.exists():
            recorded = sidecar.read_text().split()[0]
            if recorded != digest:
                errors.append(f"{p.name}: checksum mismatch with {sidecar.name}")
                continue
        seen.add(suffix)
        platform, arch, target = KNOWN[suffix]
        artifacts.append(
            {
                "platform": platform,
                "arch": arch,
                "target": target,
                "file": p.name,
                "url": f"https://github.com/{args.repo}/releases/download/{args.tag}/{p.name}",
                "size": p.stat().st_size,
                "sha256": digest,
            }
        )
        sums.append(f"{digest}  {p.name}")

    missing = sorted(set(KNOWN) - seen)
    if missing:
        errors.append(f"missing platforms: {', '.join(missing)}")
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 1

    manifest = {
        "name": "synapse-core",
        "version": version,
        "tag": args.tag,
        "commit": args.commit,
        "published_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "api": {"base_path": "/api/v1", "version": "v1"},
        "artifacts": artifacts,
    }
    (args.dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (args.dir / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
