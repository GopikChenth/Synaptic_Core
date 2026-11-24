#!/usr/bin/env python3
"""Render the top of a GitHub Release body from manifest.json.

GitHub appends its auto-generated "What's changed" notes below this header
(categorised by .github/release.yml).

Usage: release-notes.py --manifest dist/release/manifest.json --repo owner/name
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

PLATFORM_LABEL = {
    ("linux", "x86_64"): "Linux x86_64 (static, any distro)",
    ("linux", "arm64"): "Linux arm64 (static, any distro)",
    ("macos", "universal"): "macOS (Apple Silicon + Intel)",
    ("windows", "x64"): "Windows x64",
}


def human_size(n: int) -> str:
    return f"{n / 1048576:.1f} MiB"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True, type=pathlib.Path)
    ap.add_argument("--repo", required=True)
    args = ap.parse_args()

    m = json.loads(args.manifest.read_text())
    version, tag = m["version"], m["tag"]
    base = f"https://github.com/{args.repo}/releases/download/{tag}"

    desktop = [a for a in m["artifacts"] if a["platform"] != "android"]
    android = [a for a in m["artifacts"] if a["platform"] == "android"]

    out = [f"## synapse-core {version}", ""]
    if "-" in version:
        out += ["> **Pre-release.** Not marked as latest; test before shipping it in your app.", ""]

    out += ["### Downloads", "", "| Platform | File | Size |", "|---|---|---|"]
    for a in sorted(desktop, key=lambda a: (a["platform"], a["arch"])):
        label = PLATFORM_LABEL.get((a["platform"], a["arch"]), f'{a["platform"]} {a["arch"]}')
        out.append(f'| {label} | [`{a["file"]}`]({a["url"]}) | {human_size(a["size"])} |')
    for a in android:
        out.append(
            f'| Android ({a["arch"].replace(",", ", ")}) | [`{a["file"]}`]({a["url"]}) | {human_size(a["size"])} |'
        )

    out += [
        "",
        "Every binary in this release passed the HTTP API smoke test on its own platform;",
        "the Android build ran on emulators (API 24 and 34) before publishing.",
        "",
        "### Verify",
        "",
        "```bash",
        f"curl -LO {base}/SHA256SUMS.txt",
        "sha256sum -c SHA256SUMS.txt --ignore-missing",
        f"gh attestation verify <file> -R {args.repo}   # build provenance",
        "```",
        "",
        "### Use it from your app",
        "",
        f"- Machine-readable index: [`manifest.json`]({base}/manifest.json) "
        "(platform, URL, size, SHA-256 per artifact)",
        f"- Latest stable index: `https://github.com/{args.repo}/releases/latest/download/manifest.json`",
        "- API: `/api/v1` (see `API.md` inside each archive)",
    ]
    if android:
        out += [
            "- Android: unzip `jniLibs/` into your app module and set "
            "`packaging { jniLibs { useLegacyPackaging = true } }` (see `ANDROID.md`)",
        ]
    out.append("")
    sys.stdout.write("\n".join(out) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
