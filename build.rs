//! Embeds build metadata (target triple, git revision) for `synapse-core --version`.

use std::process::Command;

fn main() {
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=SYNAPSE_BUILD_TARGET={target}");

    let rev = std::env::var("SYNAPSE_GIT_REV")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(10).collect::<String>())
        .or_else(|| {
            Command::new("git")
                .args(["rev-parse", "--short=10", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
        });
    println!(
        "cargo:rustc-env=SYNAPSE_GIT_REV={}",
        rev.unwrap_or_else(|| "unknown".into())
    );
    println!("cargo:rerun-if-env-changed=SYNAPSE_GIT_REV");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");
}
