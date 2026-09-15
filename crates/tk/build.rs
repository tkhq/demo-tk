//! Bakes release and provenance metadata into the `tk` binary as `TK_*`
//! compile-time environment variables. The release tag is the version of
//! record: the release workflow sets `TK_RELEASE_VERSION` to the tag, and
//! local builds fall back to `git describe --tags` and then to the manifest
//! version. Git-derived values can be overridden through the environment for
//! builds without a checkout.
use std::env;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn var(name: &str) -> Option<String> {
    println!("cargo::rerun-if-env-changed={name}");
    env::var(name).ok().filter(|value| !value.is_empty())
}

fn git(arguments: &[&str]) -> Option<String> {
    let output = Command::new("git").args(arguments).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn main() {
    if let Some(git_dir) = git(&["rev-parse", "--git-dir"]) {
        println!("cargo::rerun-if-changed={git_dir}/HEAD");
        println!("cargo::rerun-if-changed={git_dir}/index");
    }

    // SOURCE_DATE_EPOCH keeps reproducible builds from embedding the wall clock.
    let build_timestamp = var("SOURCE_DATE_EPOCH").unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since_epoch| since_epoch.as_secs())
            .unwrap_or_default()
            .to_string()
    });
    if build_timestamp.parse::<u64>().is_err() {
        println!("cargo::error=SOURCE_DATE_EPOCH must be a Unix timestamp");
    }

    let version = var("TK_RELEASE_VERSION")
        .or_else(|| git(&["describe", "--tags"]))
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned());
    let build_target = env::var("TARGET").unwrap_or_else(|_| {
        println!("cargo::error=TARGET must be set by Cargo");
        String::new()
    });
    let release_build = match var("TK_RELEASE_BUILD").as_deref() {
        Some("1") => true,
        None => false,
        Some(_) => {
            println!("cargo::error=TK_RELEASE_BUILD must be 1 when set");
            false
        }
    };
    println!("cargo::rustc-env=TK_VERSION={version}");
    println!("cargo::rustc-env=TK_BUILD_TIMESTAMP={build_timestamp}");
    println!("cargo::rustc-env=TK_BUILD_TARGET={build_target}");
    println!("cargo::rustc-env=TK_RELEASE_BUILD={release_build}");

    let git_dirty = match var("TK_GIT_DIRTY") {
        Some(value) if value == "clean" || value == "dirty" => Some(value),
        Some(_) => {
            println!("cargo::error=TK_GIT_DIRTY must be clean or dirty");
            None
        }
        None => git(&["status", "--porcelain", "--untracked-files=no"])
            .map(|status| if status.is_empty() { "clean" } else { "dirty" }.to_owned()),
    };
    let git_sha = var("TK_GIT_SHA").or_else(|| git(&["rev-parse", "--short=12", "HEAD"]));
    println!(
        "cargo::rustc-env=TK_GIT_SHA={}",
        git_sha.as_deref().unwrap_or("unknown")
    );
    println!(
        "cargo::rustc-env=TK_GIT_DIRTY={}",
        git_dirty.as_deref().unwrap_or("unknown")
    );
}
