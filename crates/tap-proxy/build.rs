use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    println!("cargo:rerun-if-env-changed=TAP_BUILD_SHA");
    println!("cargo:rerun-if-changed=build-sha.txt");
    let build_sha_file = Path::new("build-sha.txt");
    let build_sha = std::env::var("TAP_BUILD_SHA")
        .or_else(|_| std::env::var("GITHUB_SHA"))
        .ok()
        .or_else(|| {
            std::fs::read_to_string(build_sha_file)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .or_else(|| {
            Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
                .ok()
                .filter(|out| out.status.success())
                .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=TAP_BUILD_SHA={build_sha}");

    let dashboard = Path::new("dashboard");
    if !dashboard.exists() {
        return;
    }

    // Re-run if any source file in dashboard/src changes.
    println!("cargo:rerun-if-changed=dashboard/src");
    println!("cargo:rerun-if-changed=dashboard/index.html");
    println!("cargo:rerun-if-changed=dashboard/package.json");
    println!("cargo:rerun-if-changed=dashboard/vite.config.js");

    // Install deps if node_modules is missing.
    if !dashboard.join("node_modules").exists() {
        let status = Command::new("npm")
            .args(["install"])
            .current_dir(dashboard)
            .status()
            .expect("build.rs: npm install failed");
        assert!(status.success(), "build.rs: npm install exited non-zero");
    }

    let status = Command::new("npm")
        .args(["run", "build"])
        .current_dir(dashboard)
        .status()
        .expect("build.rs: npm run build failed");
    assert!(status.success(), "build.rs: dashboard build failed");
}
