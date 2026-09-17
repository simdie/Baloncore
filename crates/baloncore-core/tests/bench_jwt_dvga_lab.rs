//! A1 — end-to-end integration test for `bench-jwt-dvga`.
//!
//! Boots the pinned DVGA image via the CLI, runs the JwtAuthFinder, and asserts
//! the forged-admin-identity bypass is `TruePositive` and the public-paste decoy
//! is `TrueNegative`. Skips (NEEDS-HUMAN) when Docker / the image is absent.

use std::path::PathBuf;
use std::process::Command;

use baloncore_core::{evaluation::GroundTruthLabel, load_benchmark_run, BenchmarkRun};

const DVGA_IMAGE: &str =
    "dolevf/dvga@sha256:040aa33c199d99f3380c9ff9a1ee5d725e9abca7b189c63a35a2a73bda79c957";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .expect("repo root")
}

fn baloncore_bin() -> Option<PathBuf> {
    let root = repo_root();
    for c in ["target/debug/baloncore", "target/release/baloncore"] {
        let p = root.join(c);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn image_available() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
        && Command::new("docker")
            .args(["image", "inspect", DVGA_IMAGE])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

#[test]
fn bench_jwt_dvga_proves_forged_token_access() {
    if !image_available() {
        eprintln!(
            "[bench_jwt_dvga_lab] SKIP — Docker/DVGA image absent; run scripts/fetch_dvga.sh"
        );
        return;
    }
    let Some(bin) = baloncore_bin() else {
        eprintln!("[bench_jwt_dvga_lab] SKIP — baloncore binary not built");
        return;
    };
    let root = repo_root();
    let ws = std::env::temp_dir().join(format!("baloncore-jwt-dvga-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&ws);
    std::fs::create_dir_all(&ws).expect("ws");
    let run_out = ws.join("benchmark_run.json");

    let status = Command::new(&bin)
        .current_dir(&root)
        .arg("bench-jwt-dvga")
        .arg("--run-results-output")
        .arg(&run_out)
        .arg("--scorecard-output")
        .arg(ws.join("scorecard.json"))
        .arg("--host-port")
        .arg("5082")
        .status()
        .expect("spawn bench-jwt-dvga");
    assert!(
        status.success(),
        "bench-jwt-dvga should exit 0; got {status:?}"
    );

    let run: BenchmarkRun = load_benchmark_run(&run_out).expect("load run");
    let by = |id: &str| {
        run.results
            .iter()
            .find(|r| r.case_id == id)
            .unwrap_or_else(|| panic!("missing {id}"))
    };
    assert_eq!(
        by("vuln-forge-admin-identity").prediction,
        GroundTruthLabel::TruePositive,
        "forged-admin-identity bypass must be Verified"
    );
    assert_eq!(
        by("decoy-public-paste").prediction,
        GroundTruthLabel::TrueNegative,
        "public-paste decoy must NOT be flagged"
    );
    let _ = std::fs::remove_dir_all(&ws);
}
