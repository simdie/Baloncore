//! A1 — end-to-end integration test for `bench-jwt-vampi`.
//!
//! Boots the vulnerable VAmPI instance via the CLI, runs the JwtAuthFinder, and
//! asserts the weak-secret HMAC forgery is `TruePositive`, while the alg=none
//! (correctly-rejected) and public-users decoys are `TrueNegative`. Skips
//! (NEEDS-HUMAN) when the vendored VAmPI venv is absent.

use std::path::PathBuf;
use std::process::Command;

use baloncore_core::{evaluation::GroundTruthLabel, load_benchmark_run, BenchmarkRun};

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

fn vampi_vendored(root: &std::path::Path) -> bool {
    root.join(".baloncore/corpus/vampi/VAmPI/.venv/bin/python")
        .exists()
}

#[test]
fn bench_jwt_vampi_proves_weak_secret_forgery() {
    let root = repo_root();
    if !vampi_vendored(&root) {
        eprintln!("[bench_jwt_vampi_lab] SKIP — VAmPI venv absent; run scripts/fetch_vampi.sh");
        return;
    }
    let Some(bin) = baloncore_bin() else {
        eprintln!("[bench_jwt_vampi_lab] SKIP — baloncore binary not built");
        return;
    };
    let ws = std::env::temp_dir().join(format!("baloncore-jwt-vampi-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&ws);
    std::fs::create_dir_all(&ws).expect("ws");
    let run_out = ws.join("benchmark_run.json");

    let status = Command::new(&bin)
        .current_dir(&root)
        .arg("bench-jwt-vampi")
        .arg("--run-results-output")
        .arg(&run_out)
        .arg("--scorecard-output")
        .arg(ws.join("scorecard.json"))
        // Distinct port to avoid colliding with the VAmPI BOLA lab test (5071/5072).
        .arg("--lab-port")
        .arg("5003")
        .status()
        .expect("spawn bench-jwt-vampi");
    assert!(
        status.success(),
        "bench-jwt-vampi should exit 0; got {status:?}"
    );

    let run: BenchmarkRun = load_benchmark_run(&run_out).expect("load run");
    let by = |id: &str| {
        run.results
            .iter()
            .find(|r| r.case_id == id)
            .unwrap_or_else(|| panic!("missing {id}"))
    };
    assert_eq!(
        by("vuln-weak-secret-hmac-admin").prediction,
        GroundTruthLabel::TruePositive,
        "weak-secret HMAC forgery must be Verified"
    );
    for decoy in ["decoy-algnone-rejected", "decoy-public-users"] {
        assert_eq!(
            by(decoy).prediction,
            GroundTruthLabel::TrueNegative,
            "decoy {decoy} must NOT be flagged"
        );
    }
    let _ = std::fs::remove_dir_all(&ws);
}
