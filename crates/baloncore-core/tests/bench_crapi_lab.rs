//! P2.S3 external corpus — end-to-end integration test for `bench-crapi`.
//!
//! Brings the OWASP crAPI Docker Compose stack up via the BALONCORE CLI binary
//! and asserts the resulting BenchmarkRun:
//!   - scores the vehicle-location BOLA (read another user's vehicle by GUID) as
//!     `TruePositive`,
//!   - scores the owner-scoped `/user/videos/{id}` (attacker 404) decoy as
//!     `TrueNegative`, and
//!   - scores the public JWKS decoy as `TrueNegative`.
//! The WHOLE stack (containers + volumes) is torn down via the runner's Drop
//! guard.
//!
//! Skipped (with a logged reason) unless Docker is running AND the stack has
//! been vendored by `scripts/fetch_crapi.sh` (compose file + images present).
//! Bringing the stack up is slow (Java services + DB seed), so this test is
//! gated and NEEDS-HUMAN to enable; it must not fail merely because nobody ran
//! the fetch script.

use std::path::PathBuf;
use std::process::Command;

use baloncore_core::{evaluation::GroundTruthLabel, load_benchmark_run, BenchmarkRun};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .expect("repo root resolvable from CARGO_MANIFEST_DIR")
}

fn baloncore_bin() -> Option<PathBuf> {
    let root = repo_root();
    for candidate in ["target/debug/baloncore", "target/release/baloncore"] {
        let p = root.join(candidate);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn docker_up() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Vendored only if the compose file exists AND the pinned web image is present.
fn crapi_vendored(root: &std::path::Path) -> bool {
    let compose = root.join(".baloncore/corpus/crapi/crAPI/deploy/docker/docker-compose.yml");
    if !compose.exists() {
        return false;
    }
    Command::new("docker")
        .args(["image", "inspect", "crapi/crapi-web:1.1.6-rc8"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn bench_crapi_real_stack_scores_bola_correctly() {
    let root = repo_root();
    if !docker_up() || !crapi_vendored(&root) {
        eprintln!(
            "[bench_crapi_lab] SKIP — Docker not running or crAPI not vendored. \
             Run `scripts/fetch_crapi.sh` to enable this test."
        );
        return;
    }
    let Some(bin) = baloncore_bin() else {
        eprintln!("[bench_crapi_lab] SKIP — baloncore binary not found; build with `cargo build`");
        return;
    };

    let workspace =
        std::env::temp_dir().join(format!("baloncore-bench-crapi-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::create_dir_all(&workspace).expect("create workspace");
    let run_out = workspace.join("benchmark_run.json");
    let sc_out = workspace.join("scorecard.json");

    let status = Command::new(&bin)
        .current_dir(&root)
        .arg("bench-crapi")
        .arg("--run-results-output")
        .arg(&run_out)
        .arg("--scorecard-output")
        .arg(&sc_out)
        .status()
        .expect("spawn bench-crapi");
    assert!(
        status.success(),
        "bench-crapi should exit 0; got {status:?}"
    );
    assert!(run_out.exists(), "benchmark_run.json must exist");

    let run: BenchmarkRun = load_benchmark_run(&run_out).expect("load BenchmarkRun");
    assert_eq!(run.suite_id, "baloncore-crapi-bola-v1");
    assert_eq!(
        run.results.len(),
        3,
        "expected 3 probes (1 vuln + 2 decoys)"
    );

    let by_id = |id: &str| {
        run.results
            .iter()
            .find(|r| r.case_id == id)
            .unwrap_or_else(|| panic!("missing result {id}"))
    };

    let planted = by_id("vuln-bola-vehicle-location");
    assert_eq!(
        planted.prediction,
        GroundTruthLabel::TruePositive,
        "vehicle-location BOLA must be detected; got {:?} (class={:?})",
        planted.prediction,
        planted.actual_classification
    );

    for decoy in ["decoy-user-video-owner-scoped", "decoy-public-jwks"] {
        let r = by_id(decoy);
        assert_eq!(
            r.prediction,
            GroundTruthLabel::TrueNegative,
            "decoy {decoy} must NOT be flagged; got {:?} (class={:?})",
            r.prediction,
            r.actual_classification
        );
    }

    let _ = std::fs::remove_dir_all(&workspace);
}
