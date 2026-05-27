#!/usr/bin/env python3
"""Local BALONCORE enterprise workbench.

This server is intentionally localhost-first. It coordinates the existing
BALONCORE validator kernel and adds a repo-security inventory layer without
sending data to any external service.
"""

from __future__ import annotations

import argparse
from collections import Counter
import datetime as dt
import hashlib
import html
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKBENCH_ROOT = REPO_ROOT / ".baloncore" / "workbench"
JOBS_ROOT = WORKBENCH_ROOT / "jobs"
MAX_SCAN_FILES = 6000
MAX_TEXT_FILE_BYTES = 1_000_000
JOB_LOCK = threading.Lock()

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_temp_access_key_id", re.compile(r"\bASIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("stripe_live_secret", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

TEXT_EXTENSIONS = {
    ".bash",
    ".c",
    ".conf",
    ".cpp",
    ".cs",
    ".css",
    ".csv",
    ".env",
    ".go",
    ".graphql",
    ".h",
    ".html",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".lock",
    ".md",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sol",
    ".sql",
    ".tf",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

DEPENDENCY_MANIFESTS = {
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
    "go.mod",
    "go.sum",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pom.xml",
    "pyproject.toml",
    "requirements.txt",
    "yarn.lock",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def make_run_dir(prefix: str) -> Path:
    run_id = f"{prefix}-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    out_dir = WORKBENCH_ROOT / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def read_json_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON body: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("JSON body must be an object")
    return parsed


def require_authorized(payload: dict[str, Any]) -> None:
    if payload.get("authorized") is not True:
        raise PermissionError(
            "BALONCORE requires authorized=true for active scans and local repo review."
        )


def json_response(handler: BaseHTTPRequestHandler, status: int, body: dict[str, Any]) -> None:
    encoded = json.dumps(body, indent=2, sort_keys=True).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(encoded)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(encoded)


def html_response(handler: BaseHTTPRequestHandler, body: str) -> None:
    encoded = body.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(encoded)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(encoded)


def resolve_local_path(path_value: str) -> Path:
    if not path_value:
        raise ValueError("path is required")
    path = Path(path_value).expanduser()
    if not path.is_absolute():
        path = (REPO_ROOT / path).resolve()
    else:
        path = path.resolve()
    if not path.exists():
        raise FileNotFoundError(f"path does not exist: {path}")
    return path


def resolve_artifact_path(path_value: str) -> Path:
    if not path_value:
        raise ValueError("artifact path is required")
    path = Path(path_value).expanduser()
    if not path.is_absolute():
        path = (REPO_ROOT / path).resolve()
    else:
        path = path.resolve()

    workbench_root = WORKBENCH_ROOT.resolve()
    if workbench_root not in path.parents and path != workbench_root:
        raise ValueError("artifact preview is restricted to .baloncore/workbench artifacts")
    if not path.is_file():
        raise FileNotFoundError(f"artifact does not exist: {path}")
    return path


def resolve_output_dir(payload: dict[str, Any], default: Path) -> Path:
    out_dir_value = payload.get("out_dir")
    if not out_dir_value:
        default.mkdir(parents=True, exist_ok=True)
        return default

    candidate = Path(str(out_dir_value)).expanduser()
    if not candidate.is_absolute():
        candidate = (REPO_ROOT / candidate).resolve()
    else:
        candidate = candidate.resolve()

    repo_root = REPO_ROOT.resolve()
    if repo_root not in candidate.parents and candidate != repo_root:
        raise ValueError("out_dir must stay inside the BALONCORE project directory")

    candidate.mkdir(parents=True, exist_ok=True)
    return candidate


def safe_read_json(path: Path) -> dict[str, Any] | list[Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def write_json_file(path: Path, value: dict[str, Any] | list[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def run_command(args: list[str], out_dir: Path, timeout: int = 300) -> dict[str, Any]:
    started = time.time()
    command_record = {
        "command": args,
        "cwd": str(REPO_ROOT),
        "started_at": utc_now(),
        "timeout_seconds": timeout,
    }
    try:
        proc = subprocess.run(
            args,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        command_record.update(
            {
                "exit_code": proc.returncode,
                "duration_seconds": round(time.time() - started, 3),
                "stdout": proc.stdout[-16000:],
                "stderr": proc.stderr[-16000:],
                "ok": proc.returncode == 0,
            }
        )
    except subprocess.TimeoutExpired as exc:
        command_record.update(
            {
                "exit_code": None,
                "duration_seconds": round(time.time() - started, 3),
                "stdout": (exc.stdout or "")[-16000:] if isinstance(exc.stdout, str) else "",
                "stderr": (exc.stderr or "")[-16000:] if isinstance(exc.stderr, str) else "",
                "ok": False,
                "error": f"command timed out after {timeout}s",
            }
        )

    log_path = out_dir / "command_log.json"
    existing: list[dict[str, Any]] = []
    if log_path.exists():
        try:
            existing = json.loads(log_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing = []
    existing.append(command_record)
    write_json_file(log_path, existing)
    return command_record


def redact_secret(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def line_hash(path: Path, line_no: int, value: str) -> str:
    digest = hashlib.sha256(f"{path}:{line_no}:{value}".encode("utf-8")).hexdigest()
    return digest[:16]


def should_read_text(path: Path) -> bool:
    if path.name in DEPENDENCY_MANIFESTS:
        return True
    if path.name.startswith(".env"):
        return True
    return path.suffix.lower() in TEXT_EXTENSIONS


def classify_file(root: Path, path: Path) -> dict[str, Any]:
    rel = path.relative_to(root).as_posix()
    name = path.name
    suffix = path.suffix.lower()
    tags: list[str] = []

    if name in DEPENDENCY_MANIFESTS:
        tags.append("dependency_manifest")
    if ".github/workflows/" in f"/{rel}" and suffix in {".yml", ".yaml"}:
        tags.append("ci_workflow")
    if name == "Dockerfile" or name.startswith("Dockerfile.") or name == "docker-compose.yml":
        tags.append("container")
    if suffix == ".tf" or name.endswith(".tfstate") or name.endswith(".tfplan.json"):
        tags.append("terraform")
    if suffix in {".yml", ".yaml"}:
        try:
            body = path.read_text(encoding="utf-8", errors="ignore")[:4000]
            if "apiVersion:" in body and "kind:" in body:
                tags.append("kubernetes_yaml")
            if "AWSTemplateFormatVersion" in body or "AWS::" in body:
                tags.append("cloudformation")
        except OSError:
            pass
    if suffix == ".sol" or name in {"foundry.toml", "hardhat.config.js", "hardhat.config.ts"}:
        tags.append("web3")
    if name.startswith(".env"):
        tags.append("environment_file")

    return {"path": rel, "extension": suffix or "<none>", "tags": tags}


def scan_repository(path: Path, out_dir: Path | None = None) -> dict[str, Any]:
    root = path.resolve()
    if root.is_file():
        root = root.parent
    if out_dir is None:
        out_dir = make_run_dir("repo-inventory")
    out_dir.mkdir(parents=True, exist_ok=True)

    files_seen = 0
    skipped = 0
    extensions: dict[str, int] = {}
    tagged_files: list[dict[str, Any]] = []
    secret_hits: list[dict[str, Any]] = []
    manifests: list[str] = []
    ci_workflows: list[str] = []
    iac_files: list[str] = []
    web3_files: list[str] = []
    containers: list[str] = []

    ignored_dirs = {
        ".baloncore",
        ".git",
        ".hg",
        ".svn",
        "dist",
        "node_modules",
        "target",
        "vendor",
        "venv",
    }

    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ignored_dirs and not d.startswith(".terraform")]
        current_path = Path(current)
        for filename in files:
            files_seen += 1
            if files_seen > MAX_SCAN_FILES:
                skipped += 1
                continue
            full_path = current_path / filename
            try:
                rel = full_path.relative_to(root).as_posix()
                size = full_path.stat().st_size
            except OSError:
                skipped += 1
                continue

            ext = full_path.suffix.lower() or "<none>"
            extensions[ext] = extensions.get(ext, 0) + 1
            classified = classify_file(root, full_path)
            if classified["tags"]:
                tagged_files.append(classified)
            if "dependency_manifest" in classified["tags"]:
                manifests.append(rel)
            if "ci_workflow" in classified["tags"]:
                ci_workflows.append(rel)
            if any(tag in classified["tags"] for tag in ("terraform", "kubernetes_yaml", "cloudformation")):
                iac_files.append(rel)
            if "web3" in classified["tags"]:
                web3_files.append(rel)
            if "container" in classified["tags"]:
                containers.append(rel)

            if size > MAX_TEXT_FILE_BYTES or not should_read_text(full_path):
                continue
            try:
                text = full_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                skipped += 1
                continue

            for line_no, line in enumerate(text.splitlines(), start=1):
                for name, pattern in SECRET_PATTERNS:
                    for match in pattern.finditer(line):
                        value = match.group(0)
                        secret_hits.append(
                            {
                                "type": name,
                                "path": rel,
                                "line": line_no,
                                "redacted": redact_secret(value),
                                "line_hash": line_hash(Path(rel), line_no, value),
                                "action": "Rotate if real; BALONCORE did not validate or transmit this secret.",
                            }
                        )

    risk_score = 0
    risk_score += min(len(secret_hits) * 20, 60)
    risk_score += 10 if iac_files else 0
    risk_score += 10 if ci_workflows else 0
    risk_score += 10 if web3_files else 0
    risk_score += 5 if containers else 0
    risk_score = min(risk_score, 100)

    next_actions: list[str] = []
    if secret_hits:
        next_actions.append("Review redacted secret hits, rotate real credentials, and add pre-commit secret scanning.")
    if iac_files:
        next_actions.append("Run authorized cloud/IAM analysis on exported Terraform, CloudFormation, or provider JSON.")
    if web3_files:
        next_actions.append("Run BALONCORE Web3 analysis and generated invariant tests for Solidity projects.")
    if ci_workflows:
        next_actions.append("Add BALONCORE CI evidence gates and regression replay to the pipeline.")
    if not next_actions:
        next_actions.append("No high-signal repo indicators found; add dependency, SAST, and IaC adapters next.")

    inventory = {
        "kind": "baloncore_repo_inventory",
        "created_at": utc_now(),
        "root": str(root),
        "output_dir": str(out_dir),
        "summary": {
            "files_seen": files_seen,
            "files_skipped": skipped,
            "extensions": dict(sorted(extensions.items())),
            "dependency_manifests": len(manifests),
            "ci_workflows": len(ci_workflows),
            "iac_files": len(iac_files),
            "web3_files": len(web3_files),
            "container_files": len(containers),
            "secret_hits": len(secret_hits),
            "risk_score": risk_score,
        },
        "files": {
            "dependency_manifests": manifests[:200],
            "ci_workflows": ci_workflows[:200],
            "iac": iac_files[:200],
            "web3": web3_files[:200],
            "containers": containers[:200],
            "tagged": tagged_files[:500],
        },
        "secret_hits": secret_hits[:500],
        "next_actions": next_actions,
        "policy": {
            "network_validation": "disabled",
            "secret_values_stored": "redacted_only",
            "max_scan_files": MAX_SCAN_FILES,
            "max_text_file_bytes": MAX_TEXT_FILE_BYTES,
        },
    }
    write_json_file(out_dir / "repo_inventory.json", inventory)
    return inventory


def web3_project_roots(target_path: Path, inventory: dict[str, Any]) -> list[Path]:
    root = target_path.resolve()
    if root.is_file():
        root = root.parent

    markers = {"foundry.toml", "hardhat.config.js", "hardhat.config.ts"}
    candidates: set[Path] = set()
    web3_files = inventory.get("files", {}).get("web3", [])
    for rel in web3_files:
        rel_path = Path(str(rel))
        absolute = (root / rel_path).resolve()
        if absolute.name in markers:
            candidates.add(absolute.parent)
            continue

        cursor = absolute.parent
        selected = cursor
        while root in cursor.parents or cursor == root:
            if any((cursor / marker).exists() for marker in markers):
                selected = cursor
                break
            if cursor == root:
                break
            cursor = cursor.parent
        candidates.add(selected)

    return sorted(candidates, key=lambda p: str(p))[:5]


def scan_repo(payload: dict[str, Any]) -> dict[str, Any]:
    require_authorized(payload)
    target_path = resolve_local_path(str(payload.get("path", "")))
    out_dir = resolve_output_dir(payload, make_run_dir("repo-scan"))
    inventory = scan_repository(target_path, out_dir)
    commands: list[dict[str, Any]] = []

    web3_roots = web3_project_roots(target_path, inventory)
    for index, web3_root in enumerate(web3_roots, start=1):
        root_slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", web3_root.name) or f"project_{index}"
        web3_out = out_dir / "web3" / f"{index:02d}_{root_slug}"
        web3_out.mkdir(parents=True, exist_ok=True)
        commands.append(
            run_command(
                [
                    "cargo",
                    "run",
                    "-p",
                    "baloncore",
                    "--",
                    "analyze-web3",
                    str(web3_root),
                    "--out-dir",
                    str(web3_out),
                    "--json",
                ],
                out_dir,
                timeout=int(payload.get("timeout_seconds", 300)),
            )
        )

    result = {
        "ok": all(command.get("ok") for command in commands) if commands else True,
        "run_dir": str(out_dir),
        "inventory": inventory,
        "commands": commands,
    }
    write_json_file(out_dir / "repo_scan_result.json", result)
    result["run_intelligence"] = write_run_intelligence(out_dir, "repo_scan")
    result["artifact_paths"] = list_artifacts(out_dir)
    write_json_file(out_dir / "repo_scan_result.json", result)
    return result


def scan_webapp(payload: dict[str, Any]) -> dict[str, Any]:
    require_authorized(payload)
    base_url = str(payload.get("base_url", "")).strip()
    openapi_url = str(payload.get("openapi_url", "")).strip()
    if not base_url or not openapi_url:
        raise ValueError("base_url and openapi_url are required")

    out_dir = resolve_output_dir(payload, make_run_dir("webapi-scan"))
    config = str(payload.get("config", "baloncore.toml"))
    owner_profile = str(payload.get("owner_profile", "user_b"))
    max_active_requests = str(int(payload.get("max_active_requests", 250)))
    noise_mode = str(payload.get("noise_mode", "quiet"))

    args = [
        "cargo",
        "run",
        "-p",
        "baloncore",
        "--",
        "scan-openapi-bola",
        "--base-url",
        base_url,
        "--openapi-url",
        openapi_url,
        "--config",
        config,
        "--owner-profile",
        owner_profile,
        "--out-dir",
        str(out_dir),
        "--noise-mode",
        noise_mode,
        "--max-active-requests",
        max_active_requests,
        "--json",
    ]
    for profile in payload.get("attacker_profiles", []) or []:
        args.extend(["--attacker-profile", str(profile)])
    if payload.get("ci_anonymous_exposure") is True:
        args.append("--ci-anonymous-exposure")

    command = run_command(args, out_dir, timeout=int(payload.get("timeout_seconds", 300)))
    result = {
        "ok": command.get("ok") is True,
        "run_dir": str(out_dir),
        "command": command,
    }
    write_json_file(out_dir / "webapi_scan_result.json", result)
    result["run_intelligence"] = write_run_intelligence(out_dir, "webapi_scan")
    result["artifact_paths"] = list_artifacts(out_dir)
    write_json_file(out_dir / "webapi_scan_result.json", result)
    return result


def artifact_kind(path: Path) -> str:
    name = path.name
    parent = path.parent.name
    suffix = path.suffix.lower()
    if name in {"repo_inventory.json", "openapi_inventory.json", "schema_discovery.json"}:
        return "inventory"
    if name in {"matrix_summary.json", "webapi_scan_result.json", "repo_scan_result.json"}:
        return "run_result"
    if name in {"artifact_index.json", "enterprise_scorecard.json"}:
        return "run_intelligence"
    if name == "executive_summary.md":
        return "executive_summary"
    if name == "evidence_manifest.json":
        return "evidence_manifest"
    if name == "evidence_signature.json":
        return "evidence_signature"
    if name == "proof_package.json":
        return "proof_package"
    if name.startswith("remediation."):
        return "remediation"
    if name == "regression_result.json" or name == "regression_result.md":
        return "regression_result"
    if name == "report.md" or name == "run_report.md" or suffix == ".html":
        return "report"
    if name.startswith("web3_") or parent == "foundry-tests" or suffix == ".sol":
        return "web3"
    if name.endswith("_exchange.json"):
        return "http_evidence"
    if name == "command_log.json":
        return "command_log"
    return "artifact"


def build_artifact_index(run_dir: Path) -> dict[str, Any]:
    artifacts = list_artifacts(run_dir)
    counts = Counter(item["kind"] for item in artifacts)
    index = {
        "kind": "baloncore_artifact_index",
        "created_at": utc_now(),
        "run_dir": str(run_dir),
        "artifact_count": len(artifacts),
        "artifact_counts": dict(sorted(counts.items())),
        "artifacts": artifacts,
    }
    write_json_file(run_dir / "artifact_index.json", index)
    return index


def summarize_matrix_run(run_dir: Path) -> dict[str, Any]:
    matrix = safe_read_json(run_dir / "matrix_summary.json")
    if not isinstance(matrix, dict):
        return {}

    validations = matrix.get("validations", [])
    if not isinstance(validations, list):
        validations = []

    verified_findings = []
    rejected = 0
    skipped = 0
    suppressed = 0
    severities = Counter()
    classifications = Counter()
    sensitive_fields = 0
    remediation_paths = []

    for validation in validations:
        if not isinstance(validation, dict):
            continue
        classification = str(validation.get("classification", "unknown"))
        classifications[classification] += 1
        if validation.get("suppressed") is True:
            suppressed += 1
        if validation.get("status") == "skipped":
            skipped += 1
            continue
        decision = validation.get("decision", {})
        is_verified = isinstance(decision, dict) and "Verified" in decision
        if isinstance(decision, dict) and "Rejected" in decision:
            rejected += 1
        if is_verified and classification not in {
            "IntendedPrivilegedAccess",
            "IntendedOwnerAccess",
            "BlockedAsExpected",
        }:
            impact = validation.get("impact", {})
            severity = str(impact.get("severity", "Unknown")) if isinstance(impact, dict) else "Unknown"
            severities[severity] += 1
            sensitive = impact.get("sensitive_fields", []) if isinstance(impact, dict) else []
            sensitive_fields += len(sensitive) if isinstance(sensitive, list) else 0
            if validation.get("remediation"):
                remediation_paths.append(str(validation["remediation"]))
            verified_findings.append(
                {
                    "classification": classification,
                    "endpoint": validation.get("endpoint"),
                    "profile": validation.get("profile"),
                    "target": validation.get("target"),
                    "severity": severity,
                    "score": impact.get("score") if isinstance(impact, dict) else None,
                    "artifact_dir": validation.get("artifacts"),
                }
            )

    coverage = matrix.get("coverage", {})
    coverage_summary = coverage.get("summary", {}) if isinstance(coverage, dict) else {}
    return {
        "kind": "webapi_auth_matrix",
        "base_url": matrix.get("base_url"),
        "openapi_url": matrix.get("openapi_url"),
        "owner_profile": matrix.get("owner_profile"),
        "matrix_profiles": matrix.get("matrix_profiles", []),
        "verified_findings": len(verified_findings),
        "rejected_validations": rejected,
        "skipped_validations": skipped,
        "suppressed_findings": suppressed,
        "classification_counts": dict(sorted(classifications.items())),
        "severity_counts": dict(sorted(severities.items())),
        "sensitive_fields_exposed": sensitive_fields,
        "remediation_count": len(remediation_paths),
        "remediation_paths": remediation_paths,
        "findings": verified_findings,
        "coverage": coverage_summary,
        "active_requests": matrix.get("active_request_policy", {}),
        "hypotheses": matrix.get("hypothesis_ledger", {}),
    }


def summarize_repo_run(run_dir: Path) -> dict[str, Any]:
    inventory = safe_read_json(run_dir / "repo_inventory.json")
    if not isinstance(inventory, dict):
        return {}
    summary = inventory.get("summary", {})
    files = inventory.get("files", {})
    return {
        "kind": "repo_inventory",
        "root": inventory.get("root"),
        "summary": summary,
        "secret_hits": inventory.get("secret_hits", []),
        "dependency_manifests": files.get("dependency_manifests", []) if isinstance(files, dict) else [],
        "ci_workflows": files.get("ci_workflows", []) if isinstance(files, dict) else [],
        "iac_files": files.get("iac", []) if isinstance(files, dict) else [],
        "web3_files": files.get("web3", []) if isinstance(files, dict) else [],
        "next_actions": inventory.get("next_actions", []),
    }


def summarize_web3_outputs(run_dir: Path) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for path in sorted(run_dir.rglob("web3_analysis.json")):
        analysis = safe_read_json(path)
        if not isinstance(analysis, dict):
            continue
        summary = analysis.get("summary", {})
        project = analysis.get("project", {})
        summaries.append(
            {
                "kind": "web3_analysis",
                "path": str(path),
                "relative_path": path.relative_to(REPO_ROOT).as_posix()
                if REPO_ROOT in path.parents
                else str(path),
                "project_name": project.get("name") if isinstance(project, dict) else None,
                "project_kind": summary.get("project_kind") if isinstance(summary, dict) else None,
                "finding_count": summary.get("finding_count") if isinstance(summary, dict) else None,
                "critical_count": summary.get("critical_count") if isinstance(summary, dict) else None,
                "high_count": summary.get("high_count") if isinstance(summary, dict) else None,
                "invariant_count": summary.get("invariant_count") if isinstance(summary, dict) else None,
                "generated_tests": len(list(path.parent.rglob("*.t.sol"))),
            }
        )
    return summaries


def enterprise_scorecard(
    run_dir: Path,
    run_type: str,
    artifact_index: dict[str, Any],
    matrix_summary: dict[str, Any],
    repo_summary: dict[str, Any],
    web3_summaries: list[dict[str, Any]],
) -> dict[str, Any]:
    counts = artifact_index.get("artifact_counts", {})
    score = 0
    evidence_manifests = int(counts.get("evidence_manifest", 0))
    remediation_count = int(counts.get("remediation", 0))
    proof_packages = int(counts.get("proof_package", 0))
    reports = int(counts.get("report", 0))

    verified_findings = int(matrix_summary.get("verified_findings", 0) or 0)
    secret_hits = int(repo_summary.get("summary", {}).get("secret_hits", 0) or 0) if repo_summary else 0
    web3_findings = sum(int(item.get("finding_count") or 0) for item in web3_summaries)
    generated_tests = sum(int(item.get("generated_tests") or 0) for item in web3_summaries)

    score += 20 if run_type else 0
    score += min(verified_findings * 20, 30)
    score += min(evidence_manifests * 15, 20)
    score += min(remediation_count * 10, 15)
    score += min(proof_packages * 10, 10)
    score += min(reports * 5, 10)
    score += min(generated_tests * 2, 10)
    if repo_summary and secret_hits == 0:
        score += 5
    score = min(score, 100)

    if score >= 80:
        readiness = "investor_demo_ready_local"
    elif score >= 55:
        readiness = "operator_ready_local"
    else:
        readiness = "foundation_needs_more_proof"

    scorecard = {
        "kind": "baloncore_enterprise_scorecard",
        "created_at": utc_now(),
        "run_dir": str(run_dir),
        "run_type": run_type,
        "score": score,
        "readiness": readiness,
        "signals": {
            "verified_webapi_findings": verified_findings,
            "evidence_manifests": evidence_manifests,
            "proof_packages": proof_packages,
            "remediation_artifacts": remediation_count,
            "reports": reports,
            "repo_secret_hits": secret_hits,
            "web3_findings": web3_findings,
            "web3_generated_tests": generated_tests,
        },
        "gaps": [],
    }

    gaps = scorecard["gaps"]
    if verified_findings and not evidence_manifests:
        gaps.append("Verified findings need sealed evidence manifests.")
    if verified_findings and not remediation_count:
        gaps.append("Verified findings need remediation artifacts.")
    if web3_findings and not generated_tests:
        gaps.append("Web3 findings need generated proof tests.")
    if not verified_findings and not web3_findings and not secret_hits:
        gaps.append("Run did not produce high-impact proof signals.")
    return scorecard


def render_executive_summary(
    run_dir: Path,
    run_type: str,
    artifact_index: dict[str, Any],
    matrix_summary: dict[str, Any],
    repo_summary: dict[str, Any],
    web3_summaries: list[dict[str, Any]],
    scorecard: dict[str, Any],
) -> str:
    lines = [
        "# BALONCORE Run Intelligence",
        "",
        f"- Run type: `{run_type}`",
        f"- Run directory: `{run_dir}`",
        f"- Enterprise score: `{scorecard.get('score')}`",
        f"- Readiness: `{scorecard.get('readiness')}`",
        f"- Artifacts indexed: `{artifact_index.get('artifact_count')}`",
        "",
        "## Proof Signals",
        "",
    ]

    signals = scorecard.get("signals", {})
    for key, value in signals.items():
        lines.append(f"- {key.replace('_', ' ').title()}: `{value}`")

    if matrix_summary:
        lines.extend(
            [
                "",
                "## Web/API Authorization",
                "",
                f"- Verified findings: `{matrix_summary.get('verified_findings')}`",
                f"- Sensitive fields exposed: `{matrix_summary.get('sensitive_fields_exposed')}`",
                f"- Remediation plans: `{matrix_summary.get('remediation_count')}`",
            ]
        )
        for finding in matrix_summary.get("findings", []):
            lines.append(
                f"- `{finding.get('severity')}` `{finding.get('classification')}` on `{finding.get('endpoint')}` as `{finding.get('profile')}`"
            )

    if repo_summary:
        summary = repo_summary.get("summary", {})
        lines.extend(
            [
                "",
                "## Repository Inventory",
                "",
                f"- Files seen: `{summary.get('files_seen')}`",
                f"- Dependency manifests: `{summary.get('dependency_manifests')}`",
                f"- CI workflows: `{summary.get('ci_workflows')}`",
                f"- IaC files: `{summary.get('iac_files')}`",
                f"- Web3 files: `{summary.get('web3_files')}`",
                f"- Redacted secret hits: `{summary.get('secret_hits')}`",
            ]
        )

    if web3_summaries:
        lines.extend(["", "## Web3 Analysis", ""])
        for item in web3_summaries:
            lines.append(
                f"- `{item.get('project_name')}` findings=`{item.get('finding_count')}` critical=`{item.get('critical_count')}` high=`{item.get('high_count')}` generated_tests=`{item.get('generated_tests')}`"
            )

    gaps = scorecard.get("gaps", [])
    if gaps:
        lines.extend(["", "## Remaining Gaps", ""])
        for gap in gaps:
            lines.append(f"- {gap}")

    lines.append("")
    return "\n".join(lines)


def write_run_intelligence(run_dir: Path, run_type: str) -> dict[str, Any]:
    artifact_index = build_artifact_index(run_dir)
    matrix_summary = summarize_matrix_run(run_dir)
    repo_summary = summarize_repo_run(run_dir)
    web3_summaries = summarize_web3_outputs(run_dir)
    scorecard = enterprise_scorecard(
        run_dir,
        run_type,
        artifact_index,
        matrix_summary,
        repo_summary,
        web3_summaries,
    )
    write_json_file(run_dir / "enterprise_scorecard.json", scorecard)
    (run_dir / "executive_summary.md").write_text("", encoding="utf-8")
    artifact_index = build_artifact_index(run_dir)
    executive_summary = render_executive_summary(
        run_dir,
        run_type,
        artifact_index,
        matrix_summary,
        repo_summary,
        web3_summaries,
        scorecard,
    )
    (run_dir / "executive_summary.md").write_text(executive_summary, encoding="utf-8")
    artifact_index = build_artifact_index(run_dir)
    return {
        "artifact_index": str(run_dir / "artifact_index.json"),
        "enterprise_scorecard": str(run_dir / "enterprise_scorecard.json"),
        "executive_summary": str(run_dir / "executive_summary.md"),
        "score": scorecard["score"],
        "readiness": scorecard["readiness"],
        "signals": scorecard["signals"],
        "artifact_count": artifact_index["artifact_count"],
    }


def preview_artifact(path_value: str) -> dict[str, Any]:
    path = resolve_artifact_path(path_value)
    stat = path.stat()
    max_preview_bytes = 200_000
    preview = {
        "path": str(path),
        "relative_path": path.relative_to(REPO_ROOT).as_posix()
        if REPO_ROOT in path.parents
        else str(path),
        "kind": artifact_kind(path),
        "bytes": stat.st_size,
        "modified_at": dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "truncated": stat.st_size > max_preview_bytes,
        "text": None,
        "json": None,
    }
    if stat.st_size > max_preview_bytes:
        return preview
    if path.suffix.lower() not in {".json", ".md", ".txt", ".log", ".html", ".toml", ".yaml", ".yml"}:
        return preview

    text = path.read_text(encoding="utf-8", errors="replace")
    preview["text"] = text
    if path.suffix.lower() == ".json":
        try:
            preview["json"] = json.loads(text)
        except json.JSONDecodeError:
            preview["json"] = None
    return preview


def job_file(job_id: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", job_id):
        raise ValueError("invalid job id")
    return JOBS_ROOT / f"{job_id}.json"


def write_job_record(record: dict[str, Any]) -> None:
    with JOB_LOCK:
        JOBS_ROOT.mkdir(parents=True, exist_ok=True)
        write_json_file(job_file(str(record["job_id"])), record)


def read_job_record(job_id: str) -> dict[str, Any]:
    path = job_file(job_id)
    record = safe_read_json(path)
    if not isinstance(record, dict):
        raise FileNotFoundError(f"job not found: {job_id}")
    return record


def list_job_records(limit: int = 50) -> list[dict[str, Any]]:
    if not JOBS_ROOT.exists():
        return []
    jobs: list[dict[str, Any]] = []
    files = sorted(JOBS_ROOT.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in files[:limit]:
        record = safe_read_json(path)
        if isinstance(record, dict):
            jobs.append(record)
    return jobs


def create_job(job_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    if job_type not in {"repo_scan", "webapi_scan"}:
        raise ValueError("job type must be repo_scan or webapi_scan")
    require_authorized(payload)
    job_id = f"job-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    record = {
        "job_id": job_id,
        "type": job_type,
        "status": "queued",
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "payload": payload,
        "result": None,
        "error": None,
    }
    write_job_record(record)
    worker = threading.Thread(target=run_job, args=(job_id,), daemon=True)
    worker.start()
    return record


def run_job(job_id: str) -> None:
    record = read_job_record(job_id)
    record["status"] = "running"
    record["started_at"] = utc_now()
    record["updated_at"] = utc_now()
    write_job_record(record)

    try:
        if record["type"] == "repo_scan":
            result = scan_repo(dict(record["payload"]))
        elif record["type"] == "webapi_scan":
            result = scan_webapp(dict(record["payload"]))
        else:
            raise ValueError(f"unsupported job type: {record['type']}")

        record["status"] = "succeeded" if result.get("ok") else "failed"
        record["result"] = {
            "ok": result.get("ok"),
            "run_dir": result.get("run_dir"),
            "run_intelligence": result.get("run_intelligence"),
            "artifact_count": len(result.get("artifact_paths", [])),
        }
        if not result.get("ok"):
            record["error"] = "scan completed with failing command status"
    except Exception as exc:  # noqa: BLE001 - job ledger records failures.
        record["status"] = "failed"
        record["error"] = str(exc)
    finally:
        record["finished_at"] = utc_now()
        record["updated_at"] = utc_now()
        write_job_record(record)


def list_artifacts(root: Path | None = None) -> list[dict[str, Any]]:
    base = root or WORKBENCH_ROOT
    if not base.exists():
        return []
    artifacts: list[dict[str, Any]] = []
    for path in sorted(base.rglob("*"), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True):
        if not path.is_file():
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        artifacts.append(
            {
                "path": str(path),
                "relative_path": path.relative_to(REPO_ROOT).as_posix()
                if REPO_ROOT in path.parents
                else str(path),
                "kind": artifact_kind(path),
                "bytes": stat.st_size,
                "modified_at": dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc)
                .replace(microsecond=0)
                .isoformat(),
            }
        )
        if len(artifacts) >= 300:
            break
    return artifacts


def status_payload() -> dict[str, Any]:
    jobs = list_job_records(limit=20)
    job_counts = Counter(str(job.get("status", "unknown")) for job in jobs)
    return {
        "name": "BALONCORE Workbench",
        "mode": "local-enterprise-workbench",
        "created_at": utc_now(),
        "repo_root": str(REPO_ROOT),
        "workbench_root": str(WORKBENCH_ROOT),
        "jobs_root": str(JOBS_ROOT),
        "network_posture": "bind to 127.0.0.1 by default; active scans require authorized=true",
        "kernel": "Rust CLI validator/proof engine",
        "control_plane": "Python stdlib local server",
        "jobs": {
            "recent_count": len(jobs),
            "status_counts": dict(sorted(job_counts.items())),
        },
        "capabilities": [
            "authorized OpenAPI BOLA/BFLA/missing-auth scan orchestration",
            "local repo inventory with redacted secret detection",
            "Solidity/Web3 project handoff to BALONCORE invariant analysis",
            "artifact discovery for evidence, reports, and command logs",
            "durable local job ledger with run intelligence and enterprise scorecards",
            "explicit operator discipline from reviewed skill-based systems",
        ],
        "enterprise_gap": "This is a local workbench, not yet multi-tenant hosted SaaS.",
    }


def render_index() -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BALONCORE Workbench</title>
  <style>
    :root {{
      color-scheme: light;
      --ink: #171a1f;
      --muted: #667085;
      --line: #d9dee8;
      --panel: #ffffff;
      --page: #f6f8fb;
      --blue: #174ea6;
      --green: #0b6b3a;
      --red: #b42318;
      --amber: #986200;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--page);
      color: var(--ink);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 14px;
    }}
    header {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 18px;
      padding: 18px 24px;
      border-bottom: 1px solid var(--line);
      background: #101820;
      color: #fff;
    }}
    header h1 {{ margin: 0; font-size: 19px; letter-spacing: 0; }}
    header p {{ margin: 3px 0 0; color: #c9d4e5; }}
    main {{ max-width: 1280px; margin: 0 auto; padding: 20px; }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; align-items: start; }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
      box-shadow: 0 1px 2px rgba(16, 24, 40, .04);
    }}
    .panel h2 {{ margin: 0 0 12px; font-size: 15px; }}
    label {{ display: block; color: var(--muted); font-size: 12px; margin: 12px 0 5px; }}
    input, select {{
      width: 100%;
      border: 1px solid #c9d1df;
      border-radius: 6px;
      padding: 9px 10px;
      font: inherit;
      background: #fff;
    }}
    .checkline {{ display: flex; align-items: center; gap: 8px; margin-top: 12px; color: var(--ink); }}
    .checkline input {{ width: auto; }}
    button {{
      border: 0;
      border-radius: 6px;
      padding: 9px 12px;
      font-weight: 700;
      color: #fff;
      background: var(--blue);
      cursor: pointer;
      margin-top: 14px;
    }}
    button.secondary {{ background: #374151; }}
    .status {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 16px;
    }}
    .metric {{
      background: #fff;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
    }}
    .metric span {{ display: block; color: var(--muted); font-size: 12px; }}
    .metric strong {{ display: block; margin-top: 4px; font-size: 18px; }}
    pre {{
      overflow: auto;
      background: #0f1720;
      color: #d9e7ff;
      border-radius: 8px;
      padding: 12px;
      min-height: 260px;
      max-height: 560px;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 8px; text-align: left; vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 700; }}
    .full {{ margin-top: 16px; }}
    .pill {{ display: inline-block; border-radius: 999px; padding: 2px 8px; background: #e8f0fe; color: var(--blue); font-size: 12px; }}
    .warn {{ color: var(--amber); }}
    @media (max-width: 860px) {{
      .grid, .status {{ grid-template-columns: 1fr; }}
      header {{ align-items: flex-start; flex-direction: column; }}
    }}
  </style>
</head>
<body>
  <header>
    <div>
      <h1>BALONCORE Workbench</h1>
      <p>Local enterprise security control plane over the BALONCORE validator kernel.</p>
    </div>
    <span class="pill">localhost only</span>
  </header>
  <main>
    <section class="status">
      <div class="metric"><span>Kernel</span><strong>Rust CLI</strong></div>
      <div class="metric"><span>Control Plane</span><strong>Python</strong></div>
      <div class="metric"><span>Mode</span><strong>Local</strong></div>
      <div class="metric"><span>Auth</span><strong>Required</strong></div>
    </section>

    <section class="grid">
      <form class="panel" id="repoForm">
        <h2>Authorized Local Repo Scan</h2>
        <label for="repoPath">Repository path</label>
        <input id="repoPath" name="path" value="{html.escape(str(REPO_ROOT))}">
        <label class="checkline"><input id="repoAuthorized" type="checkbox" checked> I own or am authorized to test this repository</label>
        <button type="submit">Run Repo Scan</button>
      </form>

      <form class="panel" id="webForm">
        <h2>Authorized Web/API Scan</h2>
        <label for="baseUrl">Base URL</label>
        <input id="baseUrl" value="http://127.0.0.1:3000">
        <label for="openapiUrl">OpenAPI URL</label>
        <input id="openapiUrl" value="http://127.0.0.1:3000/openapi.json">
        <label for="ownerProfile">Owner profile</label>
        <input id="ownerProfile" value="user_b">
        <label class="checkline"><input id="webAuthorized" type="checkbox" checked> I own or am authorized to test this web/API target</label>
        <button type="submit">Run API Auth Matrix</button>
      </form>
    </section>

    <section class="panel full">
      <h2>Durable Job Ledger</h2>
      <button class="secondary" id="refreshJobs" type="button">Refresh Jobs</button>
      <div id="jobs"></div>
    </section>

    <section class="grid full">
      <div class="panel">
        <h2>Result</h2>
        <pre id="output">Loading status...</pre>
      </div>
      <div class="panel">
        <h2>Recent Artifacts</h2>
        <button class="secondary" id="refreshArtifacts" type="button">Refresh Artifacts</button>
        <div id="artifacts"></div>
      </div>
    </section>
  </main>
  <script>
    const output = document.getElementById('output');
    const artifacts = document.getElementById('artifacts');
    const jobs = document.getElementById('jobs');
    function show(value) {{
      output.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
    }}
    async function submitJob(type, payload) {{
      show('Queued. BALONCORE is writing a durable job record and running the validator in the background...');
      const res = await fetch('/api/jobs', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ type, payload }})
      }});
      const data = await res.json();
      show(data);
      await loadJobs();
      await loadArtifacts();
    }}
    async function postJson(url, body) {{
      show('Running. This can take a minute while BALONCORE invokes the validator kernel...');
      const res = await fetch(url, {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify(body)
      }});
      const data = await res.json();
      show(data);
      await loadArtifacts();
    }}
    async function loadStatus() {{
      const res = await fetch('/api/status');
      show(await res.json());
      await loadJobs();
      await loadArtifacts();
    }}
    async function loadJobs() {{
      const res = await fetch('/api/jobs');
      const data = await res.json();
      const rows = (data.jobs || []).slice(0, 20).map(job => {{
        const result = job.result || {{}};
        const intel = result.run_intelligence || {{}};
        return `<tr><td>${{job.job_id}}</td><td>${{job.type}}</td><td>${{job.status}}</td><td>${{intel.score ?? ''}}</td><td>${{intel.readiness ?? ''}}</td><td>${{result.run_dir ?? ''}}</td></tr>`;
      }}).join('');
      jobs.innerHTML = rows
        ? `<table><thead><tr><th>Job</th><th>Type</th><th>Status</th><th>Score</th><th>Readiness</th><th>Run Dir</th></tr></thead><tbody>${{rows}}</tbody></table>`
        : '<p class="warn">No background jobs yet.</p>';
    }}
    async function loadArtifacts() {{
      const res = await fetch('/api/artifacts');
      const data = await res.json();
      const rows = (data.artifacts || []).slice(0, 30).map(item =>
        `<tr><td>${{item.relative_path}}</td><td>${{item.kind}}</td><td>${{item.bytes}}</td><td>${{item.modified_at}}</td></tr>`
      ).join('');
      artifacts.innerHTML = rows
        ? `<table><thead><tr><th>Path</th><th>Kind</th><th>Bytes</th><th>Modified</th></tr></thead><tbody>${{rows}}</tbody></table>`
        : '<p class="warn">No workbench artifacts yet.</p>';
    }}
    document.getElementById('repoForm').addEventListener('submit', async event => {{
      event.preventDefault();
      await submitJob('repo_scan', {{
        authorized: document.getElementById('repoAuthorized').checked,
        path: document.getElementById('repoPath').value
      }});
    }});
    document.getElementById('webForm').addEventListener('submit', async event => {{
      event.preventDefault();
      await submitJob('webapi_scan', {{
        authorized: document.getElementById('webAuthorized').checked,
        base_url: document.getElementById('baseUrl').value,
        openapi_url: document.getElementById('openapiUrl').value,
        owner_profile: document.getElementById('ownerProfile').value
      }});
    }});
    document.getElementById('refreshArtifacts').addEventListener('click', loadArtifacts);
    document.getElementById('refreshJobs').addEventListener('click', loadJobs);
    setInterval(loadJobs, 3000);
    loadStatus();
  </script>
</body>
</html>"""


class WorkbenchHandler(BaseHTTPRequestHandler):
    server_version = "BaloncoreWorkbench/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[{utc_now()}] {self.address_string()} {fmt % args}")

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/":
                html_response(self, render_index())
            elif parsed.path == "/api/status":
                json_response(self, 200, status_payload())
            elif parsed.path == "/api/artifacts":
                json_response(self, 200, {"artifacts": list_artifacts()})
            elif parsed.path == "/api/artifact":
                query = parse_qs(parsed.query)
                path_value = (query.get("path") or [""])[0]
                json_response(self, 200, preview_artifact(path_value))
            elif parsed.path == "/api/jobs":
                json_response(self, 200, {"jobs": list_job_records()})
            elif parsed.path.startswith("/api/jobs/"):
                job_id = parsed.path.rsplit("/", 1)[-1]
                json_response(self, 200, read_job_record(job_id))
            elif parsed.path == "/api/run-intelligence":
                query = parse_qs(parsed.query)
                run_dir_value = (query.get("run_dir") or [""])[0]
                run_dir = resolve_local_path(run_dir_value)
                json_response(
                    self,
                    200,
                    {
                        "artifact_index": safe_read_json(run_dir / "artifact_index.json"),
                        "enterprise_scorecard": safe_read_json(run_dir / "enterprise_scorecard.json"),
                        "executive_summary": (run_dir / "executive_summary.md").read_text(
                            encoding="utf-8"
                        )
                        if (run_dir / "executive_summary.md").exists()
                        else None,
                    },
                )
            else:
                json_response(self, 404, {"ok": False, "error": "not found"})
        except Exception as exc:  # noqa: BLE001 - handler returns structured local error.
            json_response(self, 500, {"ok": False, "error": str(exc)})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            payload = read_json_body(self)
            if parsed.path == "/api/scan/repo":
                json_response(self, 200, scan_repo(payload))
            elif parsed.path == "/api/scan/webapp":
                json_response(self, 200, scan_webapp(payload))
            elif parsed.path == "/api/jobs":
                job_type = str(payload.get("type", ""))
                job_payload = payload.get("payload", {})
                if not isinstance(job_payload, dict):
                    raise ValueError("job payload must be an object")
                json_response(self, 202, create_job(job_type, job_payload))
            else:
                json_response(self, 404, {"ok": False, "error": "not found"})
        except PermissionError as exc:
            json_response(self, 403, {"ok": False, "error": str(exc)})
        except (FileNotFoundError, ValueError) as exc:
            json_response(self, 400, {"ok": False, "error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - keep workbench errors visible.
            json_response(self, 500, {"ok": False, "error": str(exc)})


def serve(host: str, port: int) -> None:
    if host not in {"127.0.0.1", "localhost"}:
        raise SystemExit("Refusing to bind non-local host. Use 127.0.0.1 for the local workbench.")
    WORKBENCH_ROOT.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((host, port), WorkbenchHandler)
    print(f"BALONCORE Workbench running at http://{host}:{port}")
    print(f"Artifacts: {WORKBENCH_ROOT}")
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local BALONCORE workbench.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    serve(args.host, args.port)


if __name__ == "__main__":
    main()
