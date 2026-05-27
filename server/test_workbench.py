import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import baloncore_workbench as workbench


class WorkbenchInventoryTests(unittest.TestCase):
    def test_repo_inventory_detects_security_relevant_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "ci.yml").write_text(
                "name: ci\non: [push]\n", encoding="utf-8"
            )
            (root / "contracts").mkdir()
            (root / "contracts" / "Vault.sol").write_text(
                "contract Vault {}\n", encoding="utf-8"
            )
            (root / "infra").mkdir()
            (root / "infra" / "main.tf").write_text(
                'resource "aws_s3_bucket" "logs" {}\n', encoding="utf-8"
            )
            (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            (root / "package.json").write_text('{"scripts":{}}\n', encoding="utf-8")
            fake_key = "AKIA" + "1234567890ABCDEF"
            (root / ".env").write_text(f"AWS_ACCESS_KEY_ID={fake_key}\n", encoding="utf-8")

            out_dir = root / "out"
            result = workbench.scan_repository(root, out_dir)

            self.assertEqual(result["summary"]["secret_hits"], 1)
            self.assertEqual(result["summary"]["ci_workflows"], 1)
            self.assertEqual(result["summary"]["iac_files"], 1)
            self.assertEqual(result["summary"]["web3_files"], 1)
            self.assertEqual(result["summary"]["container_files"], 1)
            self.assertTrue((out_dir / "repo_inventory.json").exists())

            stored = json.loads((out_dir / "repo_inventory.json").read_text(encoding="utf-8"))
            hit = stored["secret_hits"][0]
            self.assertEqual(hit["type"], "aws_access_key_id")
            self.assertNotIn("1234567890ABCDEF", hit["redacted"])

    def test_authorization_gate_rejects_missing_confirmation(self) -> None:
        with self.assertRaises(PermissionError):
            workbench.require_authorized({"authorized": False})

    def test_web3_dispatch_uses_project_root_not_workspace_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "labs" / "protocol"
            (project / "src").mkdir(parents=True)
            (project / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            (project / "src" / "Vault.sol").write_text(
                "contract Vault {}\n", encoding="utf-8"
            )

            out_dir = root / "out"
            inventory = workbench.scan_repository(root, out_dir)
            roots = workbench.web3_project_roots(root, inventory)

            self.assertEqual(roots, [project.resolve()])

    def test_run_intelligence_builds_enterprise_scorecard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            finding_dir = run_dir / "candidate-001" / "user_a"
            finding_dir.mkdir(parents=True)
            (finding_dir / "evidence_manifest.json").write_text("{}", encoding="utf-8")
            (finding_dir / "proof_package.json").write_text("{}", encoding="utf-8")
            (finding_dir / "remediation.md").write_text("# Fix\n", encoding="utf-8")
            (finding_dir / "report.md").write_text("# Finding\n", encoding="utf-8")
            matrix = {
                "base_url": "http://127.0.0.1:3000",
                "openapi_url": "http://127.0.0.1:3000/openapi.json",
                "owner_profile": "user_b",
                "matrix_profiles": ["user_a"],
                "coverage": {"summary": {"tested_endpoints": 1, "endpoints_imported": 2}},
                "active_request_policy": {"used_active_requests": 2, "max_active_requests": 10},
                "validations": [
                    {
                        "classification": "BrokenObjectLevelAuthorization",
                        "endpoint": "GET /api/invoices/{id}",
                        "profile": "user_a",
                        "target": "http://127.0.0.1:3000/api/invoices/inv_2002",
                        "artifacts": str(finding_dir),
                        "decision": {"Verified": {"title": "Broken object-level authorization"}},
                        "impact": {
                            "severity": "High",
                            "score": 90,
                            "sensitive_fields": [{"path": "$.owner_email"}],
                        },
                        "remediation": str(finding_dir / "remediation.md"),
                    }
                ],
            }
            (run_dir / "matrix_summary.json").write_text(
                json.dumps(matrix), encoding="utf-8"
            )

            intelligence = workbench.write_run_intelligence(run_dir, "webapi_scan")

            self.assertGreaterEqual(intelligence["score"], 80)
            self.assertEqual(intelligence["signals"]["verified_webapi_findings"], 1)
            self.assertTrue((run_dir / "artifact_index.json").exists())
            self.assertTrue((run_dir / "enterprise_scorecard.json").exists())
            self.assertTrue((run_dir / "executive_summary.md").exists())

    def test_artifact_kind_classifies_core_outputs(self) -> None:
        self.assertEqual(workbench.artifact_kind(Path("evidence_manifest.json")), "evidence_manifest")
        self.assertEqual(workbench.artifact_kind(Path("remediation.md")), "remediation")
        self.assertEqual(workbench.artifact_kind(Path("web3_analysis.json")), "web3")

    def test_artifact_preview_is_restricted_to_workbench(self) -> None:
        with self.assertRaises(ValueError):
            workbench.preview_artifact("/private/tmp/not-a-baloncore-artifact.json")

    def test_artifact_preview_reads_json_artifact(self) -> None:
        workbench.WORKBENCH_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=workbench.WORKBENCH_ROOT) as tmp:
            artifact = Path(tmp) / "enterprise_scorecard.json"
            artifact.write_text('{"score":90}', encoding="utf-8")

            preview = workbench.preview_artifact(str(artifact))

            self.assertEqual(preview["kind"], "run_intelligence")
            self.assertEqual(preview["json"]["score"], 90)
            self.assertIn('"score":90', preview["text"])

    def test_job_file_rejects_path_traversal(self) -> None:
        with self.assertRaises(ValueError):
            workbench.job_file("../escape")

    def test_output_dir_must_stay_inside_project(self) -> None:
        with self.assertRaises(ValueError):
            workbench.resolve_output_dir({"out_dir": "/private/tmp/outside-baloncore"}, Path("unused"))


if __name__ == "__main__":
    unittest.main()
