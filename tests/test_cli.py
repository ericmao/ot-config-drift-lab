"""End-to-end tests for the configuration drift command-line interface."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "check_drift.py"


class DriftCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.directory = Path(self.temporary_directory.name)

        config = {
            "network_settings": {
                "auth_required": True,
                "modbus_port": 502,
            },
            "security_policies": {"remote_access": False},
        }
        self.baseline = {
            "schema_version": 1,
            "asset_id": "PLC_Runtime_Virtual_01",
            "captured_at": "2026-09-30T09:00:00Z",
            "source": "test_fixture",
            "config": config,
        }
        self.observed = {
            "schema_version": 1,
            "asset_id": "PLC_Runtime_Virtual_01",
            "observed_at": "2026-09-30T10:00:00Z",
            "source": "test_fixture",
            "config": copy.deepcopy(config),
        }
        self.policy = {
            "schema_version": 1,
            "default_severity": "medium",
            "rules": [
                {
                    "id": "auth-disabled",
                    "path": "/network_settings/auth_required",
                    "severity": "high",
                    "when_after": False,
                    "title": "Authentication control disabled",
                    "rationale": "Investigate whether this change was approved.",
                    "references": [],
                }
            ],
        }
        self.approvals = {"schema_version": 1, "changes": []}

    def invoke(self, extra_args: list[str] | None = None) -> tuple[subprocess.CompletedProcess[str], dict | None]:
        inputs = {
            "baseline": self.baseline,
            "observed": self.observed,
            "policy": self.policy,
            "approvals": self.approvals,
        }
        paths = {}
        for name, payload in inputs.items():
            path = self.directory / f"{name}.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            paths[name] = path

        process = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--baseline",
                str(paths["baseline"]),
                "--observed",
                str(paths["observed"]),
                "--policy",
                str(paths["policy"]),
                "--approvals",
                str(paths["approvals"]),
                "--json",
            ] + (extra_args or []),
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        try:
            result = json.loads(process.stdout)
        except json.JSONDecodeError:
            result = None
        return process, result

    def disable_auth(self) -> None:
        self.observed["config"]["network_settings"]["auth_required"] = False

    def matching_approval(self) -> dict:
        return {
            "ticket_id": "CHG-2026-001",
            "asset_id": "PLC_Runtime_Virtual_01",
            "path": "/network_settings/auth_required",
            "before": True,
            "after": False,
            "valid_from": "2026-09-30T09:30:00Z",
            "valid_until": "2026-09-30T10:30:00Z",
            "status": "approved",
        }

    def test_identical_snapshots_are_ok(self) -> None:
        process, result = self.invoke()
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIsNotNone(result, process.stdout)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["findings"], [])

    def test_nested_auth_change_is_unapproved_drift(self) -> None:
        self.disable_auth()
        process, result = self.invoke()

        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertIsNotNone(result, process.stdout)
        self.assertEqual(result["status"], "drift")
        self.assertEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        self.assertEqual(finding["path"], "/network_settings/auth_required")
        self.assertIs(finding["before"], True)
        self.assertIs(finding["after"], False)
        self.assertEqual(finding["classification"], "unapproved")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["rule_id"], "auth-disabled")
        self.assertTrue(self.baseline["config"]["network_settings"]["auth_required"])

    def test_exact_approval_within_window_is_reported(self) -> None:
        self.disable_auth()
        self.approvals["changes"] = [self.matching_approval()]
        process, result = self.invoke()

        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIsNotNone(result, process.stdout)
        self.assertEqual(result["status"], "approved_change")
        self.assertEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        self.assertEqual(finding["classification"], "approval_match")
        self.assertEqual(finding["ticket_id"], "CHG-2026-001")

    def test_approval_must_match_asset_path_values_and_time(self) -> None:
        self.disable_auth()
        mismatches = {
            "asset": {"asset_id": "Other_PLC"},
            "path": {"path": "/security_policies/remote_access"},
            "before": {"before": False},
            "after": {"after": True},
            "not_yet_valid": {"valid_from": "2026-09-30T10:01:00Z"},
            "expired": {"valid_until": "2026-09-30T09:59:00Z"},
        }
        for case, changes in mismatches.items():
            with self.subTest(case=case):
                approval = self.matching_approval()
                approval.update(changes)
                self.approvals["changes"] = [approval]
                process, result = self.invoke()
                self.assertEqual(process.returncode, 2, process.stderr)
                self.assertIsNotNone(result, process.stdout)
                self.assertEqual(result["status"], "drift")
                self.assertEqual(result["findings"][0]["classification"], "unapproved")

    def test_asset_mismatch_between_snapshots_is_invalid(self) -> None:
        self.observed["asset_id"] = "Other_PLC"
        process, _ = self.invoke()
        self.assertEqual(process.returncode, 3)
        self.assertTrue(process.stderr.strip())

    def test_added_and_removed_keys_are_reported(self) -> None:
        del self.observed["config"]["network_settings"]["modbus_port"]
        del self.observed["config"]["security_policies"]["remote_access"]
        self.observed["config"]["network_settings"]["new_setting"] = "enabled"

        process, result = self.invoke()
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertIsNotNone(result, process.stdout)
        self.assertEqual(result["status"], "drift")
        self.assertEqual(
            {finding["path"] for finding in result["findings"]},
            {
                "/network_settings/modbus_port",
                "/security_policies/remote_access",
                "/network_settings/new_setting",
            },
        )
        self.assertTrue(
            all(finding["classification"] == "unapproved" for finding in result["findings"])
        )

    def test_invalid_observation_timestamp_is_rejected(self) -> None:
        self.observed["observed_at"] = "not-a-timestamp"
        process, _ = self.invoke()
        self.assertEqual(process.returncode, 3)
        self.assertTrue(process.stderr.strip())

    def test_nonfinite_age_limit_is_rejected(self) -> None:
        for invalid in ("nan", "inf", "-inf"):
            with self.subTest(invalid=invalid):
                process, _ = self.invoke([f"--max-age-seconds={invalid}"])
                self.assertEqual(process.returncode, 3)
                self.assertIn("finite", process.stderr)

    def test_removing_parent_preserves_leaf_change_paths(self) -> None:
        del self.observed["config"]["network_settings"]
        process, result = self.invoke()
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertIsNotNone(result, process.stdout)
        self.assertEqual(
            {finding["path"] for finding in result["findings"]},
            {"/network_settings/auth_required", "/network_settings/modbus_port"},
        )
        self.assertTrue(all(finding["change_type"] == "removed" for finding in result["findings"]))

    def test_replacing_parent_with_null_preserves_leaf_change_paths(self) -> None:
        self.observed["config"]["network_settings"] = None
        process, result = self.invoke()
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertIsNotNone(result, process.stdout)
        self.assertIn(
            "/network_settings/auth_required",
            {finding["path"] for finding in result["findings"]},
        )
        self.assertIn(
            "/network_settings",
            {finding["path"] for finding in result["findings"]},
        )

    def test_boolean_schema_version_is_rejected(self) -> None:
        self.baseline["schema_version"] = True
        process, _ = self.invoke()
        self.assertEqual(process.returncode, 3)
        self.assertIn("schema_version", process.stderr)


if __name__ == "__main__":
    unittest.main()
