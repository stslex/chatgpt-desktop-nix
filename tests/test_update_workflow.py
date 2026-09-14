"""Exercise the workflow's actual credential selection and early-failure shell."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/update.yml").read_text())


class TestUpdaterCredentials(unittest.TestCase):
    def test_complete_absent_and_partial_credentials(self):
        step = next(s for s in WORKFLOW["jobs"]["update"]["steps"]
                    if s.get("id") == "auth")
        for app_id, has_key, mode, status in (
            ("", "false", "github-token", 0),
            ("1234", "true", "app", 0),
            ("1234", "false", None, 1),
            ("", "true", None, 1),
        ):
            with self.subTest(app_id=app_id, has_key=has_key), \
                    tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / "output"
                proc = subprocess.run(
                    ["bash", "-eu", "-c", step["run"]],
                    env={"PATH": os.environ["PATH"], "GITHUB_OUTPUT": str(output),
                         "UPDATER_APP_ID": app_id,
                         "UPDATER_APP_KEY_CONFIGURED": has_key},
                    capture_output=True, text=True,
                )
                self.assertEqual(proc.returncode, status, proc.stderr)
                if mode:
                    self.assertEqual(output.read_text(), f"mode={mode}\n")
                else:
                    self.assertFalse(output.exists())
                    self.assertIn("::error", proc.stdout)


class TestEarlyFailureReporting(unittest.TestCase):
    def test_missing_version_skips_reporting_but_real_reporter_errors_propagate(self):
        step = WORKFLOW["jobs"]["report-failure"]["steps"][-1]
        script = step["run"].replace("${{ github.repository }}", "owner/repo")
        for version, reporter_status, expected_status in (
            ("", "23", 0),
            ("26.820.71523", "0", 0),
            ("26.820.71523", "23", 23),
        ):
            with self.subTest(version=version, reporter_status=reporter_status), \
                    tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                trace = root / "arguments"
                stub = root / "python3"
                stub.write_text(
                    f"#!{shutil.which('bash')}\n"
                    'printf "%s\\n" "$@" > "$TEST_ARGS"\n'
                    'exit "$TEST_STATUS"\n'
                )
                stub.chmod(0o755)
                proc = subprocess.run(
                    ["bash", "-eu", "-c", script],
                    env={"PATH": tmp + os.pathsep + os.environ["PATH"],
                         "VERSION": version, "KIND": "trust", "RUN_URL": "test-run",
                         "TEST_ARGS": str(trace), "TEST_STATUS": reporter_status},
                    capture_output=True, text=True,
                )
                self.assertEqual(proc.returncode, expected_status, proc.stderr)
                if version:
                    self.assertEqual(trace.read_text().splitlines(), [
                        "tools/report_failure.py", "--repo", "owner/repo",
                        "--version", version, "--kind", "trust", "--run-url", "test-run",
                    ])
                else:
                    self.assertFalse(trace.exists())
                    self.assertIn("No candidate to report", proc.stdout)


if __name__ == "__main__":
    unittest.main()
