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


class TestSupersededPullRequests(unittest.TestCase):
    PRS = (
        '[{"number": 9, "headRefName": "automation/chatgpt-26.917.71314"},'
        ' {"number": 10, "headRefName": "automation/chatgpt-26.924.22138"},'
        ' {"number": 11, "headRefName": "review/chatgpt-26.924.22138"}]'
    )

    def run_step(self, root: Path, list_status: str):
        step = next(s for s in WORKFLOW["jobs"]["update"]["steps"]
                    if s.get("id") == "supersede")
        prs = root / "prs.json"
        prs.write_text(self.PRS)
        closed = root / "closed"
        stub = root / "gh"
        stub.write_text(
            f"#!{shutil.which('bash')}\n"
            'case "$1 $2" in\n'
            '  "pr list")\n'
            '    [ "$TEST_LIST_STATUS" = 0 ] || exit "$TEST_LIST_STATUS"\n'
            '    while [ $# -gt 0 ]; do\n'
            '      [ "$1" = --jq ] && { jq -r "$2" "$TEST_PRS"; exit; }\n'
            '      shift\n'
            '    done\n'
            '    exit 98 ;;\n'
            '  "pr close") printf "%s\\n" "$*" >> "$TEST_CLOSED" ;;\n'
            '  *) exit 99 ;;\n'
            'esac\n'
        )
        stub.chmod(0o755)
        proc = subprocess.run(
            ["bash", "-eu", "-c", step["run"]],
            cwd=root,
            env={"PATH": str(root) + os.pathsep + os.environ["PATH"],
                 "BRANCH": "automation/chatgpt-26.924.22138",
                 "VERSION": "26.924.22138", "PR_NUMBER": "10",
                 "TEST_PRS": str(prs), "TEST_CLOSED": str(closed),
                 "TEST_LIST_STATUS": list_status},
            capture_output=True, text=True,
        )
        return proc, closed

    def test_closes_only_other_automation_branches(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc, closed = self.run_step(Path(tmp), "0")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(closed.read_text().splitlines(), [
                "pr close 9 --delete-branch --comment "
                "Superseded by #10 (26.924.22138).",
            ])

    def test_a_failed_listing_fails_the_step_and_closes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc, closed = self.run_step(Path(tmp), "4")
            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse(closed.exists())


if __name__ == "__main__":
    unittest.main()
