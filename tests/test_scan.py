import unittest
import shutil
import tempfile
from pathlib import Path

from agent_repo_safety_check.scanner import run_scan


class ScanTests(unittest.TestCase):
    def test_sample_scan_reports_expected_categories(self) -> None:
        source = Path("samples/risky-node-project").resolve()
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "risky-node-project"
            shutil.copytree(source, target)
            sentinel = "sample-redaction-value"
            (target / ".env.local").write_text(f"DO_NOT_REPORT_THIS_VALUE={sentinel}", encoding="utf-8")
            (target / "secrets-backup.7z").write_text("dummy archive marker", encoding="utf-8")

            result = run_scan(target, "2026-05-20", profile="oss")
            titles = [finding.title for finding in result.findings]
            all_evidence = "\n".join(finding.evidence for finding in result.findings)

            self.assertEqual(result.profile, "oss")
            self.assertTrue(any("Read-only scan completed" in title for title in titles))
            self.assertTrue(any("npm lifecycle script" in title for title in titles))
            self.assertTrue(any("VS Code task runs on folder open" in title for title in titles))
            self.assertTrue(any("remote script execution" in title for title in titles))
            self.assertTrue(any("pull_request_target" in title for title in titles))
            self.assertTrue(any("broad write permission" in title for title in titles))
            self.assertTrue(any("mutable action reference" in title for title in titles))
            self.assertTrue(any("floating version" in title for title in titles))
            self.assertTrue(any("structured config" in title for title in titles))
            self.assertTrue(any("Local archive file exists" in title for title in titles))
            self.assertTrue(any("LICENSE is missing" in title for title in titles))
            self.assertTrue(all(sentinel not in finding.evidence for finding in result.findings))
            self.assertNotIn("do-not-print-sample-token", all_evidence)

    def test_agent_profile_skips_repo_hygiene(self) -> None:
        source = Path("samples/risky-node-project").resolve()
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "risky-node-project"
            shutil.copytree(source, target)

            result = run_scan(target, "2026-05-20")
            titles = [finding.title for finding in result.findings]

            self.assertEqual(result.profile, "agent")
            self.assertEqual(result.checked_items["repo hygiene"], "skipped; use --profile oss")
            self.assertFalse(any("LICENSE is missing" in title for title in titles))


if __name__ == "__main__":
    unittest.main()
