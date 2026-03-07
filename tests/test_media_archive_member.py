"""
Direct unit tests for MediaAuthenticityAnalyzer._inspect_archive_member().

Covers all five security-scoring branches:
  1. Dangerous extension  → score +5.0, early return
  2. Nested archive       → score +2.0 + recursive score; early return when score ≥ 5.0
  3. Suspicious extension → score +3.0
  4. Safe file            → score 0.0, no warnings
  5. Path-traversal sanitization (member name is cleaned before scoring)

SECURITY STORY: _inspect_archive_member is the single code path that flags
executables hidden inside ZIP/TAR attachments.  Without direct tests a silent
regression (e.g. inverting the early-return, removing an extension, or breaking
sanitize_filename) would eliminate protection for all archive-borne threats.
"""

import unittest
from unittest.mock import MagicMock

from src.modules.media_analyzer import MediaAuthenticityAnalyzer
from src.utils.config import AnalysisConfig


def _make_analyzer() -> MediaAuthenticityAnalyzer:
    config = MagicMock(spec=AnalysisConfig)
    config.check_media_attachments = True
    config.deepfake_detection_enabled = False
    return MediaAuthenticityAnalyzer(config)


class TestInspectArchiveMemberDangerousExtension(unittest.TestCase):
    """Branch: member_lower.endswith(DANGEROUS_EXTENSIONS) → score +5.0, early return."""

    def setUp(self):
        self.analyzer = _make_analyzer()

    def test_exe_returns_score_five_with_warning(self):
        score, warnings = self.analyzer._inspect_archive_member(
            "archive.zip", "payload.exe", lambda: (0.0, [])
        )
        self.assertEqual(score, 5.0)
        self.assertTrue(any("payload.exe" in w for w in warnings))

    def test_bat_returns_score_five_with_warning(self):
        score, warnings = self.analyzer._inspect_archive_member(
            "archive.zip", "run.bat", lambda: (0.0, [])
        )
        self.assertEqual(score, 5.0)
        self.assertTrue(any("run.bat" in w for w in warnings))

    def test_nested_handler_not_called_for_dangerous_extension(self):
        """Early return must skip the nested_handler_fn entirely."""
        handler = MagicMock(return_value=(3.0, ["nested warning"]))
        self.analyzer._inspect_archive_member("archive.zip", "backdoor.exe", handler)
        handler.assert_not_called()


class TestInspectArchiveMemberNestedArchive(unittest.TestCase):
    """Branch: _is_nested_archive(member_lower) → score +2.0 + recursive score."""

    def setUp(self):
        self.analyzer = _make_analyzer()

    def test_zip_member_accumulates_nested_score(self):
        """Inner .zip adds 2.0 + whatever the handler returns."""
        score, warnings = self.analyzer._inspect_archive_member(
            "outer.zip", "inner.zip", lambda: (1.0, ["nested warning"])
        )
        # 2.0 (nested archive) + 1.0 (handler result) = 3.0
        self.assertEqual(score, 3.0)
        self.assertTrue(any("inner.zip" in w for w in warnings))
        self.assertIn("nested warning", warnings)

    def test_nested_archive_early_exit_when_score_reaches_five(self):
        """When nested score pushes total to ≥ 5.0 the suspicious check is skipped.

        This test temporarily treats ``.zip`` as a suspicious extension so that the
        same member name (``inner.zip``) qualifies as both a nested archive and a
        suspicious file. If the early-return after the nested-archive recursion is
        broken, the suspicious-extension branch would run and push the score above
        5.0 and emit a "suspicious file" warning.
        """
        original_suspicious = self.analyzer.SUSPICIOUS_EXTENSIONS
        try:
            # Force overlap: ".zip" is both a nested archive and a suspicious extension.
            self.analyzer.SUSPICIOUS_EXTENSIONS = (".zip",)
            score, warnings = self.analyzer._inspect_archive_member(
                "outer.zip", "inner.zip", lambda: (3.0, [])
            )
            # 2.0 (nested archive) + 3.0 (handler) = 5.0; suspicious branch must NOT run.
            self.assertEqual(score, 5.0)
            # If suspicious branch ran, we would expect a "suspicious file" style warning.
            self.assertFalse(any("suspicious file" in w.lower() for w in warnings))
        finally:
            # Restore original configuration so other tests are unaffected.
            self.analyzer.SUSPICIOUS_EXTENSIONS = original_suspicious
    def test_nested_handler_called_exactly_once(self):
        handler = MagicMock(return_value=(0.0, []))
        self.analyzer._inspect_archive_member("outer.zip", "inner.zip", handler)
        handler.assert_called_once()


class TestInspectArchiveMemberSuspiciousExtension(unittest.TestCase):
    """Branch: member_lower.endswith(SUSPICIOUS_EXTENSIONS) → score +3.0."""

    def setUp(self):
        self.analyzer = _make_analyzer()

    def test_html_returns_score_three(self):
        score, warnings = self.analyzer._inspect_archive_member(
            "archive.zip", "phish.html", lambda: (0.0, [])
        )
        self.assertEqual(score, 3.0)
        self.assertTrue(any("phish.html" in w for w in warnings))

    def test_docm_returns_score_three(self):
        score, warnings = self.analyzer._inspect_archive_member(
            "archive.zip", "invoice.docm", lambda: (0.0, [])
        )
        self.assertEqual(score, 3.0)
        self.assertTrue(any("invoice.docm" in w for w in warnings))

    def test_safe_file_returns_zero_score_no_warnings(self):
        score, warnings = self.analyzer._inspect_archive_member(
            "archive.zip", "readme.txt", lambda: (0.0, [])
        )
        self.assertEqual(score, 0.0)
        self.assertEqual(warnings, [])


class TestInspectArchiveMemberPathTraversal(unittest.TestCase):
    """Sanitization: member name is cleaned before extension checks and logging."""

    def setUp(self):
        self.analyzer = _make_analyzer()

    def test_path_traversal_without_dangerous_extension_scores_zero(self):
        """../../etc/passwd has no dangerous/suspicious extension after sanitization."""
        score, warnings = self.analyzer._inspect_archive_member(
            "archive.zip", "../../etc/passwd", lambda: (0.0, [])
        )
        self.assertEqual(score, 0.0)
        # The sanitized name must not expose the traversal path in any warning
        for w in warnings:
            self.assertNotIn("../", w)

    def test_path_traversal_with_exe_extension_scores_five_and_sanitizes_name(self):
        """../evil.exe is dangerous; the warning must not contain '../'."""
        score, warnings = self.analyzer._inspect_archive_member(
            "archive.zip", "../evil.exe", lambda: (0.0, [])
        )
        self.assertEqual(score, 5.0)
        self.assertTrue(len(warnings) > 0)
        for w in warnings:
            self.assertNotIn("../", w)
        # The base filename (without traversal) should appear in the warning
        self.assertTrue(any("evil.exe" in w for w in warnings))


if __name__ == "__main__":
    unittest.main()
