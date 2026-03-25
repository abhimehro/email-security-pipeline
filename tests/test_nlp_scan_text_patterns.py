"""
Unit tests for NLPThreatAnalyzer._scan_text_patterns().

SECURITY STORY: _scan_text_patterns is called on every email. The two-phase
optimization and the heterogeneous AU list structure are both regression-prone:

  Phase 1 (fast gate): simple_master_pattern.search(part)
  Phase 2 (full scan): master_pattern.finditer(part) → matches_by_category

A bug in the simple_master_pattern gate (e.g. match vs search) would silently
produce zero pattern detections for all emails.  The AU category must store
lists of matched strings (not counts) because _detect_authority_impersonation
compares match text against the sender domain; changing AU to use ints would
silently break impersonation scoring.
"""

import unittest

from src.modules.nlp_analyzer import NLPThreatAnalyzer


class MockConfig:
    def __init__(self):
        self.check_social_engineering = True
        self.check_urgency_markers = True
        self.check_authority_impersonation = True
        self.check_psychological_triggers = True
        self.nlp_threshold = 0.5
        self.nlp_model = "distilbert-base-uncased"


class _BaseNLPScanTest(unittest.TestCase):
    """Shared setUp that disables the optional ML model for deterministic tests."""

    def setUp(self):
        self.analyzer = NLPThreatAnalyzer(MockConfig())
        # Disable ML model: avoids torch/transformers dependency in unit tests
        self.analyzer.model = None
        self.analyzer.tokenizer = None


# ---------------------------------------------------------------------------
# Empty / falsy input
# ---------------------------------------------------------------------------


class TestScanTextPatternsEmpty(_BaseNLPScanTest):
    """_scan_text_patterns must return sane defaults for empty or falsy input."""

    def _assert_empty_result(self, matches, exc_count, caps_count):
        self.assertEqual(exc_count, 0)
        self.assertEqual(caps_count, 0)
        for key in ("SE", "UG", "AU", "PS"):
            self.assertIn(key, matches, f"Key '{key}' must always be present")
            self.assertEqual(len(matches[key]), 0, f"Category '{key}' must be empty")

    def test_empty_list_returns_zeros_and_all_keys(self):
        result = self.analyzer._scan_text_patterns([])
        self._assert_empty_result(*result)

    def test_falsy_parts_are_skipped(self):
        # None and "" are both falsy — neither should affect counts or matches
        result = self.analyzer._scan_text_patterns([None, ""])
        self._assert_empty_result(*result)


# ---------------------------------------------------------------------------
# Exclamation and CAPS-word counting
# ---------------------------------------------------------------------------


class TestScanTextPatternsCounts(_BaseNLPScanTest):
    """Tests for the two simple counters returned alongside matches."""

    def test_exclamation_count(self):
        _, exc_count, _ = self.analyzer._scan_text_patterns(
            ["Hello! Are you there! Please respond!"]
        )
        self.assertEqual(exc_count, 3)

    def test_caps_words_count_requires_four_char_minimum(self):
        # CAPS_WORDS_PATTERN: r'\b[A-Z]{4,}\b'
        # "FREE" (4 chars) ✓  "MONEY" (5 chars) ✓  "NOW" (3 chars) ✗
        _, _, caps_count = self.analyzer._scan_text_patterns(["FREE MONEY NOW"])
        self.assertEqual(caps_count, 2)

    def test_no_keywords_gives_zero_counts_and_empty_matches(self):
        neutral = "The weather is pleasant outside. Let us go for a walk today."
        matches, exc_count, caps_count = self.analyzer._scan_text_patterns([neutral])
        self.assertEqual(exc_count, 0)
        self.assertEqual(caps_count, 0)
        for key in ("SE", "UG", "AU", "PS"):
            self.assertEqual(len(matches[key]), 0)


# ---------------------------------------------------------------------------
# Category population and value types
# ---------------------------------------------------------------------------


class TestScanTextPatternsCategories(_BaseNLPScanTest):
    """Tests for match categorisation and the critical heterogeneous value types."""

    def test_se_pattern_populates_se_with_int_counts(self):
        # "verify your account" → SE_0 ("Account verification request"), count += 1
        matches, _, _ = self.analyzer._scan_text_patterns(
            ["Please verify your account immediately."]
        )
        self.assertGreater(len(matches["SE"]), 0)
        # SE entries must be ints (not lists)
        for val in matches["SE"].values():
            self.assertIsInstance(val, int)
        # AU must remain untouched by this input
        self.assertEqual(len(matches["AU"]), 0)

    def test_au_pattern_stores_list_of_matched_strings(self):
        # "paypal" → AU_0 ("Authority entity mention")
        # CRITICAL: AU values are lists, not counts, so _detect_authority_impersonation
        # can compare the actual match string against the sender domain.
        matches, _, _ = self.analyzer._scan_text_patterns(
            ["Please log in to your paypal account."]
        )
        self.assertGreater(len(matches["AU"]), 0)
        for val in matches["AU"].values():
            self.assertIsInstance(
                val,
                list,
                "AU values must be lists (not int) to guard " "impersonation scoring",
            )
            self.assertGreater(len(val), 0)
        # The matched text itself must be present (case-insensitive check)
        all_au_matches = [s.lower() for lst in matches["AU"].values() for s in lst]
        self.assertIn("paypal", all_au_matches)

    def test_se_and_au_populated_independently(self):
        # "security alert" → SE; "paypal" → AU
        matches, _, _ = self.analyzer._scan_text_patterns(
            ["security alert from paypal about your account"]
        )
        self.assertGreater(len(matches["SE"]), 0)
        self.assertGreater(len(matches["AU"]), 0)
        # Value types must not bleed across categories
        for val in matches["SE"].values():
            self.assertIsInstance(val, int)
        for val in matches["AU"].values():
            self.assertIsInstance(val, list)

    def test_counts_accumulate_across_parts(self):
        # Two separate parts each containing a UG keyword — totals must add up
        matches, _, _ = self.analyzer._scan_text_patterns(
            ["This is urgent!", "Another urgent matter."]
        )
        ug_total = sum(matches["UG"].values())
        self.assertGreaterEqual(ug_total, 2)


# ---------------------------------------------------------------------------
# Two-phase optimisation gate
# ---------------------------------------------------------------------------


class TestScanTextPatternsTwoPhase(_BaseNLPScanTest):
    """Confirms that the fast simple_master_pattern gate short-circuits correctly."""

    def test_neutral_text_bypasses_named_group_scan(self):
        # None of the 20 patterns appear in this text.
        # simple_master_pattern.search() must return None →
        #   the master_pattern.finditer loop is never entered →
        #   matches_by_category stays empty for all categories.
        neutral = "The weather is pleasant outside. Let us go for a walk today."
        matches, _, _ = self.analyzer._scan_text_patterns([neutral])
        for key in ("SE", "UG", "AU", "PS"):
            self.assertEqual(
                len(matches[key]),
                0,
                f"Category '{key}' should be empty when simple_master_pattern "
                f"finds no keywords (two-phase gate regression)",
            )


if __name__ == "__main__":
    unittest.main()
