"""
Unit tests for NLPThreatAnalyzer._detect_social_engineering and
._detect_authority_impersonation.

SECURITY STORY: _detect_authority_impersonation applies a 5× higher score
(2.5 vs 0.5) when the authority keyword does NOT appear in the sender domain.
A regression in the SENDER_DOMAIN_PATTERN regex would silently lower scores
for impersonation attacks by 5×, allowing them to slip below alert thresholds.
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


class _BaseNLPTest(unittest.TestCase):
    """Shared setUp that disables optional ML model for deterministic tests."""

    def setUp(self):
        self.analyzer = NLPThreatAnalyzer(MockConfig())
        self.analyzer.model = None
        self.analyzer.tokenizer = None


class TestDetectSocialEngineering(_BaseNLPTest):

    def test_empty_counts_returns_zero(self):
        score, indicators = self.analyzer._detect_social_engineering({})
        self.assertEqual(score, 0.0)
        self.assertEqual(indicators, [])

    def test_single_keyword_scores_two_per_occurrence(self):
        # SECURITY STORY: social-engineering keywords carry the highest weight
        # (×2.0) so that a single match still meaningfully raises the threat score.
        score, indicators = self.analyzer._detect_social_engineering(
            {"Phishing keyword": 1}
        )
        self.assertAlmostEqual(score, 2.0)
        self.assertEqual(len(indicators), 1)
        self.assertIn("Phishing keyword", indicators[0])

    def test_multiple_keywords_accumulate_score(self):
        # 2 occurrences of A (→4.0) + 3 occurrences of B (→6.0) = 10.0
        counts = {"Keyword A": 2, "Keyword B": 3}
        score, indicators = self.analyzer._detect_social_engineering(counts)
        self.assertAlmostEqual(score, 10.0)
        self.assertEqual(len(indicators), 2)


class TestDetectAuthorityImpersonation(_BaseNLPTest):
    def test_empty_matches_returns_zero(self):
        score, indicators = self.analyzer._detect_authority_impersonation(
            "user@example.com", {}
        )
        self.assertEqual(score, 0.0)
        self.assertEqual(indicators, [])

    def test_match_text_in_sender_domain_gives_low_score(self):
        # SECURITY STORY: "paypal" IS in paypal.com → legitimate sender context
        # → low score (×0.5) and no "domain mismatch" indicator.
        matches_by_desc = {"Authority entity mention": ["paypal"]}
        score, indicators = self.analyzer._detect_authority_impersonation(
            "support@paypal.com", matches_by_desc
        )
        self.assertAlmostEqual(score, 0.5)
        self.assertFalse(any("domain mismatch" in ind for ind in indicators))

    def test_match_text_absent_from_sender_domain_gives_high_score(self):
        # SECURITY STORY: "paypal" NOT in attacker.com → impersonation attempt
        # → high score (×2.5) and "domain mismatch" indicator.
        matches_by_desc = {"Authority entity mention": ["paypal"]}
        score, indicators = self.analyzer._detect_authority_impersonation(
            "support@attacker.com", matches_by_desc
        )
        self.assertAlmostEqual(score, 2.5)
        self.assertTrue(any("domain mismatch" in ind for ind in indicators))

    def test_multiple_mismatching_matches_scale_score(self):
        # Three mismatching match texts → 3 × 2.5 = 7.5
        matches_by_desc = {
            "Authority entity mention": ["paypal", "amazon", "microsoft"]
        }
        score, indicators = self.analyzer._detect_authority_impersonation(
            "billing@evil.com", matches_by_desc
        )
        self.assertAlmostEqual(score, 7.5)
        self.assertTrue(any("domain mismatch" in ind for ind in indicators))

    def test_no_extractable_domain_treated_as_mismatch(self):
        # SECURITY STORY: a sender string with no "@domain" means the domain
        # cannot be verified. Any authority claim should be treated as suspicious.
        matches_by_desc = {"Authority title": ["ceo"]}
        score, indicators = self.analyzer._detect_authority_impersonation(
            "nodomain", matches_by_desc
        )
        self.assertAlmostEqual(score, 2.5)
        self.assertTrue(any("domain mismatch" in ind for ind in indicators))


if __name__ == "__main__":
    unittest.main()
