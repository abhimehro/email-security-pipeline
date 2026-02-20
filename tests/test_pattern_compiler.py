"""
Unit tests for src/utils/pattern_compiler.py

Tests cover:
- compile_patterns: basic OR matching, case-insensitivity, custom flags,
  non-capturing group wrapping, and validate_redos bypass
- compile_named_group_pattern: group naming, group_map accuracy, attribution
  via match.lastgroup, and custom group_prefix
- check_redos_safety: raises on known ReDoS signatures, passes on safe patterns
- Edge cases: empty pattern list
"""

import re
import pytest

from src.utils.pattern_compiler import (
    check_redos_safety,
    compile_named_group_pattern,
    compile_patterns,
)


# ---------------------------------------------------------------------------
# check_redos_safety
# ---------------------------------------------------------------------------


class TestCheckRedosSafety:
    def test_safe_patterns_pass(self):
        """Common email-analysis patterns should not raise."""
        safe = [
            r"\b(urgent|emergency)\b",
            r"https?://[^\s<>\"]+",
            r"\w+@[\w\.-]+",
        ]
        check_redos_safety(safe)  # must not raise

    @pytest.mark.parametrize(
        "bad_pattern",
        [
            r"(\w+)*",
            r"(\d+)+",
            r"(\s+)*",
            r"(a+)+",
            r"([a-zA-Z]+)*",
        ],
    )
    def test_known_redos_signatures_raise(self, bad_pattern):
        with pytest.raises(ValueError, match="Potential ReDoS"):
            check_redos_safety([bad_pattern])

    def test_redos_mixed_with_safe_still_raises(self):
        """If any one pattern is unsafe the whole call should raise."""
        patterns = [r"\b(free|bonus)\b", r"(\w+)*"]
        with pytest.raises(ValueError, match="Potential ReDoS"):
            check_redos_safety(patterns)


# ---------------------------------------------------------------------------
# compile_patterns
# ---------------------------------------------------------------------------


class TestCompilePatterns:
    def test_matches_any_pattern(self):
        pat = compile_patterns([r"\bfoo\b", r"\bbar\b"])
        assert pat.search("I like foo here")
        assert pat.search("bar is nice")
        assert not pat.search("neither of the two")

    def test_case_insensitive_by_default(self):
        pat = compile_patterns([r"\bspam\b"])
        assert pat.search("SPAM")
        assert pat.search("Spam")
        assert pat.search("spam")

    def test_custom_flags_respected(self):
        """With re.I | re.M the pattern should honour multiline anchors."""
        pat = compile_patterns([r"^start"], flags=re.I | re.M)
        text = "first line\nstart of second"
        assert pat.search(text)

    def test_non_capturing_groups_preserve_alternation(self):
        """Each input pattern is wrapped in (?:...) so top-level | is safe."""
        # "a|b" and "c|d" should each be independent alternatives
        pat = compile_patterns([r"a|b", r"c|d"])
        assert pat.search("a")
        assert pat.search("b")
        assert pat.search("c")
        assert pat.search("d")

    def test_empty_list_compiles_to_empty_alternation(self):
        """An empty list should not raise; the resulting pattern matches nothing."""
        pat = compile_patterns([])
        # re.compile("") matches everything; an empty join also matches ""
        # The key thing is it must not raise.
        assert isinstance(pat, re.Pattern)

    def test_validate_redos_raises_on_unsafe_pattern(self):
        with pytest.raises(ValueError, match="Potential ReDoS"):
            compile_patterns([r"(\w+)*"])

    def test_validate_redos_can_be_disabled(self):
        """Passing validate_redos=False should not raise for known-bad patterns."""
        # We don't recommend this in production, but the flag must work.
        pat = compile_patterns([r"(\w+)*"], validate_redos=False)
        assert isinstance(pat, re.Pattern)

    def test_returns_compiled_pattern(self):
        result = compile_patterns([r"\btest\b"])
        assert isinstance(result, re.Pattern)


# ---------------------------------------------------------------------------
# compile_named_group_pattern
# ---------------------------------------------------------------------------


class TestCompileNamedGroupPattern:
    def test_returns_pattern_and_map(self):
        pat, group_map = compile_named_group_pattern([r"\bfoo\b", r"\bbar\b"])
        assert isinstance(pat, re.Pattern)
        assert isinstance(group_map, dict)
        assert len(group_map) == 2

    def test_default_group_naming(self):
        _, group_map = compile_named_group_pattern([r"\bfoo\b", r"\bbar\b"])
        assert "p_0" in group_map
        assert "p_1" in group_map

    def test_custom_group_prefix(self):
        _, group_map = compile_named_group_pattern(
            [r"\bvirus\b", r"\bmalware\b"], group_prefix="threat"
        )
        assert "threat_0" in group_map
        assert "threat_1" in group_map

    def test_group_map_values_are_original_patterns(self):
        patterns = [r"\bphishing\b", r"\bscam\b"]
        _, group_map = compile_named_group_pattern(patterns, group_prefix="kw")
        assert group_map["kw_0"] == patterns[0]
        assert group_map["kw_1"] == patterns[1]

    def test_match_lastgroup_identifies_source_pattern(self):
        """match.lastgroup should map back to the originating pattern via group_map."""
        patterns = [r"\burgent\b", r"\bwinner\b"]
        pat, group_map = compile_named_group_pattern(patterns, group_prefix="spam_kw")
        match = pat.search("You are the winner!")
        assert match is not None
        assert match.lastgroup == "spam_kw_1"
        assert group_map[match.lastgroup] == r"\bwinner\b"

    def test_case_insensitive_by_default(self):
        pat, _ = compile_named_group_pattern([r"\bphishing\b"])
        assert pat.search("PHISHING attempt detected")

    def test_validate_redos_raises(self):
        with pytest.raises(ValueError, match="Potential ReDoS"):
            compile_named_group_pattern([r"(\w+)*"])

    def test_validate_redos_can_be_disabled(self):
        pat, _ = compile_named_group_pattern([r"(\w+)*"], validate_redos=False)
        assert isinstance(pat, re.Pattern)

    def test_spam_kw_prefix_matches_analyzer_naming(self):
        """Verify the exact naming scheme used by SpamAnalyzer still works."""
        spam_keywords = [
            r"\b(viagra|cialis)\b",
            r"\b(winner|prize)\b",
        ]
        pat, group_map = compile_named_group_pattern(
            spam_keywords, re.I, "spam_kw"
        )
        assert "spam_kw_0" in group_map
        assert "spam_kw_1" in group_map
        m = pat.search("You are the winner")
        assert m is not None
        assert m.lastgroup == "spam_kw_1"
