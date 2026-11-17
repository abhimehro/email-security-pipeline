"""Unit tests for missing signature validation and strict configuration helpers."""

import unittest
from typing import NamedTuple

from src.modules.media_file_type import (
    _ensure_strict_validation_config,
    _validate_missing_signature,
)


class DummyAnalyzer:
    """Mock class mimicking MediaAuthenticityAnalyzer attributes."""

    MEDIA_EXTENSIONS = (
        ".mp4",
        ".avi",
        ".mov",
        ".wmv",
        ".flv",
        ".mkv",
        ".mp3",
        ".wav",
        ".aac",
        ".flac",
        ".ogg",
        ".m4a",
    )


class ValidationScenario(NamedTuple):
    """Scenario parameters for missing signature validation."""

    filename: str
    expected_score: float
    expected_warning_substr: str


class TestMediaSignatureValidation(unittest.TestCase):
    """Test suite for missing signature validation and strict config caching."""

    def setUp(self):
        """Set up test environment."""
        self.analyzer = DummyAnalyzer()

    def test_ensure_strict_validation_config_initialization(self):
        """Test lazy initialization and caching of strict validation attributes."""

        class IsolatedClass:
            pass

        media_exts = (".mp4", ".mov")
        strict_exts, crit_exts, exts_tuple = _ensure_strict_validation_config(
            IsolatedClass, media_exts
        )

        # Verify initial dictionary content and attributes
        self.assertIn(".mp4", strict_exts)
        self.assertIn(".pdf", strict_exts)
        self.assertIn(".wav", crit_exts)
        self.assertIn(".mp4", crit_exts)
        self.assertNotIn(".pdf", crit_exts)
        self.assertIsInstance(exts_tuple, tuple)
        self.assertEqual(getattr(IsolatedClass, "_STRICT_VALIDATION_EXTS"), strict_exts)
        self.assertEqual(getattr(IsolatedClass, "_CRITICAL_MEDIA_EXTS"), crit_exts)
        self.assertEqual(
            getattr(IsolatedClass, "_STRICT_VALIDATION_EXTS_TUPLE"), exts_tuple
        )

        # Calling again should return cached structures
        cached_strict, cached_crit, cached_tuple = _ensure_strict_validation_config(
            IsolatedClass, media_exts
        )
        self.assertIs(cached_strict, strict_exts)
        self.assertIs(cached_crit, crit_exts)
        self.assertIs(cached_tuple, exts_tuple)

    def test_validate_missing_signature_scenarios(self):
        """Test various file extensions and sanitization edge cases."""
        scenarios = [
            # Critical media files -> 5.0 score
            ValidationScenario("video.mp4", 5.0, "Invalid file signature for .mp4"),
            ValidationScenario("movie.mov", 5.0, "Invalid file signature for .mov"),
            ValidationScenario("audio.wav", 5.0, "Invalid file signature for .wav"),
            ValidationScenario("clip.mkv", 5.0, "Invalid file signature for .mkv"),
            # Non-critical strict files -> 2.0 score
            ValidationScenario("doc.pdf", 2.0, "Invalid file signature for .pdf"),
            ValidationScenario("archive.zip", 2.0, "Invalid file signature for .zip"),
            ValidationScenario("image.png", 2.0, "Invalid file signature for .png"),
            ValidationScenario("binary.exe", 2.0, "Invalid file signature for .exe"),
            # Benign / unmonitored files -> 0.0 score
            ValidationScenario("notes.txt", 0.0, ""),
            ValidationScenario("data.csv", 0.0, ""),
            # Sanitization edge cases
            ValidationScenario("SAMPLE.MP4", 5.0, "Invalid file signature for .mp4"),
            ValidationScenario("video.mp4.", 5.0, "Invalid file signature for .mp4"),
            ValidationScenario("video.mp4\0", 5.0, "Invalid file signature for .mp4"),
            ValidationScenario("doc.pdf   ", 2.0, "Invalid file signature for .pdf"),
        ]

        for scenario in scenarios:
            with self.subTest(filename=scenario.filename):
                score, warning = _validate_missing_signature(
                    self.analyzer, scenario.filename
                )
                self.assertEqual(score, scenario.expected_score)
                if scenario.expected_warning_substr:
                    self.assertIn(scenario.expected_warning_substr, warning)
                else:
                    self.assertEqual(warning, "")

    def test_validate_missing_signature_without_media_extensions(self):
        """Test fallback when instance lacks MEDIA_EXTENSIONS attribute."""

        class MinimalInstance:
            pass

        instance = MinimalInstance()
        # .wav is always in critical extensions even if MEDIA_EXTENSIONS is empty/missing
        score_wav, warning_wav = _validate_missing_signature(instance, "audio.wav")
        self.assertEqual(score_wav, 5.0)
        self.assertIn("Invalid file signature for .wav", warning_wav)

        # .mp4 without MEDIA_EXTENSIONS is treated as non-critical strict (score 2.0)
        # Note: we test on an isolated class to avoid pollution from previous tests
        class FreshClass:
            pass

        fresh_instance = FreshClass()
        score_mp4, warning_mp4 = _validate_missing_signature(fresh_instance, "clip.mp4")
        self.assertEqual(score_mp4, 2.0)
        self.assertIn("Invalid file signature for .mp4", warning_mp4)


if __name__ == "__main__":
    unittest.main()
