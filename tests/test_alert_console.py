"""Unit tests for alert console media rendering (src/modules/alert_console.py).

Tests print_media_details and its handling of:
- Safe attachments fallback when analysis is empty or lists are empty
- Rendering all warning categories with appropriate titles and bullets
- Truncation using max_media threshold
- Partial warning categories
- Graceful handling of None values
"""

import sys
import unittest
from io import StringIO
from pathlib import Path
from typing import Dict, List, Optional
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.modules.alert_console import print_media_details
from src.utils.colors import Colors


class TestPrintMediaDetails(unittest.TestCase):
    """Unit tests for print_media_details."""

    def _render(
        self,
        media_analysis: Dict,
        risk_color: str = "\033[91m",
        max_media: int = 3,
        colorize_side_effect: bool = False,
    ) -> str:
        """Invoke print_media_details and return captured stdout string."""
        captured = StringIO()
        if colorize_side_effect:
            with (
                patch("sys.stdout", captured),
                patch.object(
                    Colors,
                    "colorize",
                    side_effect=lambda text, code: f"{code}{text}\033[0m",
                ),
            ):
                print_media_details(media_analysis, risk_color, max_media)
        else:
            with patch("sys.stdout", captured):
                print_media_details(media_analysis, risk_color, max_media)
        return captured.getvalue()

    def test_print_media_details_safe_attachments_when_empty(self) -> None:
        """An empty analysis dictionary prints the safe attachments fallback."""
        output = self._render({})
        self.assertIn("✔ Attachments appear safe", output)
        self.assertNotIn("File Warnings:", output)
        self.assertNotIn("Suspicious Attachments:", output)
        self.assertNotIn("Size Anomalies:", output)
        self.assertNotIn("Potential Deepfakes:", output)

    def test_print_media_details_safe_attachments_when_empty_lists(self) -> None:
        """Dictionaries containing only empty indicator lists render the safe message."""
        analysis: Dict[str, List[str]] = {
            "file_type_warnings": [],
            "suspicious_attachments": [],
            "size_anomalies": [],
            "potential_deepfakes": [],
        }
        output = self._render(analysis)
        self.assertIn("✔ Attachments appear safe", output)
        self.assertNotIn("File Warnings:", output)

    def test_print_media_details_renders_all_warning_categories(self) -> None:
        """All four categories are rendered with their headers and bullet points."""
        analysis = {
            "file_type_warnings": ["invoice.exe: executable file type"],
            "suspicious_attachments": ["script.vbs: dangerous script payload"],
            "size_anomalies": ["photo.jpg: unexpectedly large archive"],
            "potential_deepfakes": ["video.mp4: facial frame inconsistency"],
        }
        output = self._render(analysis)

        self.assertNotIn("Attachments appear safe", output)
        self.assertIn("File Warnings:", output)
        self.assertIn("invoice.exe: executable file type", output)
        self.assertIn("Suspicious Attachments:", output)
        self.assertIn("script.vbs: dangerous script payload", output)
        self.assertIn("Size Anomalies:", output)
        self.assertIn("photo.jpg: unexpectedly large archive", output)
        self.assertIn("Potential Deepfakes:", output)
        self.assertIn("video.mp4: facial frame inconsistency", output)

    def test_print_media_details_truncation_with_max_media(self) -> None:
        """Category items exceeding max_media are truncated."""
        warnings = [f"warning_{i}.bin" for i in range(5)]
        analysis = {"file_type_warnings": warnings}

        output = self._render(analysis, max_media=2)
        self.assertIn("File Warnings:", output)
        self.assertIn("warning_0.bin", output)
        self.assertIn("warning_1.bin", output)
        self.assertNotIn("warning_2.bin", output)
        self.assertNotIn("warning_3.bin", output)
        self.assertNotIn("warning_4.bin", output)

    def test_print_media_details_partial_categories(self) -> None:
        """Only present categories are rendered; absent categories are omitted."""
        analysis = {
            "file_type_warnings": ["doc.exe"],
            "potential_deepfakes": ["ceo_audio.wav"],
        }
        output = self._render(analysis)

        self.assertNotIn("Attachments appear safe", output)
        self.assertIn("File Warnings:", output)
        self.assertIn("doc.exe", output)
        self.assertIn("Potential Deepfakes:", output)
        self.assertIn("ceo_audio.wav", output)
        self.assertNotIn("Suspicious Attachments:", output)
        self.assertNotIn("Size Anomalies:", output)

    def test_print_media_details_handles_none_values(self) -> None:
        """None values for indicator keys do not raise exceptions."""
        analysis: Dict[str, Optional[List[str]]] = {
            "file_type_warnings": None,
            "suspicious_attachments": None,
            "size_anomalies": None,
            "potential_deepfakes": None,
        }
        output = self._render(analysis)
        self.assertIn("✔ Attachments appear safe", output)

    def test_print_media_details_with_colors_enabled(self) -> None:
        """Rendering with colors enabled applies ANSI formatting to bullet and title."""
        analysis = {
            "suspicious_attachments": ["malware.pdf"],
        }
        output = self._render(analysis, colorize_side_effect=True)
        self.assertIn("Suspicious Attachments:", output)
        self.assertIn("malware.pdf", output)
        # Check that ANSI escape sequences are present in the output
        self.assertIn("\033[", output)


if __name__ == "__main__":
    unittest.main()
