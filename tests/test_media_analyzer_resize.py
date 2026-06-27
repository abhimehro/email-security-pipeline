import unittest
from unittest.mock import MagicMock, patch

import numpy as np

from src.modules.media_analyzer import MediaAuthenticityAnalyzer


class TestMediaAnalyzerResize(unittest.TestCase):
    def setUp(self):
        config = MagicMock()
        self.analyzer = MediaAuthenticityAnalyzer(config)
        self.analyzer.logger = MagicMock()

    def test_resize_frame_if_needed_non_positive_dimensions(self):
        """Test that frames with 0 or negative dimensions are skipped and logged."""
        # Create a frame with 0 height (shape: 0, 100, 3)
        frame = np.zeros((0, 100, 3), dtype=np.uint8)

        result = self.analyzer._resize_frame_if_needed(frame)

        # Should return the exact same frame object
        self.assertIs(result, frame)
        self.analyzer.logger.warning.assert_called_once()
        warning_msg = self.analyzer.logger.warning.call_args[0][0]
        self.assertIn("non-positive dimensions", warning_msg)

    def test_resize_frame_if_needed_exception_handling(self):
        """Test that exceptions during resize are caught, logged, and original frame returned."""
        # Create a valid frame
        frame = np.zeros((2000, 2000, 3), dtype=np.uint8)

        # We simulate a resize failure by mocking cv2.resize to throw an Exception
        with patch("src.modules.media_analyzer.cv2.resize") as mock_resize:
            mock_resize.side_effect = Exception("Mocked resize error")

            result = self.analyzer._resize_frame_if_needed(frame, max_dim=1000)

            # Should catch the exception, log it, and return the original frame
            self.assertIs(result, frame)
            self.analyzer.logger.warning.assert_called_once()
            warning_msg = self.analyzer.logger.warning.call_args[0][0]
            self.assertIn("Error resizing frame", warning_msg)
            self.assertIn("Mocked resize error", warning_msg)

    def test_resize_frame_if_needed_happy_path(self):
        """Test that a valid frame exceeding max dimensions is actually resized."""
        frame = np.zeros((2000, 1000, 3), dtype=np.uint8)

        # We just test the functionality of max_dim scaling here
        result = self.analyzer._resize_frame_if_needed(frame, max_dim=1000)

        # Original was 2000x1000. It should be scaled by 1000/2000 = 0.5.
        # So new size is 1000x500
        self.assertEqual(result.shape, (1000, 500, 3))
        self.assertIsNot(result, frame)

    def test_resize_frame_if_needed_no_resize(self):
        """Test that a valid frame under max dimensions is NOT resized."""
        frame = np.zeros((800, 600, 3), dtype=np.uint8)

        result = self.analyzer._resize_frame_if_needed(frame, max_dim=1000)

        # Should be the exact same object
        self.assertIs(result, frame)


if __name__ == "__main__":
    unittest.main()
