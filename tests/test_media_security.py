
import unittest
import numpy as np
import sys
from unittest.mock import MagicMock, patch

# Add src to path
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.modules.media_analyzer import MediaAuthenticityAnalyzer

class TestMediaDoS(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock()
        # Ensure deepfake detection is enabled to trigger relevant paths if tested there
        self.config.deepfake_detection_enabled = True
        self.analyzer = MediaAuthenticityAnalyzer(self.config)

    @patch('cv2.VideoCapture')
    def test_extract_large_frames(self, mock_capture):
        # Create a mock video capture
        mock_cap_instance = MagicMock()
        mock_capture.return_value = mock_cap_instance
        mock_cap_instance.isOpened.return_value = True

        # Simulate a massive frame (e.g. 8K resolutionish: 4000x3000)
        large_height = 3000
        large_width = 4000
        large_frame = np.zeros((large_height, large_width, 3), dtype=np.uint8)

        # Configure mock to return this frame once
        mock_cap_instance.read.side_effect = [(True, large_frame), (False, None)]
        mock_cap_instance.get.return_value = 1  # 1 frame

        # Call the method
        frames = self.analyzer._extract_frames_from_video("dummy_path")

        # Verify result
        self.assertTrue(len(frames) > 0, "Should have extracted at least one frame")
        extracted_frame = frames[0]

        print(f"Original shape: {large_frame.shape}")
        print(f"Extracted shape: {extracted_frame.shape}")

        # Check dimensions
        h, w = extracted_frame.shape[:2]
        max_dim = max(h, w)

        # The limit defined in the class
        LIMIT = 1920

        self.assertLessEqual(max_dim, LIMIT, f"Frame dimension {max_dim} exceeds limit {LIMIT}")

        # Verify aspect ratio is preserved (approximately)
        original_aspect = large_width / large_height
        new_aspect = w / h
        self.assertAlmostEqual(original_aspect, new_aspect, places=2, msg="Aspect ratio mismatch")

        print("Test Passed: Frame was correctly resized.")

if __name__ == '__main__':
    unittest.main()
