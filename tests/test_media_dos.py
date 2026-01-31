import unittest
from unittest.mock import MagicMock, patch
import numpy as np
import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.modules.media_analyzer import MediaAuthenticityAnalyzer

class TestMediaDoS(unittest.TestCase):
    def setUp(self):
        # Create config mock
        self.config = MagicMock()
        self.config.check_media_attachments = True
        self.config.deepfake_detection_enabled = True

        self.analyzer = MediaAuthenticityAnalyzer(self.config)

    @patch('cv2.VideoCapture')
    def test_huge_frame_resize(self, mock_capture_cls):
        # Setup mock capture
        mock_capture = MagicMock()
        mock_capture_cls.return_value = mock_capture
        mock_capture.isOpened.return_value = True

        # Mock frame properties: 10 frames
        mock_capture.get.side_effect = lambda prop: {
            7: 10, # CV_CAP_PROP_FRAME_COUNT (7)
            5: 30  # CV_CAP_PROP_FPS (5)
        }.get(prop, 0)

        # Create a huge frame (fake 4K)
        # 3840x2160
        huge_frame = np.zeros((2160, 3840, 3), dtype=np.uint8)

        # Return the huge frame
        mock_capture.read.return_value = (True, huge_frame)

        # Call extraction
        frames = self.analyzer._extract_frames_from_video("dummy.mp4", max_frames=1)

        self.assertTrue(len(frames) > 0)
        processed_frame = frames[0]

        # Check dimensions
        h, w = processed_frame.shape[:2]
        print(f"Original: 2160x3840, Processed: {h}x{w}")

        # Assert resizing behavior
        self.assertLessEqual(h, 1080, "Frame height should be <= 1080")
        self.assertLessEqual(w, 1920, "Frame width should be <= 1920")

if __name__ == '__main__':
    unittest.main()
