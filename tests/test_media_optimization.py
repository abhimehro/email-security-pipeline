
import unittest
from unittest.mock import MagicMock, patch
import cv2
import numpy as np
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.modules.media_analyzer import MediaAuthenticityAnalyzer

class TestMediaOptimization(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock()
        self.config.check_media_attachments = True
        self.config.deepfake_detection_enabled = True
        self.config.media_analysis_timeout = 30
        self.analyzer = MediaAuthenticityAnalyzer(self.config)

    @patch('cv2.VideoCapture')
    def test_extract_frames_sequential_read_optimization(self, mock_capture):
        """Test that sequential reading (step=1) avoids expensive seek operations"""
        # Setup mock behavior
        cap_instance = mock_capture.return_value
        cap_instance.isOpened.return_value = True

        # Scenario: 15 frames total, max_frames=10 -> step = 15 // 10 = 1
        total_frames = 15
        max_frames = 10

        def get_prop(prop):
            if prop == cv2.CAP_PROP_FRAME_COUNT:
                return total_frames
            return 0
        cap_instance.get.side_effect = get_prop

        # Mock read behavior
        # Return success=True, frame=dummy_frame
        dummy_frame = np.zeros((100, 100, 3), dtype=np.uint8)
        cap_instance.read.return_value = (True, dummy_frame)

        frames = self.analyzer._extract_frames_from_video("dummy.mp4", max_frames=max_frames)

        self.assertEqual(len(frames), 10)

        # Verify optimization: set(CV_CAP_PROP_POS_FRAMES, ...) should NOT be called
        set_calls = [call for call in cap_instance.set.call_args_list
                     if call[0][0] == cv2.CAP_PROP_POS_FRAMES]

        self.assertEqual(len(set_calls), 0, "Should not call set() for sequential reading (step=1)")

        # Verify read was called at least 10 times
        self.assertGreaterEqual(cap_instance.read.call_count, 10)

    @patch('cv2.VideoCapture')
    def test_extract_frames_seek_for_large_step(self, mock_capture):
        """Test that large step uses seek operations"""
        cap_instance = mock_capture.return_value
        cap_instance.isOpened.return_value = True

        # Scenario: 100 frames total, max_frames=10 -> step = 100 // 10 = 10
        total_frames = 100
        max_frames = 10

        def get_prop(prop):
            if prop == cv2.CAP_PROP_FRAME_COUNT:
                return total_frames
            return 0
        cap_instance.get.side_effect = get_prop

        dummy_frame = np.zeros((100, 100, 3), dtype=np.uint8)
        cap_instance.read.return_value = (True, dummy_frame)

        frames = self.analyzer._extract_frames_from_video("dummy.mp4", max_frames=max_frames)

        self.assertEqual(len(frames), 10)

        # Verify seek WAS called
        set_calls = [call for call in cap_instance.set.call_args_list
                     if call[0][0] == cv2.CAP_PROP_POS_FRAMES]

        self.assertGreater(len(set_calls), 0, "Should call set() for non-sequential reading (step>1)")

if __name__ == '__main__':
    unittest.main()
