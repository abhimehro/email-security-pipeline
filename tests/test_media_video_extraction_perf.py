
import unittest
import cv2
import numpy as np
import tempfile
import os
import sys

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.modules.media_analyzer import MediaAuthenticityAnalyzer
from unittest.mock import MagicMock

class TestMediaVideoExtractionPerf(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock()
        self.config.check_media_attachments = True
        self.config.deepfake_detection_enabled = True
        self.config.media_analysis_timeout = 30
        self.analyzer = MediaAuthenticityAnalyzer(self.config)

    def create_dummy_video(self, filename, frames=100, width=64, height=48):
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        out = cv2.VideoWriter(filename, fourcc, 20.0, (width, height))
        for i in range(frames):
            # Create frame with index encoded in pixel to verify order
            # Use large steps to avoid compression artifacts merging values
            frame = np.zeros((height, width, 3), dtype=np.uint8)
            val = (i * 10) % 255
            frame[:,:,0] = val
            out.write(frame)
        out.release()

    def test_extract_frames_sequential(self):
        """Test sequential extraction (step=1)"""
        with tempfile.NamedTemporaryFile(suffix='.mp4', delete=False) as tf:
            video_path = tf.name

        try:
            # 50 frames, ask for 100 -> step=1, sequential read
            self.create_dummy_video(video_path, frames=50)
            frames = self.analyzer._extract_frames_from_video(video_path, max_frames=100)

            # Should get all 50 frames
            self.assertEqual(len(frames), 50)
            # Verify order
            for i, frame in enumerate(frames):
                # Allow small tolerance for compression
                expected_val = (i * 10) % 255
                actual_val = frame[0,0,0]
                diff = abs(int(actual_val) - int(expected_val))
                # MP4 compression can be lossy. But if we are writing simple solid color frames...
                # 5 should be enough tolerance?
                self.assertLess(diff, 10, f"Frame {i}: expected {expected_val}, got {actual_val}")

        finally:
            if os.path.exists(video_path):
                os.remove(video_path)

    def test_extract_frames_sampled(self):
        """Test sampled extraction (step>1)"""
        with tempfile.NamedTemporaryFile(suffix='.mp4', delete=False) as tf:
            video_path = tf.name

        try:
            # 100 frames, ask for 10 -> step=10
            self.create_dummy_video(video_path, frames=100)
            frames = self.analyzer._extract_frames_from_video(video_path, max_frames=10)

            self.assertEqual(len(frames), 10)

            # Check if frames are different
            first_val = frames[0][0,0,0]
            last_val = frames[-1][0,0,0]
            self.assertNotEqual(first_val, last_val)

        finally:
            if os.path.exists(video_path):
                os.remove(video_path)

if __name__ == '__main__':
    unittest.main()
