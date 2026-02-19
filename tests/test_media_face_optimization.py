import unittest
from unittest.mock import MagicMock, patch
import numpy as np
from src.modules.media_analyzer import MediaAuthenticityAnalyzer

class TestMediaFaceOptimization(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock()
        self.config.check_media_attachments = True
        self.config.deepfake_detection_enabled = True
        self.config.media_analysis_timeout = 30
        self.analyzer = MediaAuthenticityAnalyzer(self.config)

    @patch('cv2.CascadeClassifier')
    def test_analyze_facial_inconsistencies_optimization(self, mock_cascade_cls):
        """Test that facial analysis only checks a subset of frames"""
        # Setup mock behavior
        mock_cascade = mock_cascade_cls.return_value
        mock_cascade.empty.return_value = False
        mock_cascade.detectMultiScale.return_value = [] # No faces found

        # Inject the mock into the analyzer (it's loaded lazily, so we preload it)
        self.analyzer.face_cascade = mock_cascade

        # Create 10 dummy frames
        frames = [np.zeros((100, 100), dtype=np.uint8) for _ in range(10)]

        # Run analysis
        self.analyzer._analyze_facial_inconsistencies(frames)

        # Verify detectMultiScale was called 5 times (not 10)
        self.assertEqual(mock_cascade.detectMultiScale.call_count, 5,
                         f"Expected 5 calls to detectMultiScale, got {mock_cascade.detectMultiScale.call_count}")

if __name__ == '__main__':
    unittest.main()
