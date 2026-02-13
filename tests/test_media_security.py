
import unittest
import numpy as np
import sys
import os
from unittest.mock import MagicMock, patch
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.modules.media_analyzer import MediaAuthenticityAnalyzer
from src.modules.email_ingestion import EmailData
from src.utils.config import AnalysisConfig

class TestMediaDoS(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock()
        # Ensure deepfake detection is enabled to trigger relevant paths if tested there
        self.config.deepfake_detection_enabled = True
        self.analyzer = MediaAuthenticityAnalyzer(self.config)

    # Patch the module-local cv2 reference used by MediaAuthenticityAnalyzer.
    @patch('src.modules.media_analyzer.cv2.VideoCapture')
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

class TestMediaSecurity(unittest.TestCase):
    def setUp(self):
        self.config = AnalysisConfig(
            spam_threshold=5.0,
            spam_check_headers=True,
            spam_check_urls=True,
            nlp_model="test",
            nlp_threshold=0.7,
            nlp_batch_size=8,
            check_social_engineering=True,
            check_urgency_markers=True,
            check_authority_impersonation=True,
            check_media_attachments=True,
            deepfake_detection_enabled=True,
            media_analysis_timeout=10,
            deepfake_provider="simulator",
            deepfake_api_key=None,
            deepfake_api_url=None,
            deepfake_model_path=None
        )
        self.analyzer = MediaAuthenticityAnalyzer(self.config)

    def test_disguised_mov_file_blocked(self):
        # Create a "fake" mov that is actually just text
        # .mov is now strictly validated
        fake_mov_content = b"This is not a video file, it is a text file disguised as mov."

        email_data = EmailData(
            message_id="1",
            subject="Test",
            sender="sender@example.com",
            recipient="recipient@example.com",
            date=datetime.now(),
            body_text="body",
            body_html="",
            headers={},
            attachments=[{
                "filename": "exploit.mov",
                "content_type": "video/quicktime",
                "size": len(fake_mov_content),
                "data": fake_mov_content,
                "truncated": False
            }],
            raw_email=None,
            account_email="me@example.com",
            folder="INBOX"
        )

        with unittest.mock.patch.object(self.analyzer, '_extract_frames_from_video', return_value=[]) as mock_extract:
            result = self.analyzer.analyze(email_data)

            # Check if mismatch was detected
            found_mismatch = any("Invalid file signature" in w for w in result.suspicious_attachments)

            self.assertTrue(found_mismatch, "Should detect file type mismatch for .mov")

            # Verify that deepfake analysis was skipped (OpenCV not called)
            mock_extract.assert_not_called()

if __name__ == '__main__':
    unittest.main()
