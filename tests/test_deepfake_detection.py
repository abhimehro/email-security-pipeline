
import unittest
import os
import sys
import numpy as np
from unittest.mock import MagicMock

# Add repo root to path
sys.path.insert(0, os.getcwd())

# Import using src package to resolve relative imports correctly
from src.modules.media_analyzer import MediaAuthenticityAnalyzer
from src.modules.email_ingestion import EmailData
from src.utils.config import AnalysisConfig

class TestDeepfakeDetection(unittest.TestCase):
    def setUp(self):
        # Create a mock config
        self.config = MagicMock(spec=AnalysisConfig)
        self.config.check_media_attachments = True
        self.config.deepfake_detection_enabled = True
        self.config.deepfake_provider = "simulator"
        self.config.deepfake_api_key = None
        self.config.deepfake_api_url = None
        self.config.deepfake_model_path = None

        self.analyzer = MediaAuthenticityAnalyzer(self.config)

    def test_simulator_clean_file(self):
        email_data = EmailData(
            message_id="1",
            subject="Clean Video",
            sender="user@example.com",
            recipient="me@example.com",
            date="2023-01-01",
            body_text="Here is a video",
            body_html="",
            headers={},
            account_email="me@example.com",
            folder="INBOX",
            raw_email=None,
            attachments=[{
                "filename": "vacation.mp4",
                "content_type": "video/mp4",
                "size": 1024 * 1024,
                "data": b"\x00\x00\x00\x18ftypmp42" + b"a" * 1024 * 200,
                "truncated": False
            }]
        )

        result = self.analyzer.analyze(email_data)
        self.assertEqual(len(result.potential_deepfakes), 0)
        self.assertLess(result.threat_score, 1.0)

    def test_simulator_deepfake_file(self):
        email_data = EmailData(
            message_id="2",
            subject="Deepfake Video",
            sender="bad@example.com",
            recipient="me@example.com",
            date="2023-01-01",
            body_text="Look at this",
            body_html="",
            headers={},
            account_email="me@example.com",
            folder="INBOX",
            raw_email=None,
            attachments=[{
                "filename": "deepfake_video.mp4",
                "content_type": "video/mp4",
                "size": 1024 * 1024,
                "data": b"\x00\x00\x00\x18ftypmp42" + b"a" * 1024 * 200,
                "truncated": False
            }]
        )

        # Mock frame extraction to return dummy frames
        self.analyzer._extract_frames_from_video = MagicMock(return_value=[np.zeros((100, 100, 3), dtype=np.uint8)])
        # Mock model score to be high
        self.analyzer._run_deepfake_model = MagicMock(return_value=0.8)

        result = self.analyzer.analyze(email_data)
        self.assertGreater(len(result.potential_deepfakes), 0)
        self.assertIn("High probability of deepfake", result.potential_deepfakes[0])
        self.assertGreaterEqual(result.threat_score, 3.0)

    def test_simulator_suspicious_file(self):
        email_data = EmailData(
            message_id="3",
            subject="Suspicious Video",
            sender="bad@example.com",
            recipient="me@example.com",
            date="2023-01-01",
            body_text="Look at this",
            body_html="",
            headers={},
            account_email="me@example.com",
            folder="INBOX",
            raw_email=None,
            attachments=[{
                "filename": "suspicious_clip.mp4",
                "content_type": "video/mp4",
                "size": 1024 * 1024,
                "data": b"\x00\x00\x00\x18ftypmp42" + b"a" * 1024 * 200,
                "truncated": False
            }]
        )

        # Mock frame extraction to return dummy frames
        self.analyzer._extract_frames_from_video = MagicMock(return_value=[np.zeros((100, 100, 3), dtype=np.uint8)])
        # Mock some facial inconsistencies to get a score
        self.analyzer._analyze_facial_inconsistencies = MagicMock(return_value=(1.0, ["Facial issue"]))
        # Mock model score to be low
        self.analyzer._run_deepfake_model = MagicMock(return_value=0.1)

        result = self.analyzer.analyze(email_data)
        self.assertGreater(len(result.potential_deepfakes), 0)
        self.assertIn("Facial issue", result.potential_deepfakes[0])
        self.assertGreaterEqual(result.threat_score, 1.0)

    def test_provider_unknown(self):
        self.config.deepfake_provider = "unknown_provider"
        email_data = EmailData(
            message_id="4",
            subject="Unknown Provider",
            sender="user@example.com",
            recipient="me@example.com",
            date="2023-01-01",
            body_text="Video",
            body_html="",
            headers={},
            account_email="me@example.com",
            folder="INBOX",
            raw_email=None,
            attachments=[{
                "filename": "deepfake_test.mp4",
                "content_type": "video/mp4",
                "size": 1024 * 1024,
                "data": b"\x00\x00\x00\x18ftypmp42" + b"a" * 1024 * 200,
                "truncated": False
            }]
        )

        result = self.analyzer.analyze(email_data)
        # Should default to 0.0 and log warning
        self.assertEqual(len(result.potential_deepfakes), 0)

if __name__ == '__main__':
    unittest.main()
