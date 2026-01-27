import unittest
from unittest.mock import MagicMock, patch
import os
import tempfile
from src.modules.media_analyzer import MediaAuthenticityAnalyzer
from src.modules.email_ingestion import EmailData

class TestMediaAnalyzerLeak(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock()
        # Enable checks to reach the vulnerable code path
        self.config.check_media_attachments = True
        self.config.deepfake_detection_enabled = True
        self.analyzer = MediaAuthenticityAnalyzer(self.config)

    @patch('src.modules.media_analyzer.tempfile.NamedTemporaryFile')
    @patch('src.modules.media_analyzer.os.unlink')
    @patch('src.modules.media_analyzer.os.path.exists')
    def test_temp_file_cleanup_on_write_error(self, mock_exists, mock_unlink, mock_tempfile):
        """
        Test that temporary file is cleaned up even if writing to it fails.
        This simulates a disk full or permission error during write.
        """
        # Setup mock temp file
        mock_file = MagicMock()
        mock_file.name = "/tmp/leaked_file"

        # Configure the context manager to return our mock file
        mock_tempfile.return_value.__enter__.return_value = mock_file

        # Simulate write error (e.g., Disk Full)
        mock_file.write.side_effect = IOError("Disk full")

        # Mock existence check to return True so unlink would be called if logic reached it
        mock_exists.return_value = True

        # Construct minimal email data with VALID signature to pass initial checks
        # MP4 magic bytes: ... ftyp ...
        # Standard MP4 header often starts with size (4 bytes) then 'ftyp'
        valid_mp4_header = b'\x00\x00\x00\x20ftypisom'

        email_data = MagicMock(spec=EmailData)
        email_data.attachments = [{
            "filename": "video.mp4",
            "content_type": "video/mp4",
            "size": len(valid_mp4_header),
            "data": valid_mp4_header,
            "truncated": False
        }]

        # Call analyze. It catches exceptions internally, so it shouldn't crash.
        self.analyzer.analyze(email_data)

        # ASSERT: os.unlink SHOULD be called to clean up the file
        mock_unlink.assert_called_with("/tmp/leaked_file")

if __name__ == '__main__':
    unittest.main()
