import unittest
import zipfile
from unittest.mock import MagicMock

from src.modules.media_analyzer import MediaAuthenticityAnalyzer


class TestMediaAnalyzerBug(unittest.TestCase):
    def test_read_zip_member_securely_name_error_fixed(self):
        # Create a mock config
        config = MagicMock()
        config.check_media_attachments = True
        config.deepfake_detection_enabled = False

        analyzer = MediaAuthenticityAnalyzer(config)

        # Create a ZipFile mock that raises BadZipFile on close()
        # We need to mock zf.open() to return a file-like object whose close() raises BadZipFile

        mock_zf = MagicMock(spec=zipfile.ZipFile)
        mock_file = MagicMock()
        mock_file.read.side_effect = [b"some content", b""]  # Return content then EOF

        # Make close() raise BadZipFile
        mock_file.close.side_effect = zipfile.BadZipFile("CRC mismatch")

        mock_zf.open.return_value = mock_file

        # Mock logger to see if it logs the error
        analyzer.logger = MagicMock()

        try:
            # This should NOT raise NameError anymore
            result = analyzer._read_zip_member_securely(mock_zf, "test.txt", 1000)
            self.assertEqual(result, b"some content")

            # Verify it logged the debug message
            analyzer.logger.debug.assert_called()
            args, _ = analyzer.logger.debug.call_args
            self.assertIn("Ignored error closing zip stream", args[0])
            self.assertIn("CRC mismatch", str(args[0]))

        except NameError as e:
            self.fail(f"Caught NameError: {e} - Fix failed!")
        except Exception as e:
            self.fail(f"Caught unexpected exception: {type(e).__name__}: {e}")

    def test_analyze_deepfake_threat_general_exception(self):
        # Create a mock config
        config = MagicMock()
        config.media_analysis_timeout = 10

        analyzer = MediaAuthenticityAnalyzer(config)
        analyzer.logger = MagicMock()

        # Mock executor to return a future that raises an Exception
        mock_future = MagicMock()
        mock_future.result.side_effect = Exception("General deepfake analysis error")
        analyzer._deepfake_executor = MagicMock()
        analyzer._deepfake_executor.submit.return_value = mock_future

        # Call the method
        result = analyzer._analyze_deepfake_threat("test.mp4", b"data", "video/mp4")

        # Verify the structure returned
        self.assertEqual(result["score"], 0.0)
        self.assertEqual(result["indicators"], [])
        self.assertEqual(result["errors"], [])

        # Verify logger.error was called with the correct message
        analyzer.logger.error.assert_called_once()
        args, _ = analyzer.logger.error.call_args
        self.assertIn(
            "Deepfake analysis failed for test.mp4: General deepfake analysis error",
            args[0],
        )


if __name__ == "__main__":
    unittest.main()
