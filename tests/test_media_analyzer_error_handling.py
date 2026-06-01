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



    def test_inspect_zip_contents_bad_zipfile(self):
        # Create a mock config
        config = MagicMock()
        config.check_media_attachments = True
        config.deepfake_detection_enabled = False

        analyzer = MediaAuthenticityAnalyzer(config)
        analyzer.logger = MagicMock()

        # Pass intentionally malformed zip data to trigger zipfile.BadZipFile
        score, warnings = analyzer._inspect_zip_contents("test.zip", b"not a valid zip")

        # BadZipFile is caught and ignored
        self.assertEqual(score, 0.0)
        self.assertEqual(warnings, [])
        analyzer.logger.warning.assert_not_called()

    def test_inspect_zip_contents_generic_exception(self):
        # Create a mock config
        config = MagicMock()
        config.check_media_attachments = True
        config.deepfake_detection_enabled = False

        analyzer = MediaAuthenticityAnalyzer(config)
        analyzer.logger = MagicMock()

        import zipfile
        import io
        from unittest.mock import patch

        with patch("src.modules.media_analyzer.zipfile.ZipFile") as mock_zipfile:
            mock_zipfile.side_effect = Exception("Generic unexpected error")

            score, warnings = analyzer._inspect_zip_contents("test.zip", b"some data")

            # Exception is caught and logged
            self.assertEqual(score, 0.0)
            self.assertEqual(warnings, [])

            # Verify the warning was logged
            analyzer.logger.warning.assert_called_once()
            args, _ = analyzer.logger.warning.call_args
            self.assertIn("Error inspecting zip test.zip", args[0])
            self.assertIn("Generic unexpected error", args[0])


if __name__ == "__main__":

    unittest.main()
