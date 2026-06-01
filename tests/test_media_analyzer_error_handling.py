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



    def test_handle_nested_zip_member_value_error(self):
        # Create a mock config
        config = MagicMock()
        config.check_media_attachments = True
        config.deepfake_detection_enabled = False

        analyzer = MediaAuthenticityAnalyzer(config)
        analyzer.logger = MagicMock()

        mock_zf = MagicMock(spec=zipfile.ZipFile)
        mock_info = MagicMock()
        mock_info.file_size = 100
        mock_zf.getinfo.return_value = mock_info

        analyzer._read_zip_member_securely = MagicMock(side_effect=ValueError("Nested zip bomb"))

        score, warnings = analyzer._handle_nested_zip_member(mock_zf, "nested.zip", "parent.zip", 0)

        self.assertEqual(score, 5.0)
        self.assertEqual(len(warnings), 1)
        self.assertIn("Zip bomb detected", warnings[0])
        self.assertIn("Nested zip bomb", warnings[0])

    def test_handle_nested_zip_member_exception(self):
        config = MagicMock()
        config.check_media_attachments = True
        config.deepfake_detection_enabled = False

        analyzer = MediaAuthenticityAnalyzer(config)
        analyzer.logger = MagicMock()

        mock_zf = MagicMock(spec=zipfile.ZipFile)
        mock_info = MagicMock()
        mock_info.file_size = 100
        mock_zf.getinfo.return_value = mock_info

        analyzer._read_zip_member_securely = MagicMock(side_effect=Exception("Generic error"))

        score, warnings = analyzer._handle_nested_zip_member(mock_zf, "nested.zip", "parent.zip", 0)

        self.assertEqual(score, 3.0)
        self.assertEqual(len(warnings), 1)
        self.assertIn("Failed to inspect nested archive", warnings[0])
        self.assertIn("Generic error", warnings[0])
        analyzer.logger.warning.assert_called_with("Error inspecting nested archive nested.zip: Generic error")

    def test_handle_nested_zip_member_size_limit(self):
        config = MagicMock()
        config.check_media_attachments = True
        config.deepfake_detection_enabled = False

        analyzer = MediaAuthenticityAnalyzer(config)
        analyzer.logger = MagicMock()

        mock_zf = MagicMock(spec=zipfile.ZipFile)
        mock_info = MagicMock()
        # Set file size greater than MAX_NESTED_ZIP_SIZE (default is usually 10MB or 50MB, let's use a huge number)
        mock_info.file_size = analyzer.MAX_NESTED_ZIP_SIZE + 1000
        mock_zf.getinfo.return_value = mock_info

        score, warnings = analyzer._handle_nested_zip_member(mock_zf, "nested.zip", "parent.zip", 0)

        self.assertEqual(score, 0.0)
        self.assertEqual(len(warnings), 0)
        analyzer.logger.warning.assert_called_with(f"Skipping nested archive nested.zip (declared size {mock_info.file_size} > limit)")

    def test_handle_nested_zip_member_depth_limit(self):
        config = MagicMock()
        config.check_media_attachments = True
        config.deepfake_detection_enabled = False

        analyzer = MediaAuthenticityAnalyzer(config)
        analyzer.logger = MagicMock()

        mock_zf = MagicMock(spec=zipfile.ZipFile)

        score, warnings = analyzer._handle_nested_zip_member(mock_zf, "nested.zip", "parent.zip", 2)

        self.assertEqual(score, 0.0)
        self.assertEqual(len(warnings), 0)
        # _read_zip_member_securely should not be called because depth >= 2
        mock_zf.getinfo.assert_not_called()

if __name__ == "__main__":
    unittest.main()
