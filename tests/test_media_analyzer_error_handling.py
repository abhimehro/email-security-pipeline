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



    def test_handle_nested_tar_member_extraction_error(self):
        config = MagicMock()
        config.check_media_attachments = True
        config.deepfake_detection_enabled = False

        analyzer = MediaAuthenticityAnalyzer(config)
        analyzer.logger = MagicMock()

        # Mock TarFile and TarInfo
        mock_tf = MagicMock()
        mock_member = MagicMock()
        mock_member.name = "nested.zip"
        mock_member.size = 100

        # Mock extraction to raise an Exception
        mock_tf.extractfile.side_effect = Exception("Mocked extraction error")

        score, warnings = analyzer._handle_nested_tar_member(
            tf=mock_tf, member=mock_member, parent_filename="parent.tar", depth=0
        )

        self.assertEqual(score, 3.0)
        self.assertEqual(len(warnings), 1)
        self.assertIn(
            "Failed to inspect nested archive nested.zip: Mocked extraction error",
            warnings[0],
        )
        analyzer.logger.warning.assert_called()

if __name__ == "__main__":
    unittest.main()
