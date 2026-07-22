import unittest
from src.utils.security_validators import sanitize_filename


class TestSanitizeFilename(unittest.TestCase):
    def test_happy_path(self):
        self.assertEqual(sanitize_filename("normal_file.txt"), "normal_file.txt")
        self.assertEqual(sanitize_filename("file-name_123.jpg"), "file-name_123.jpg")

    def test_empty_input(self):
        self.assertEqual(sanitize_filename(""), "unnamed_attachment")
        self.assertEqual(sanitize_filename(None), "unnamed_attachment")

    def test_path_traversal(self):
        self.assertEqual(sanitize_filename("../../etc/passwd"), "passwd")
        self.assertEqual(sanitize_filename("C:\\Windows\\System32\\cmd.exe"), "cmd.exe")
        self.assertEqual(sanitize_filename("/absolute/path/file.txt"), "file.txt")

    def test_dots_and_spaces(self):
        self.assertEqual(sanitize_filename("file....txt"), "file.txt")
        self.assertEqual(sanitize_filename(".hidden_file"), "hidden_file")
        self.assertEqual(sanitize_filename("file_with_trailing_dot."), "file_with_trailing_dot")
        self.assertEqual(sanitize_filename("  spaces  .txt  "), "spaces  .txt")

    def test_becomes_empty(self):
        self.assertEqual(sanitize_filename("///"), "unnamed_attachment")
        self.assertEqual(sanitize_filename("\0\0\0"), "unnamed_attachment")

    def test_windows_reserved(self):
        self.assertEqual(sanitize_filename("CON.txt"), "_CON.txt")
        self.assertEqual(sanitize_filename("prn.pdf"), "_prn.pdf")
        self.assertEqual(sanitize_filename("AUX"), "_AUX")
        self.assertEqual(sanitize_filename("COM1.tar.gz"), "_COM1.tar.gz")
        self.assertEqual(sanitize_filename("LPT9"), "_LPT9")

    def test_length_limits(self):
        long_name_255 = "文" * 255
        self.assertEqual(len(sanitize_filename(long_name_255)), 255)

        long_name_256 = "文" * 256
        self.assertEqual(len(sanitize_filename(long_name_256)), 255)


if __name__ == "__main__":
    unittest.main()
