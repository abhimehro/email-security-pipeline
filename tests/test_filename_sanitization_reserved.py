
import unittest
from src.utils.security_validators import sanitize_filename

class TestSanitizeFilenameReserved(unittest.TestCase):
    def test_reserved_filenames(self):
        reserved_names = [
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
        ]

        for name in reserved_names:
            # Case insensitive check
            filenames = [name, name.lower(), name.title()]
            for fname in filenames:
                sanitized = sanitize_filename(fname)
                # We expect it to be modified (e.g. prepended with _)
                self.assertNotEqual(sanitized.upper(), name, f"Reserved name {fname} was not sanitized")

            # With extension
            filenames_ext = [f"{name}.txt", f"{name.lower()}.txt"]
            for fname in filenames_ext:
                sanitized = sanitize_filename(fname)
                base = sanitized.split('.')[0]
                self.assertNotEqual(base.upper(), name, f"Reserved name with extension {fname} was not sanitized")

if __name__ == '__main__':
    unittest.main()
