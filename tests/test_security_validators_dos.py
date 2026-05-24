import unittest

from src.utils.security_validators import (
    DEFAULT_MAX_EMAIL_SIZE,
    MAX_MIME_PARTS,
    calculate_max_email_size,
    validate_mime_parts_count,
)

# calculate_max_email_size is expected to add a fixed 5 MB overhead to any
# positive attachment limit. Mirror that contract here so the tests clearly
# document and verify this behavior.
_OVERHEAD_BYTES = 5 * 1024 * 1024


class TestValidateMimePartsCount(unittest.TestCase):

    def test_count_of_one_is_safe(self):
        self.assertTrue(validate_mime_parts_count(1))

    def test_count_at_exact_limit_is_safe(self):
        self.assertTrue(validate_mime_parts_count(MAX_MIME_PARTS))

    def test_count_one_over_limit_is_rejected(self):
        self.assertFalse(validate_mime_parts_count(MAX_MIME_PARTS + 1))

    def test_count_of_zero_is_safe(self):
        self.assertTrue(validate_mime_parts_count(0))


class TestCalculateMaxEmailSize(unittest.TestCase):

    def test_positive_attachment_limit_adds_overhead(self):
        attachment_bytes = 20 * 1024 * 1024  # 20 MB
        self.assertEqual(
            calculate_max_email_size(attachment_bytes),
            attachment_bytes + _OVERHEAD_BYTES,
        )

    def test_zero_attachment_limit_returns_default(self):
        self.assertEqual(calculate_max_email_size(0), DEFAULT_MAX_EMAIL_SIZE)

    def test_ten_mb_attachment_limit_is_exactly_fifteen_mb(self):
        ten_mb = 10 * 1024 * 1024
        self.assertEqual(calculate_max_email_size(ten_mb), ten_mb + _OVERHEAD_BYTES)


if __name__ == "__main__":
    unittest.main()
