import unittest

from src.utils.security_validators import (
    DEFAULT_MAX_EMAIL_SIZE,
    MAX_MIME_PARTS,
    MAX_SUBJECT_LENGTH,
    calculate_max_email_size,
    validate_mime_parts_count,
    validate_subject_length,
)

# The 5 MB overhead added by calculate_max_email_size is an implementation
# constant defined inline in security_validators.py.  Mirror it here so all
# tests stay consistent when the value changes in the implementation.
_OVERHEAD_BYTES = 5 * 1024 * 1024


class TestValidateSubjectLength(unittest.TestCase):

    def test_short_subject_returned_unchanged(self):
        subject = "Hello World"
        self.assertEqual(validate_subject_length(subject), subject)

    def test_subject_at_exact_limit_returned_unchanged(self):
        subject = "A" * MAX_SUBJECT_LENGTH
        self.assertEqual(validate_subject_length(subject), subject)

    def test_subject_one_over_limit_is_truncated(self):
        subject = "B" * (MAX_SUBJECT_LENGTH + 1)
        result = validate_subject_length(subject)
        self.assertEqual(len(result), MAX_SUBJECT_LENGTH)
        self.assertEqual(result, "B" * MAX_SUBJECT_LENGTH)

    def test_very_long_subject_is_truncated(self):
        subject = "C" * (MAX_SUBJECT_LENGTH * 10)
        result = validate_subject_length(subject)
        self.assertEqual(len(result), MAX_SUBJECT_LENGTH)
        self.assertEqual(result, "C" * MAX_SUBJECT_LENGTH)


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
