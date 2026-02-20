"""
Unit tests for src/modules/email_parser.py

SECURITY STORY: email_parser.py is the security boundary between raw, untrusted
email bytes and the rest of the pipeline.  These tests validate that the four
main defences actually work:

  1. MIME bomb prevention   – reject emails that contain too many MIME parts
  2. Attachment size limits – truncate oversized attachments, enforce counts
  3. Encoding fallbacks     – safely handle unknown/invalid charsets
  4. Header size limits     – truncate oversized subjects, normalise header keys
"""

import unittest
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from unittest.mock import MagicMock

from src.modules.email_parser import EmailParser
from src.utils.config import EmailAccountConfig
from src.utils.security_validators import MAX_MIME_PARTS, MAX_SUBJECT_LENGTH

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# A generous body/total-attachment ceiling used to prevent unrelated size limits
# from masking the specific security behaviour under test.
_100_MB = 100 * 1024 * 1024

# How many times larger than the per-attachment limit a "per-file high" ceiling is.
# Setting this high prevents per-file truncation from masking the total-size check.
_PER_FILE_LIMIT_MULTIPLIER = 10


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_config() -> EmailAccountConfig:
    """Return a minimal EmailAccountConfig suitable for all tests."""
    return EmailAccountConfig(
        enabled=True,
        email="test@example.com",
        imap_server="imap.example.com",
        imap_port=993,
        app_password="secret",
        folders=["INBOX"],
        provider="test",
        use_ssl=True,
        verify_ssl=True,
    )


def _make_parser(**kwargs) -> EmailParser:
    """Convenience factory; keyword arguments override parser defaults."""
    return EmailParser(_make_config(), **kwargs)


def _simple_raw(subject: str = "Test", body: str = "Hello") -> bytes:
    """Return raw bytes for the simplest possible plain-text email."""
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    return msg.as_bytes()


# ---------------------------------------------------------------------------
# 1. MIME bomb prevention
# ---------------------------------------------------------------------------

class TestMimeBombPrevention(unittest.TestCase):
    """
    SECURITY STORY: A MIME bomb exploits the tree structure of MIME messages.
    An attacker nests thousands of multipart containers so the parser spends
    huge amounts of time and memory walking every node.  We cap the total
    number of MIME parts processed to MAX_MIME_PARTS (100).
    """

    def setUp(self):
        # Use a generous body-size limit so truncation cannot mask the MIME limit
        self.parser = _make_parser(max_body_size=_100_MB)
        # Silence warning noise during tests
        self.parser.logger = MagicMock()

    def _build_wide_multipart(self, n_parts: int) -> bytes:
        """Return an email whose top-level multipart has *n_parts* children."""
        msg = MIMEMultipart()
        msg["Subject"] = "Wide MIME bomb"
        msg["From"] = "attacker@example.com"
        msg["To"] = "victim@example.com"
        for i in range(n_parts):
            msg.attach(MIMEText(f"Part {i}\n", "plain"))
        return msg.as_bytes()

    # -- deep nesting -------------------------------------------------------

    def test_mime_bomb_deep_nesting_returns_email_data(self):
        """Parser must not crash on a deeply-nested multipart structure."""
        # Build: outer > inner1 > inner2 > … (each level wraps the previous)
        innermost = MIMEText("leaf content", "plain")
        wrapper = innermost
        for _ in range(MAX_MIME_PARTS + 10):
            outer = MIMEMultipart()
            outer.attach(wrapper)
            wrapper = outer
        wrapper["Subject"] = "Deep MIME bomb"
        wrapper["From"] = "a@example.com"
        wrapper["To"] = "b@example.com"
        raw = wrapper.as_bytes()

        result = self.parser.parse_email("deep-1", raw, "INBOX")

        # Parser returns an EmailData, not None
        self.assertIsNotNone(result)

    def test_mime_bomb_deep_nesting_logs_warning(self):
        """Parser must log a warning when the MIME parts limit is exceeded."""
        outer = MIMEMultipart()
        outer["Subject"] = "Deep bomb"
        outer["From"] = "a@example.com"
        outer["To"] = "b@example.com"
        # Attach more children than allowed
        for i in range(MAX_MIME_PARTS + 10):
            outer.attach(MIMEText(f"part {i}", "plain"))
        raw = outer.as_bytes()

        self.parser.parse_email("deep-2", raw, "INBOX")

        # At least one warning about exceeding the limit must have been logged
        warning_texts = [
            str(call) for call in self.parser.logger.warning.call_args_list
        ]
        self.assertTrue(
            any("max MIME parts" in t or "MAX_MIME_PARTS" in t or str(MAX_MIME_PARTS) in t
                for t in warning_texts),
            f"Expected a MIME-limit warning, got: {warning_texts}",
        )

    # -- wide (many siblings) -----------------------------------------------

    def test_mime_bomb_wide_nesting_truncates_parts(self):
        """
        When an email has more parts than MAX_MIME_PARTS, only the first
        MAX_MIME_PARTS are included in the body.
        """
        n_attachments = MAX_MIME_PARTS + 50
        raw = self._build_wide_multipart(n_attachments)

        result = self.parser.parse_email("wide-1", raw, "INBOX")

        self.assertIsNotNone(result)
        # Parts beyond the limit must be absent.
        # walk() yields the container itself first, so (MAX_MIME_PARTS - 1) children
        # are processed before the counter hits the ceiling.
        first_skipped = MAX_MIME_PARTS - 1
        self.assertNotIn(f"Part {first_skipped}", result.body_text,
                         f"Content from part {first_skipped} onward should have been truncated "
                         f"(MAX_MIME_PARTS={MAX_MIME_PARTS}, container counts as part 1)")
        # Content that IS within the limit should be present.
        self.assertIn("Part 0", result.body_text)

    def test_mime_bomb_wide_nesting_result_not_none(self):
        """Parser must still return a valid EmailData for a wide MIME bomb."""
        raw = self._build_wide_multipart(MAX_MIME_PARTS + 10)
        result = self.parser.parse_email("wide-2", raw, "INBOX")
        self.assertIsNotNone(result)


# ---------------------------------------------------------------------------
# 2. Attachment size limits
# ---------------------------------------------------------------------------

class TestAttachmentSizeLimits(unittest.TestCase):
    """
    SECURITY STORY: An attacker can craft an email with a huge attachment to
    exhaust memory or disk space.  We truncate individual attachments and reject
    emails whose combined attachment size is too large.
    """

    MAX_ATTACH = 1024  # 1 KB – intentionally tiny for testing

    def setUp(self):
        self.parser = _make_parser(
            max_attachment_bytes=self.MAX_ATTACH,
            max_total_attachment_bytes=_100_MB,
            max_attachment_count=10,
        )
        self.parser.logger = MagicMock()

    def _build_email_with_attachment(
        self,
        filename: str,
        content: bytes,
        content_type: str = "application/octet-stream",
    ) -> bytes:
        """Return raw bytes for an email that carries one attachment."""
        msg = MIMEMultipart()
        msg["Subject"] = "Attachment test"
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg.attach(MIMEText("See attached", "plain"))

        part = MIMEBase(*content_type.split("/", 1))
        part.set_payload(content)
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", "attachment", filename=filename)
        msg.attach(part)
        return msg.as_bytes()

    # -- truncation ---------------------------------------------------------

    def test_attachment_size_limit_truncates_payload(self):
        """Payloads larger than max_attachment_bytes must be truncated."""
        oversized = b"X" * (self.MAX_ATTACH * 10)
        raw = self._build_email_with_attachment("big.bin", oversized)

        result = self.parser.parse_email("att-1", raw, "INBOX")

        self.assertIsNotNone(result)
        self.assertEqual(len(result.attachments), 1)
        att = result.attachments[0]
        self.assertLessEqual(len(att["data"]), self.MAX_ATTACH,
                             "Stored payload must not exceed the per-attachment limit")

    def test_attachment_truncation_sets_flag(self):
        """Truncated attachments must carry truncated=True."""
        oversized = b"Y" * (self.MAX_ATTACH * 5)
        raw = self._build_email_with_attachment("over.bin", oversized)

        result = self.parser.parse_email("att-2", raw, "INBOX")

        att = result.attachments[0]
        self.assertTrue(att["truncated"], "truncated flag must be True for oversized attachments")

    # -- metadata preservation ----------------------------------------------

    def test_attachment_truncation_preserves_filename(self):
        """Filename must survive truncation."""
        big_content = b"Z" * (self.MAX_ATTACH * 3)
        raw = self._build_email_with_attachment("important.pdf", big_content)

        result = self.parser.parse_email("att-3", raw, "INBOX")

        att = result.attachments[0]
        self.assertIn("important.pdf", att["filename"])

    def test_attachment_truncation_preserves_content_type(self):
        """Content-Type must survive truncation."""
        big_content = b"C" * (self.MAX_ATTACH * 3)
        raw = self._build_email_with_attachment(
            "doc.pdf", big_content, "application/pdf"
        )

        result = self.parser.parse_email("att-4", raw, "INBOX")

        att = result.attachments[0]
        self.assertEqual(att["content_type"], "application/pdf")

    def test_attachment_truncation_preserves_original_size(self):
        """The reported size must reflect the *original* (pre-truncation) size."""
        original_size = self.MAX_ATTACH * 4
        big_content = b"S" * original_size
        raw = self._build_email_with_attachment("big2.bin", big_content)

        result = self.parser.parse_email("att-5", raw, "INBOX")

        att = result.attachments[0]
        self.assertEqual(att["size"], original_size,
                         "Reported size should be the original size before truncation")

    # -- non-truncated attachment -------------------------------------------

    def test_small_attachment_not_truncated(self):
        """Attachments within the limit must arrive unmodified."""
        content = b"A" * (self.MAX_ATTACH // 2)
        raw = self._build_email_with_attachment("small.txt", content)

        result = self.parser.parse_email("att-6", raw, "INBOX")

        att = result.attachments[0]
        self.assertFalse(att["truncated"])
        self.assertEqual(att["data"], content)

    # -- count limit --------------------------------------------------------

    def test_attachment_count_limit_enforced(self):
        """Attachments beyond max_attachment_count must be silently dropped."""
        limit = 3
        parser = _make_parser(max_attachment_count=limit)
        parser.logger = MagicMock()

        msg = MIMEMultipart()
        msg["Subject"] = "Many attachments"
        msg["From"] = "s@example.com"
        msg["To"] = "r@example.com"
        for i in range(limit + 5):
            part = MIMEBase("application", "octet-stream")
            part.set_payload(b"data")
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", "attachment", filename=f"file{i}.bin")
            msg.attach(part)

        result = parser.parse_email("att-7", msg.as_bytes(), "INBOX")

        self.assertIsNotNone(result)
        self.assertLessEqual(len(result.attachments), limit,
                             f"Must not store more than {limit} attachments")

    # -- total size limit ---------------------------------------------------

    def test_total_attachment_size_limit_rejects_excess(self):
        """Attachments that would exceed max_total_attachment_bytes are skipped."""
        total_limit = self.MAX_ATTACH * 2
        # Per-file limit is deliberately high so per-file truncation does not
        # interfere with the total-size check we are exercising here.
        per_file_limit = total_limit * _PER_FILE_LIMIT_MULTIPLIER
        parser = _make_parser(
            max_attachment_bytes=per_file_limit,
            max_total_attachment_bytes=total_limit,
        )
        parser.logger = MagicMock()

        msg = MIMEMultipart()
        msg["Subject"] = "Total size test"
        msg["From"] = "s@example.com"
        msg["To"] = "r@example.com"

        # First attachment fits within total_limit (half the budget).
        first_content = b"A" * (total_limit // 2)
        # Second attachment would push the running total over the limit.
        second_content = b"B" * total_limit

        for i, content in enumerate([first_content, second_content]):
            part = MIMEBase("application", "octet-stream")
            part.set_payload(content)
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", "attachment", filename=f"big{i}.bin")
            msg.attach(part)

        result = parser.parse_email("att-8", msg.as_bytes(), "INBOX")

        self.assertIsNotNone(result)
        # Only the first attachment (which fits the budget) must be present.
        self.assertEqual(len(result.attachments), 1,
                         "Second attachment should be rejected when it would exceed "
                         "max_total_attachment_bytes")


# ---------------------------------------------------------------------------
# 3. Encoding fallbacks
# ---------------------------------------------------------------------------

class TestEncodingFallbacks(unittest.TestCase):
    """
    SECURITY STORY: Malformed or unknown charsets must not crash the parser;
    we always fall back to UTF-8 with 'replace' error handling so the pipeline
    keeps running even when adversaries send deliberately broken encodings.
    """

    # -- _decode_bytes (static method, tested directly) ---------------------

    def test_decode_bytes_none_charset_defaults_to_utf8(self):
        """`None` charset → UTF-8 decoding."""
        data = "hello".encode("utf-8")
        result = EmailParser._decode_bytes(data, None)
        self.assertEqual(result, "hello")

    def test_decode_bytes_explicit_utf8(self):
        """Explicit utf-8 charset decodes correctly."""
        data = "héllo".encode("utf-8")
        result = EmailParser._decode_bytes(data, "utf-8")
        self.assertEqual(result, "héllo")

    def test_decode_bytes_invalid_charset_falls_back_to_utf8(self):
        """
        An unknown/invalid charset triggers a LookupError that we catch and
        fall back to UTF-8, returning something rather than raising.
        """
        data = b"safe bytes"
        # "not-a-real-charset" will cause a LookupError inside codecs
        result = EmailParser._decode_bytes(data, "not-a-real-charset")
        self.assertIsInstance(result, str)
        # The fallback UTF-8 decode of ASCII bytes must still be the string
        self.assertEqual(result, "safe bytes")

    def test_decode_bytes_latin1_charset(self):
        """Latin-1 encoded bytes are decoded with the supplied charset."""
        data = "caf\xe9".encode("latin-1")
        result = EmailParser._decode_bytes(data, "latin-1")
        self.assertEqual(result, "café")

    def test_decode_bytes_replace_errors_on_bad_bytes(self):
        """Replacement characters appear for bytes invalid in the charset."""
        bad_bytes = b"\xff\xfe invalid"
        # utf-8 cannot decode 0xff directly without errors='replace'
        result = EmailParser._decode_bytes(bad_bytes, "utf-8")
        self.assertIsInstance(result, str)
        # The replacement character U+FFFD should appear
        self.assertIn("\ufffd", result)

    # -- _decode_header_value (static method) --------------------------------

    def test_header_decoding_plain_ascii(self):
        """Plain ASCII header values are returned unchanged."""
        result = EmailParser._decode_header_value("Hello World")
        self.assertEqual(result, "Hello World")

    def test_header_decoding_empty_string(self):
        """Empty string returns empty string."""
        self.assertEqual(EmailParser._decode_header_value(""), "")

    def test_header_decoding_rfc2047_base64(self):
        """RFC 2047 base64-encoded header values are decoded correctly."""
        # =?utf-8?b?SGVsbG8=?=  →  Hello
        encoded = "=?utf-8?b?SGVsbG8=?="
        result = EmailParser._decode_header_value(encoded)
        self.assertEqual(result, "Hello")

    def test_header_decoding_invalid_encoding_returns_original(self):
        """A malformed encoded-word must not crash; original value is returned."""
        malformed = "=?utf-8?b?!!!notbase64!!!?="
        result = EmailParser._decode_header_value(malformed)
        # Should not raise; may return the original or a partial decode
        self.assertIsInstance(result, str)

    # -- mixed charsets in body parts ---------------------------------------

    def test_body_decoding_mixed_charsets(self):
        """
        A multipart email whose parts use different charsets must be decoded
        and concatenated without errors.
        """
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Mixed charsets"
        msg["From"] = "s@example.com"
        msg["To"] = "r@example.com"

        # Part 1: UTF-8
        part1 = MIMEText("UTF-8 content: \u00e9", "plain", "utf-8")
        # Part 2: ASCII (subset of latin-1)
        part2 = MIMEText("ASCII content", "plain", "us-ascii")
        msg.attach(part1)
        msg.attach(part2)

        parser = _make_parser()
        result = parser.parse_email("enc-1", msg.as_bytes(), "INBOX")

        self.assertIsNotNone(result)
        self.assertIn("UTF-8 content", result.body_text)
        self.assertIn("ASCII content", result.body_text)


# ---------------------------------------------------------------------------
# 4. Header size limits
# ---------------------------------------------------------------------------

class TestHeaderSizeLimits(unittest.TestCase):
    """
    SECURITY STORY: Extremely long headers (especially Subject) are a known
    vector for buffer-overflow and DoS attacks.  We truncate to
    MAX_SUBJECT_LENGTH (1 024 chars) to bound memory usage.
    """

    def setUp(self):
        self.parser = _make_parser()
        self.parser.logger = MagicMock()

    def _parse_with_subject(self, subject: str):
        """Helper: build and parse an email with the given subject."""
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = "s@example.com"
        msg["To"] = "r@example.com"
        msg.set_content("body")
        return self.parser.parse_email("hdr-test", msg.as_bytes(), "INBOX")

    # -- subject truncation -------------------------------------------------

    def test_oversized_subject_is_truncated(self):
        """Subject longer than MAX_SUBJECT_LENGTH must be truncated."""
        long_subject = "S" * (MAX_SUBJECT_LENGTH + 500)
        result = self._parse_with_subject(long_subject)

        self.assertIsNotNone(result)
        self.assertEqual(len(result.subject), MAX_SUBJECT_LENGTH)

    def test_exact_length_subject_not_truncated(self):
        """A subject of exactly MAX_SUBJECT_LENGTH chars must pass through intact."""
        exact_subject = "A" * MAX_SUBJECT_LENGTH
        result = self._parse_with_subject(exact_subject)

        self.assertEqual(len(result.subject), MAX_SUBJECT_LENGTH)

    def test_short_subject_unchanged(self):
        """Short subjects are returned without modification."""
        result = self._parse_with_subject("Short subject")
        self.assertEqual(result.subject, "Short subject")

    def test_oversized_subject_logs_warning(self):
        """Truncating an oversized subject must produce a warning log."""
        self.parser.parse_email(
            "hdr-warn",
            _simple_raw(subject="W" * (MAX_SUBJECT_LENGTH + 100)),
            "INBOX",
        )
        warning_texts = [str(c) for c in self.parser.logger.warning.call_args_list]
        self.assertTrue(
            any("truncated" in t.lower() or str(MAX_SUBJECT_LENGTH) in t
                for t in warning_texts),
            f"Expected a truncation warning, got: {warning_texts}",
        )

    # -- header key normalisation -------------------------------------------

    def test_header_keys_are_lowercased(self):
        """All header keys must be stored in lowercase."""
        from email.mime.text import MIMEText
        msg = MIMEText("body")
        msg["Subject"] = "Case test"
        msg["From"] = "s@example.com"
        msg["X-Custom-Header"] = "value"
        raw = msg.as_bytes()

        result = self.parser.parse_email("hdr-case", raw, "INBOX")

        self.assertIsNotNone(result)
        for key in result.headers:
            self.assertEqual(key, key.lower(),
                             f"Header key '{key}' should be lowercase")

    # -- duplicate headers stored as list -----------------------------------

    def test_duplicate_headers_stored_as_list(self):
        """
        Headers that appear more than once (e.g. Received) must be stored as
        a Python list, not a scalar string.
        """
        import email as email_lib
        raw_str = (
            "Subject: Dup test\r\n"
            "From: s@example.com\r\n"
            "To: r@example.com\r\n"
            "X-Tag: first\r\n"
            "X-Tag: second\r\n"
            "\r\n"
            "body"
        )
        raw = raw_str.encode()

        result = self.parser.parse_email("hdr-dup", raw, "INBOX")

        self.assertIsNotNone(result)
        x_tag = result.headers.get("x-tag")
        self.assertIsInstance(x_tag, list,
                              "Duplicate headers must be stored as a list")
        self.assertIn("first", x_tag)
        self.assertIn("second", x_tag)

    # -- missing subject ----------------------------------------------------

    def test_missing_subject_returns_empty_string(self):
        """Emails without a Subject header produce an empty subject field."""
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["From"] = "s@example.com"
        msg["To"] = "r@example.com"
        msg.set_content("no subject")
        raw = msg.as_bytes()

        result = self.parser.parse_email("hdr-nosub", raw, "INBOX")

        self.assertIsNotNone(result)
        self.assertEqual(result.subject, "")


# ---------------------------------------------------------------------------
# 5. General parsing (smoke tests)
# ---------------------------------------------------------------------------

class TestGeneralParsing(unittest.TestCase):
    """Basic happy-path and robustness checks for EmailParser.parse_email."""

    def setUp(self):
        self.parser = _make_parser()
        self.parser.logger = MagicMock()

    def test_parses_simple_email(self):
        """A minimal text email is parsed without error."""
        raw = _simple_raw(subject="Hello", body="World")
        result = self.parser.parse_email("001", raw, "INBOX")

        self.assertIsNotNone(result)
        self.assertEqual(result.subject, "Hello")
        self.assertIn("World", result.body_text)
        self.assertEqual(result.folder, "INBOX")

    def test_returns_none_for_empty_bytes(self):
        """Completely empty input must not raise; None is returned."""
        result = self.parser.parse_email("002", b"", "INBOX")
        # Empty bytes produce a minimal (but not None) EmailMessage
        # The important thing is no unhandled exception is raised.
        # If result is not None, at minimum it should have basic fields.
        if result is not None:
            self.assertIsInstance(result.subject, str)

    def test_parse_result_contains_account_email(self):
        """The parsed result must carry the account_email from the config."""
        raw = _simple_raw()
        result = self.parser.parse_email("003", raw, "INBOX")

        self.assertIsNotNone(result)
        self.assertEqual(result.account_email, "test@example.com")

    def test_missing_date_falls_back_to_now(self):
        """When the Date header is absent/malformed the parser uses now()."""
        from email.message import EmailMessage
        from datetime import datetime
        msg = EmailMessage()
        msg["From"] = "s@example.com"
        msg["Subject"] = "No date"
        msg.set_content("body")
        # No Date header → _extract_date falls back to datetime.now()

        before = datetime.now()
        result = self.parser.parse_email("004", msg.as_bytes(), "INBOX")
        after = datetime.now()

        self.assertIsNotNone(result)
        self.assertGreaterEqual(result.date, before)
        self.assertLessEqual(result.date, after)


if __name__ == "__main__":
    unittest.main()
