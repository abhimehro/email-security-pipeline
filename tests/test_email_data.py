"""
Unit tests for src/modules/email_data.py

PATTERN RECOGNITION: EmailData is a plain dataclass — the foundation for all
analysis modules.  Every field that enters from the outside world (subject,
sender, body, headers, attachments) is stored verbatim in EmailData and later
consumed by spam, NLP, and media analysers.

SECURITY STORY: Bugs in the data container (wrong types, missing None-guards)
can corrupt downstream analysis silently. These tests pin the contract of
EmailData so regressions are caught before they cascade through the pipeline.

MAINTENANCE WISDOM: EmailData has no methods to mock, so every test is
pure-Python with zero external dependencies. This makes the suite fast and
immune to environment issues.
"""

import unittest
from datetime import datetime
from email.message import Message

from src.modules.email_data import EmailData


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_email(**overrides) -> EmailData:
    """Return a fully populated EmailData; keyword overrides replace defaults."""
    defaults = dict(
        message_id="<test-id@example.com>",
        subject="Test Subject",
        sender="sender@example.com",
        recipient="recipient@example.com",
        date=datetime(2024, 1, 15, 12, 0, 0),
        body_text="Hello, this is the email body.",
        body_html="<p>Hello, this is the email body.</p>",
        headers={"subject": "Test Subject", "from": "sender@example.com"},
        attachments=[],
        raw_email=Message(),
        account_email="account@example.com",
        folder="INBOX",
    )
    defaults.update(overrides)
    return EmailData(**defaults)


# ---------------------------------------------------------------------------
# 1. Basic initialisation
# ---------------------------------------------------------------------------

class TestEmailDataInit(unittest.TestCase):
    """EmailData stores every field exactly as supplied."""

    def test_all_fields_stored(self):
        """All supplied values must be accessible via the expected attributes."""
        raw = Message()
        raw["Subject"] = "Raw Subject"
        date = datetime(2024, 6, 1, 8, 30, 0)

        email = EmailData(
            message_id="<abc@mail.example.com>",
            subject="Hello",
            sender="alice@example.com",
            recipient="bob@example.com",
            date=date,
            body_text="Plain text body",
            body_html="<b>HTML body</b>",
            headers={"from": "alice@example.com", "to": "bob@example.com"},
            attachments=[{"filename": "doc.pdf", "size": 1024}],
            raw_email=raw,
            account_email="alice@example.com",
            folder="INBOX",
        )

        self.assertEqual(email.message_id, "<abc@mail.example.com>")
        self.assertEqual(email.subject, "Hello")
        self.assertEqual(email.sender, "alice@example.com")
        self.assertEqual(email.recipient, "bob@example.com")
        self.assertEqual(email.date, date)
        self.assertEqual(email.body_text, "Plain text body")
        self.assertEqual(email.body_html, "<b>HTML body</b>")
        self.assertEqual(email.headers["from"], "alice@example.com")
        self.assertEqual(len(email.attachments), 1)
        self.assertIs(email.raw_email, raw)
        self.assertEqual(email.account_email, "alice@example.com")
        self.assertEqual(email.folder, "INBOX")

    def test_default_helper_returns_valid_object(self):
        """_make_email() helper must produce an EmailData without raising."""
        email = _make_email()
        self.assertIsInstance(email, EmailData)

    def test_is_dataclass(self):
        """EmailData must be a dataclass (has __dataclass_fields__)."""
        import dataclasses
        self.assertTrue(dataclasses.is_dataclass(EmailData))


# ---------------------------------------------------------------------------
# 2. Field type contracts
# ---------------------------------------------------------------------------

class TestEmailDataFieldTypes(unittest.TestCase):
    """
    PATTERN RECOGNITION: Downstream analysers cast fields to str, iterate
    attachments as list, and look up keys in headers as dict. Getting the
    types wrong here causes AttributeError/TypeError in analysers.
    """

    def test_message_id_is_string(self):
        email = _make_email()
        self.assertIsInstance(email.message_id, str)

    def test_subject_is_string(self):
        email = _make_email()
        self.assertIsInstance(email.subject, str)

    def test_sender_is_string(self):
        email = _make_email()
        self.assertIsInstance(email.sender, str)

    def test_recipient_is_string(self):
        email = _make_email()
        self.assertIsInstance(email.recipient, str)

    def test_date_is_datetime(self):
        email = _make_email()
        self.assertIsInstance(email.date, datetime)

    def test_body_text_is_string(self):
        email = _make_email()
        self.assertIsInstance(email.body_text, str)

    def test_body_html_is_string(self):
        email = _make_email()
        self.assertIsInstance(email.body_html, str)

    def test_headers_is_dict(self):
        email = _make_email()
        self.assertIsInstance(email.headers, dict)

    def test_attachments_is_list(self):
        email = _make_email()
        self.assertIsInstance(email.attachments, list)

    def test_raw_email_is_message(self):
        email = _make_email()
        self.assertIsInstance(email.raw_email, Message)

    def test_account_email_is_string(self):
        email = _make_email()
        self.assertIsInstance(email.account_email, str)

    def test_folder_is_string(self):
        email = _make_email()
        self.assertIsInstance(email.folder, str)


# ---------------------------------------------------------------------------
# 3. None / empty value handling
# ---------------------------------------------------------------------------

class TestEmailDataNoneAndEmptyValues(unittest.TestCase):
    """
    SECURITY STORY: Analysers may receive emails with missing headers or empty
    bodies. The container must accept None/empty without raising, deferring
    validation to the individual analysers.
    """

    def test_empty_subject_accepted(self):
        email = _make_email(subject="")
        self.assertEqual(email.subject, "")

    def test_empty_body_text_accepted(self):
        email = _make_email(body_text="")
        self.assertEqual(email.body_text, "")

    def test_empty_body_html_accepted(self):
        email = _make_email(body_html="")
        self.assertEqual(email.body_html, "")

    def test_empty_headers_dict(self):
        email = _make_email(headers={})
        self.assertEqual(email.headers, {})

    def test_empty_attachments_list(self):
        email = _make_email(attachments=[])
        self.assertEqual(email.attachments, [])

    def test_none_message_id_accepted(self):
        """
        MAINTENANCE WISDOM: Some mail servers omit Message-ID entirely.
        The parser may store None; downstream code must guard against it.
        Storing None in the container itself must not raise.
        """
        email = _make_email(message_id=None)
        self.assertIsNone(email.message_id)

    def test_none_date_accepted(self):
        """Emails may arrive with a missing/unparseable Date header."""
        email = _make_email(date=None)
        self.assertIsNone(email.date)

    def test_none_sender_accepted(self):
        email = _make_email(sender=None)
        self.assertIsNone(email.sender)

    def test_none_recipient_accepted(self):
        email = _make_email(recipient=None)
        self.assertIsNone(email.recipient)

    def test_none_body_text_accepted(self):
        email = _make_email(body_text=None)
        self.assertIsNone(email.body_text)

    def test_none_body_html_accepted(self):
        email = _make_email(body_html=None)
        self.assertIsNone(email.body_html)


# ---------------------------------------------------------------------------
# 4. Headers — multi-value and duplicate-key support
# ---------------------------------------------------------------------------

class TestEmailDataHeaders(unittest.TestCase):
    """
    PATTERN RECOGNITION: The type annotation is Dict[str, Union[str, List[str]]].
    Headers that appear multiple times in a raw email (e.g. 'Received') are
    stored as lists; single-occurrence headers remain plain strings.
    """

    def test_single_value_header_stored_as_string(self):
        email = _make_email(headers={"subject": "Hello"})
        self.assertIsInstance(email.headers["subject"], str)

    def test_multi_value_header_stored_as_list(self):
        """
        INDUSTRY CONTEXT: 'Received' headers appear once per hop. Storing them
        as a list preserves the full routing trace for anti-spoofing analysis.
        """
        received = [
            "from mx1.example.com by mx2.example.com",
            "from smtp.example.com by mx1.example.com",
        ]
        email = _make_email(headers={"received": received})
        self.assertIsInstance(email.headers["received"], list)
        self.assertEqual(len(email.headers["received"]), 2)

    def test_headers_keys_are_accessible(self):
        headers = {
            "from": "alice@example.com",
            "to": "bob@example.com",
            "subject": "Hi",
            "dkim-signature": "v=1; a=rsa-sha256;",
        }
        email = _make_email(headers=headers)
        for key in headers:
            self.assertIn(key, email.headers)

    def test_headers_are_mutable(self):
        """
        MAINTENANCE WISDOM: EmailData is a plain dataclass (not frozen), so
        downstream code can add normalised keys without copying the whole object.
        """
        email = _make_email(headers={"subject": "Original"})
        email.headers["x-custom"] = "added-later"
        self.assertEqual(email.headers["x-custom"], "added-later")


# ---------------------------------------------------------------------------
# 5. Attachments structure
# ---------------------------------------------------------------------------

class TestEmailDataAttachments(unittest.TestCase):
    """
    SECURITY STORY: Attachment metadata drives the media analyser. If the
    structure deviates from what is expected (missing 'filename', wrong types),
    the analyser will raise KeyError — a silent pipeline abort.
    """

    def test_single_attachment_stored(self):
        attachment = {
            "filename": "invoice.pdf",
            "content_type": "application/pdf",
            "size": 2048,
            "data": b"%PDF-1.4 ...",
        }
        email = _make_email(attachments=[attachment])
        self.assertEqual(len(email.attachments), 1)
        self.assertEqual(email.attachments[0]["filename"], "invoice.pdf")

    def test_multiple_attachments_stored(self):
        attachments = [
            {"filename": "a.txt", "size": 100},
            {"filename": "b.png", "size": 50000},
            {"filename": "c.zip", "size": 1024 * 1024},
        ]
        email = _make_email(attachments=attachments)
        self.assertEqual(len(email.attachments), 3)
        names = [a["filename"] for a in email.attachments]
        self.assertIn("a.txt", names)
        self.assertIn("b.png", names)
        self.assertIn("c.zip", names)

    def test_attachments_list_is_mutable(self):
        """Downstream code may append parsed metadata to the list."""
        email = _make_email(attachments=[])
        email.attachments.append({"filename": "new.doc", "size": 512})
        self.assertEqual(len(email.attachments), 1)


# ---------------------------------------------------------------------------
# 6. Dataclass equality and identity
# ---------------------------------------------------------------------------

class TestEmailDataEquality(unittest.TestCase):
    """
    PATTERN RECOGNITION: Dataclass equality compares field values, which
    allows deduplication of identical emails in tests without needing custom
    __eq__ logic.
    """

    def test_two_identical_instances_are_equal(self):
        raw = Message()
        date = datetime(2024, 1, 1)
        kwargs = dict(
            message_id="<id@example.com>",
            subject="Subject",
            sender="a@example.com",
            recipient="b@example.com",
            date=date,
            body_text="body",
            body_html="<p>body</p>",
            headers={},
            attachments=[],
            raw_email=raw,
            account_email="a@example.com",
            folder="INBOX",
        )
        email1 = EmailData(**kwargs)
        email2 = EmailData(**kwargs)
        self.assertEqual(email1, email2)

    def test_differing_subjects_are_not_equal(self):
        email1 = _make_email(subject="Alpha")
        email2 = _make_email(subject="Beta")
        self.assertNotEqual(email1, email2)

    def test_differing_folders_are_not_equal(self):
        email1 = _make_email(folder="INBOX")
        email2 = _make_email(folder="Spam")
        self.assertNotEqual(email1, email2)


# ---------------------------------------------------------------------------
# 7. Field mutation (non-frozen dataclass)
# ---------------------------------------------------------------------------

class TestEmailDataMutability(unittest.TestCase):
    """
    MAINTENANCE WISDOM: EmailData is not frozen, so analysers can annotate it
    in-place (e.g. normalise subject whitespace) without the overhead of
    copying. This suite confirms mutation is possible and isolated per instance.
    """

    def test_subject_can_be_updated(self):
        email = _make_email(subject="  Extra whitespace  ")
        email.subject = email.subject.strip()
        self.assertEqual(email.subject, "Extra whitespace")

    def test_mutation_does_not_affect_other_instance(self):
        email1 = _make_email(subject="Original")
        email2 = _make_email(subject="Original")
        email1.subject = "Modified"
        self.assertEqual(email2.subject, "Original")

    def test_folder_can_be_updated(self):
        email = _make_email(folder="INBOX")
        email.folder = "Sent"
        self.assertEqual(email.folder, "Sent")


# ---------------------------------------------------------------------------
# 8. Missing required field raises TypeError
# ---------------------------------------------------------------------------

class TestEmailDataMissingFields(unittest.TestCase):
    """
    SECURITY STORY: Callers that forget a required field get an immediate
    TypeError at construction time, not a silent AttributeError buried in an
    analyser deep in the call stack.
    """

    def test_missing_message_id_raises(self):
        with self.assertRaises(TypeError):
            EmailData(
                # message_id omitted
                subject="Hi",
                sender="a@example.com",
                recipient="b@example.com",
                date=datetime.now(),
                body_text="",
                body_html="",
                headers={},
                attachments=[],
                raw_email=Message(),
                account_email="a@example.com",
                folder="INBOX",
            )

    def test_missing_folder_raises(self):
        with self.assertRaises(TypeError):
            EmailData(
                message_id="<id@example.com>",
                subject="Hi",
                sender="a@example.com",
                recipient="b@example.com",
                date=datetime.now(),
                body_text="",
                body_html="",
                headers={},
                attachments=[],
                raw_email=Message(),
                account_email="a@example.com",
                # folder omitted
            )

    def test_no_arguments_raises(self):
        with self.assertRaises(TypeError):
            EmailData()


# ---------------------------------------------------------------------------
# 9. Raw email field stores an email.message.Message object
# ---------------------------------------------------------------------------

class TestEmailDataRawEmail(unittest.TestCase):
    """
    INDUSTRY CONTEXT: raw_email preserves the original parsed MIME object so
    that modules can re-inspect MIME structure without re-parsing bytes.
    """

    def test_raw_email_headers_accessible(self):
        """Headers set on the Message must be readable through raw_email."""
        raw = Message()
        raw["Subject"] = "Original Subject"
        raw["From"] = "sender@example.com"

        email = _make_email(raw_email=raw)

        self.assertEqual(email.raw_email["Subject"], "Original Subject")
        self.assertEqual(email.raw_email["From"], "sender@example.com")

    def test_raw_email_is_same_object(self):
        """EmailData must store the exact Message instance, not a copy."""
        raw = Message()
        email = _make_email(raw_email=raw)
        self.assertIs(email.raw_email, raw)


# ---------------------------------------------------------------------------
# 10. Repr / str representation
# ---------------------------------------------------------------------------

class TestEmailDataRepr(unittest.TestCase):
    """
    MAINTENANCE WISDOM: Dataclass __repr__ makes debugging much easier — the
    default representation includes all field names and values.
    """

    def test_repr_contains_class_name(self):
        email = _make_email()
        self.assertIn("EmailData", repr(email))

    def test_repr_contains_message_id(self):
        email = _make_email(message_id="<unique-id@test.example>")
        self.assertIn("unique-id@test.example", repr(email))


if __name__ == "__main__":
    unittest.main()
