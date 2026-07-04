import re

with open("tests/test_multi_account.py", "r") as f:
    content = f.read()

# Refactor the function definition
old_def = r"    def _create_mock_email\(self, msg_id, subject, sender, recipient, account_email\):"
new_def = "    def _create_mock_email(self, msg_id, **kwargs):"
content = re.sub(old_def, new_def, content)

old_return = r"""        return EmailData\(
            message_id=msg_id,
            subject=subject,
            sender=sender,
            recipient=recipient,
            date=datetime\.now\(\),
            body_text="Body",
            body_html="",
            headers=\{\},
            attachments=\[\],
            raw_email=MagicMock\(\),
            account_email=account_email,
            folder="INBOX",
        \)"""
new_return = """        return EmailData(
            message_id=msg_id,
            subject=kwargs.get("subject", ""),
            sender=kwargs.get("sender", ""),
            recipient=kwargs.get("recipient", ""),
            date=datetime.now(),
            body_text="Body",
            body_html="",
            headers={},
            attachments=[],
            raw_email=MagicMock(),
            account_email=kwargs.get("account_email", ""),
            folder="INBOX",
        )"""
content = re.sub(old_return, new_return, content)

# Refactor email1 call site
old_email1 = r"""        email1 = self\._create_mock_email\(
            "email-1",
            "Email from Account 1",
            "sender1@example\.com",
            "user1@example\.com",
            "user1@example\.com",
        \)"""
new_email1 = """        email1 = self._create_mock_email(
            "email-1",
            subject="Email from Account 1",
            sender="sender1@example.com",
            recipient="user1@example.com",
            account_email="user1@example.com",
        )"""
content = re.sub(old_email1, new_email1, content)

# Refactor email2 call site
old_email2 = r"""        email2 = self\._create_mock_email\(
            "email-2",
            "Email from Account 2",
            "sender2@different\.com",
            "user2@different\.com",
            "user2@different\.com",
        \)"""
new_email2 = """        email2 = self._create_mock_email(
            "email-2",
            subject="Email from Account 2",
            sender="sender2@different.com",
            recipient="user2@different.com",
            account_email="user2@different.com",
        )"""
content = re.sub(old_email2, new_email2, content)

# Refactor many_emails call site
old_many = r"""            self\._create_mock_email\(
                f"email-\{i\}",
                f"Email \{i\}",
                "sender@example\.com",
                "user1@example\.com",
                "user1@example\.com",
            \)"""
new_many = """            self._create_mock_email(
                f"email-{i}",
                subject=f"Email {i}",
                sender="sender@example.com",
                recipient="user1@example.com",
                account_email="user1@example.com",
            )"""
content = re.sub(old_many, new_many, content)


with open("tests/test_multi_account.py", "w") as f:
    f.write(content)
