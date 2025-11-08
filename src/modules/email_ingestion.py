"""
Email Ingestion Module
Handles IMAP connection and email retrieval from multiple providers
"""

import imaplib
import email
import time
import logging
from typing import Any, Dict, List, Optional, Tuple
from email.message import Message
from dataclasses import dataclass
from datetime import datetime
from email.header import decode_header, make_header
from email.utils import getaddresses

from ..utils.config import EmailAccountConfig


@dataclass
class EmailData:
    """Container for email data"""
    message_id: str
    subject: str
    sender: str
    recipient: str
    date: datetime
    body_text: str
    body_html: str
    headers: Dict[str, str]
    attachments: List[Dict[str, Any]]
    raw_email: Message
    account_email: str
    folder: str


class IMAPClient:
    """IMAP client for connecting to email servers"""

    def __init__(
        self,
        config: EmailAccountConfig,
        rate_limit_delay: int = 1,
        max_attachment_bytes: int = 25 * 1024 * 1024,
    ):
        """
        Initialize IMAP client

        Args:
            config: Email account configuration
            rate_limit_delay: Delay between operations (seconds)
            max_attachment_bytes: Maximum attachment bytes retained for analysis
        """
        self.config = config
        self.rate_limit_delay = rate_limit_delay
        self.max_attachment_bytes = max_attachment_bytes
        self.connection: Optional[imaplib.IMAP4_SSL] = None
        self.logger = logging.getLogger(f"IMAPClient.{config.provider}")

    def connect(self) -> bool:
        """
        Establish connection to IMAP server

        Returns:
            True if connection successful
        """
        try:
            self.logger.info(f"Connecting to {self.config.imap_server}:{self.config.imap_port}")

            self.connection = imaplib.IMAP4_SSL(
                self.config.imap_server,
                self.config.imap_port
            )

            self.connection.login(self.config.email, self.config.app_password)
            self.logger.info(f"Successfully connected to {self.config.email}")
            return True

        except imaplib.IMAP4.error as e:
            self.logger.error(f"IMAP connection error: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected connection error: {e}")
            return False

    def ensure_connection(self) -> bool:
        """Ensure the IMAP connection is alive, reconnecting if necessary."""
        if not self.connection:
            return self.connect()
        try:
            self.connection.noop()
            return True
        except Exception as exc:
            self.logger.warning(f"IMAP connection lost ({exc}), attempting reconnect")
            self.disconnect()
            return self.connect()

    def disconnect(self):
        """Close IMAP connection"""
        if not self.connection:
            return

        try:
            self.connection.logout()
            self.logger.info("Disconnected from IMAP server")
        except Exception:
            # Connection may already be closed, ignore
            self.logger.debug("Connection was already closed or logout failed")
        finally:
            self.connection = None

    def list_folders(self) -> List[str]:
        """
        List available folders

        Returns:
            List of folder names
        """
        if not self.connection:
            return []

        try:
            status, folders = self.connection.list()
            if status == "OK":
                folder_names = []
                for folder in folders:
                    # Parse folder names from response
                    parts = folder.decode().split('"')
                    if len(parts) >= 3:
                        folder_names.append(parts[-2])
                return folder_names
        except Exception as e:
            self.logger.error(f"Error listing folders: {e}")

        return []

    def select_folder(self, folder: str) -> bool:
        """
        Select a folder for operations

        Args:
            folder: Folder name

        Returns:
            True if folder selected successfully
        """
        if not self.connection:
            return False

        try:
            status, data = self.connection.select(folder)
            if status == "OK":
                self.logger.debug(f"Selected folder: {folder}")
                return True
            else:
                self.logger.warning(f"Could not select folder {folder}: {status}")
                return False
        except Exception as e:
            self.logger.error(f"Error selecting folder {folder}: {e}")
            return False

    def fetch_unseen_emails(self, folder: str, limit: int = 50) -> List[Tuple[str, bytes]]:
        """
        Fetch unseen emails from folder

        Args:
            folder: Folder name
            limit: Maximum number of emails to fetch

        Returns:
            List of (email_id, raw_email) tuples
        """
        if not self.select_folder(folder):
            return []

        try:
            # Search for unseen messages
            status, messages = self.connection.search(None, "UNSEEN")

            if status != "OK":
                self.logger.warning(f"Search failed in {folder}")
                return []

            email_ids = messages[0].split()

            if not email_ids:
                self.logger.debug(f"No unseen emails in {folder}")
                return []

            # Limit number of emails to fetch
            email_ids = email_ids[:limit]

            self.logger.info(f"Found {len(email_ids)} unseen emails in {folder}")

            emails = []
            for email_id in email_ids:
                time.sleep(self.rate_limit_delay)  # Rate limiting

                try:
                    status, data = self.connection.fetch(email_id, "(RFC822)")
                    if status == "OK" and data and data[0]:
                        raw_bytes = data[0][1]
                        if isinstance(raw_bytes, bytes):
                            emails.append((email_id.decode(), raw_bytes))
                        else:
                            self.logger.warning(f"Unexpected payload type for email {email_id}: {type(raw_bytes)}")
                except Exception as e:
                    self.logger.error(f"Error fetching email {email_id}: {e}")

            return emails

        except Exception as e:
            self.logger.error(f"Error in fetch_unseen_emails: {e}")
            return []

    def parse_email(self, email_id: str, raw_email: bytes, folder: str) -> Optional[EmailData]:
        """
        Parse raw email into EmailData object

        Args:
            email_id: Email ID
            raw_email: Raw email bytes
            folder: Source folder

        Returns:
            EmailData object or None if parsing fails
        """
        try:
            msg = email.message_from_bytes(raw_email)

            # Extract headers
            headers = {key: self._decode_header_value(value) for key, value in msg.items()}

            subject = self._decode_header_value(msg.get("Subject", ""))
            sender = self._format_addresses(msg.get("From", ""))
            recipient = self._format_addresses(msg.get("To", ""))

            # Extract body
            body_text = ""
            body_html = ""
            attachments = []

            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition", ""))

                    # Extract text body
                    if content_type == "text/plain" and "attachment" not in content_disposition:
                        body_text += self._decode_part_payload(part)

                    # Extract HTML body
                    elif content_type == "text/html" and "attachment" not in content_disposition:
                        body_html += self._decode_part_payload(part)

                    # Extract attachments
                    elif "attachment" in content_disposition:
                        filename = self._decode_header_value(part.get_filename() or "")
                        if filename:
                            payload = part.get_payload(decode=True) or b""
                            original_size = len(payload)
                            truncated = False
                            if self.max_attachment_bytes > 0 and original_size > self.max_attachment_bytes:
                                self.logger.warning(
                                    "Attachment %s exceeds max size (%d bytes); truncating for analysis",
                                    filename,
                                    original_size,
                                )
                                payload = payload[:self.max_attachment_bytes]
                                truncated = True
                            attachments.append({
                                "filename": filename,
                                "content_type": content_type,
                                "size": original_size,
                                "data": payload,
                                "truncated": truncated,
                            })
            else:
                # Single part message
                content_type = msg.get_content_type()
                try:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        decoded = self._decode_bytes(payload, msg.get_content_charset())
                        if content_type == "text/html":
                            body_html = decoded
                        else:
                            body_text = decoded
                except Exception:
                    pass

            # Parse date
            date_str = msg.get("Date", "")
            try:
                date = email.utils.parsedate_to_datetime(date_str)
            except Exception:
                date = datetime.now()

            return EmailData(
                message_id=msg.get("Message-ID", email_id),
                subject=subject,
                sender=sender,
                recipient=recipient,
                date=date,
                body_text=body_text,
                body_html=body_html,
                headers=headers,
                attachments=attachments,
                raw_email=msg,
                account_email=self.config.email,
                folder=folder
            )

        except Exception as e:
            self.logger.error(f"Error parsing email {email_id}: {e}")
            return None

    @staticmethod
    def _decode_header_value(value: str) -> str:
        if not value:
            return ""
        try:
            return str(make_header(decode_header(value)))
        except Exception:
            return value

    @classmethod
    def _format_addresses(cls, header_value: str) -> str:
        if not header_value:
            return ""
        formatted = []
        for name, address in getaddresses([header_value]):
            name_clean = cls._decode_header_value(name)
            if name_clean and address:
                formatted.append(f"{name_clean} <{address}>")
            elif address:
                formatted.append(address)
            elif name_clean:
                formatted.append(name_clean)
        return ", ".join(formatted)

    @staticmethod
    def _decode_part_payload(part: Message) -> str:
        payload = part.get_payload(decode=True)
        if not payload:
            return ""
        return IMAPClient._decode_bytes(payload, part.get_content_charset())

    @staticmethod
    def _decode_bytes(data: bytes, charset: Optional[str]) -> str:
        encoding = charset or "utf-8"
        try:
            return data.decode(encoding, errors="replace")
        except LookupError:
            return data.decode("utf-8", errors="replace")


class EmailIngestionManager:
    """Manages email ingestion from multiple accounts"""

    def __init__(
        self,
        accounts: List[EmailAccountConfig],
        rate_limit_delay: int = 1,
        max_attachment_bytes: int = 25 * 1024 * 1024,
    ):
        """
        Initialize ingestion manager

        Args:
            accounts: List of email account configurations
            rate_limit_delay: Delay between operations
            max_attachment_bytes: Maximum attachment bytes retained for analysis
        """
        self.accounts = accounts
        self.rate_limit_delay = rate_limit_delay
        self.max_attachment_bytes = max_attachment_bytes
        self.clients: Dict[str, IMAPClient] = {}
        self.logger = logging.getLogger("EmailIngestionManager")

    def initialize_clients(self) -> bool:
        """
        Initialize IMAP clients for all accounts

        Returns:
            True if at least one client connected successfully
        """
        success_count = 0

        for account in self.accounts:
            if not account.enabled:
                continue

            client = IMAPClient(account, self.rate_limit_delay, self.max_attachment_bytes)
            if client.connect():
                self.clients[account.email] = client
                success_count += 1
            else:
                self.logger.error(f"Failed to connect to {account.email}")

        if success_count == 0:
            self.logger.error("No email accounts connected successfully")
            return False

        self.logger.info(f"Connected to {success_count}/{len(self.accounts)} accounts")
        return True

    def fetch_all_emails(self, max_per_folder: int = 50) -> List[EmailData]:
        """
        Fetch emails from all configured accounts and folders

        Args:
            max_per_folder: Maximum emails to fetch per folder

        Returns:
            List of EmailData objects
        """
        all_emails = []

        for account in self.accounts:
            if not account.enabled or account.email not in self.clients:
                continue

            client = self.clients[account.email]

            for folder in account.folders:
                if not client.ensure_connection():
                    self.logger.error(f"Unable to reconnect to {account.email}; skipping remaining folders")
                    break

                self.logger.info(f"Fetching from {account.email}/{folder}")

                raw_emails = client.fetch_unseen_emails(folder, max_per_folder)

                for email_id, raw_email in raw_emails:
                    email_data = client.parse_email(email_id, raw_email, folder)
                    if email_data:
                        all_emails.append(email_data)

        self.logger.info(f"Fetched {len(all_emails)} emails total")
        return all_emails

    def close_all_connections(self):
        """Close all IMAP connections"""
        for client in self.clients.values():
            client.disconnect()
        self.clients.clear()
        self.logger.info("All connections closed")
