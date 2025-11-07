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
from email.header import decode_header, make_header
from dataclasses import dataclass
from datetime import datetime

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

    def __init__(self, config: EmailAccountConfig, rate_limit_delay: int = 1):
        """
        Initialize IMAP client

        Args:
            config: Email account configuration
            rate_limit_delay: Delay between operations (seconds)
        """
        self.config = config
        self.rate_limit_delay = rate_limit_delay
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

    def disconnect(self):
        """Close IMAP connection"""
        if self.connection:
            try:
                self.connection.logout()
                self.logger.info("Disconnected from IMAP server")
            except Exception as e:
                self.logger.error(f"Error during disconnect: {e}")

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
                    if status == "OK":
                        emails.append((email_id.decode(), data[0][1]))
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
            headers = {}
            for key, value in msg.items():
                headers[key] = value

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
                        try:
                            body_text += part.get_payload(decode=True).decode(errors='ignore')
                        except Exception:
                            pass

                    # Extract HTML body
                    elif content_type == "text/html" and "attachment" not in content_disposition:
                        try:
                            body_html += part.get_payload(decode=True).decode(errors='ignore')
                        except Exception:
                            pass

                    # Extract attachments
                    elif "attachment" in content_disposition:
                        filename = part.get_filename()
                        if filename:
                            attachments.append({
                                "filename": filename,
                                "content_type": content_type,
                                "size": len(part.get_payload(decode=True) or b""),
                                "data": part.get_payload(decode=True)
                            })
            else:
                # Single part message
                content_type = msg.get_content_type()
                try:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        decoded = payload.decode(errors='ignore')
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
                subject=msg.get("Subject", ""),
                sender=msg.get("From", ""),
                recipient=msg.get("To", ""),
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


class EmailIngestionManager:
    """Manages email ingestion from multiple accounts"""

    def __init__(self, accounts: List[EmailAccountConfig], rate_limit_delay: int = 1):
        """
        Initialize ingestion manager

        Args:
            accounts: List of email account configurations
            rate_limit_delay: Delay between operations
        """
        self.accounts = accounts
        self.rate_limit_delay = rate_limit_delay
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

            client = IMAPClient(account, self.rate_limit_delay)
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
