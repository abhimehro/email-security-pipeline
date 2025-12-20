"""
Email Ingestion Module
Handles IMAP connection and email retrieval from multiple providers
"""

import imaplib
import email
import time
import logging
import socket
import ssl
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
        max_total_attachment_bytes: int = 100 * 1024 * 1024,
        max_attachment_count: int = 10,
    ):
        """
        Initialize IMAP client

        Args:
            config: Email account configuration
            rate_limit_delay: Delay between operations (seconds)
            max_attachment_bytes: Maximum attachment bytes retained for analysis
            max_total_attachment_bytes: Maximum total size of all attachments per email
            max_attachment_count: Maximum number of attachments per email
        """
        self.config = config
        self.rate_limit_delay = rate_limit_delay
        self.max_attachment_bytes = max_attachment_bytes
        self.max_total_attachment_bytes = max_total_attachment_bytes
        self.max_attachment_count = max_attachment_count
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
            batch_size = 10  # Process in small batches to respect rate limits while improving speed

            for i in range(0, len(email_ids), batch_size):
                if i > 0:
                    time.sleep(self.rate_limit_delay)  # Rate limiting between batches

                batch_ids = email_ids[i : i + batch_size]
                # Join IDs with comma (b"1,2,3")
                ids_str = b",".join(batch_ids)

                try:
                    status, data = self.connection.fetch(ids_str, "(RFC822)")
                    if status == "OK" and isinstance(data, list):
                        for item in data:
                            if isinstance(item, tuple):
                                # item is (header, body)
                                # header is typically b'seq (RFC822 {size}'
                                header = item[0]
                                raw_bytes = item[1]

                                # Extract sequence number from header
                                # e.g. b'123 (RFC822 {456}' -> b'123'
                                try:
                                    msg_seq = header.split()[0]
                                    if isinstance(raw_bytes, bytes):
                                        emails.append((msg_seq.decode(), raw_bytes))
                                    else:
                                        self.logger.warning(
                                            f"Unexpected payload type for email {msg_seq}: {type(raw_bytes)}"
                                        )
                                except Exception as parse_err:
                                    self.logger.error(
                                        f"Error parsing email header {header}: {parse_err}"
                                    )

                    else:
                        self.logger.warning(
                            f"Failed to fetch batch {ids_str}: {status}"
                        )

                except Exception as e:
                    self.logger.error(f"Error fetching email batch {ids_str}: {e}")

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
            current_total_size = 0

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
                        # Check attachment count limit
                        if len(attachments) >= self.max_attachment_count:
                            self.logger.warning(
                                f"Max attachment count ({self.max_attachment_count}) reached for email {email_id}. Skipping remaining attachments."
                            )
                            continue

                        filename = self._decode_header_value(part.get_filename() or "")
                        if filename:
                            payload = part.get_payload(decode=True) or b""
                            original_size = len(payload)

                            # Check total size limit before adding
                            if self.max_total_attachment_bytes > 0 and (current_total_size + original_size) > self.max_total_attachment_bytes:
                                self.logger.warning(
                                    f"Max total attachment size ({self.max_total_attachment_bytes}) exceeded for email {email_id}. Skipping attachment {filename}."
                                )
                                continue

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
                            current_total_size += original_size
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

    def diagnose_connection_issues(self, account: EmailAccountConfig) -> Dict[str, Any]:
        """Diagnose IMAP connection issues"""
        diagnostics = {
            "server_reachable": self._check_server_reachability(account),
            "port_open": self._check_port_open(account),
            "ssl_valid": self._check_ssl_certificate(account),
            "credentials_valid": self._check_credentials(account),
        }
        return diagnostics

    def _check_server_reachability(self, account: EmailAccountConfig) -> Dict[str, Any]:
        """Check if the IMAP server is reachable via DNS and responds to ping."""
        result = {"host_resolved": None, "resolves_to": None, "error": None}
        try:
            ip_address = socket.gethostbyname(account.imap_server)
            result["host_resolved"] = True
            result["resolves_to"] = ip_address
        except socket.gaierror as e:
            result["host_resolved"] = False
            result["error"] = f"DNS lookup failed: {e}"
        return result

    def _check_port_open(self, account: EmailAccountConfig) -> Dict[str, Any]:
        """Check if the IMAP port is open and accepting connections."""
        result = {"open": False, "error": None}
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            try:
                if sock.connect_ex((account.imap_server, account.imap_port)) == 0:
                    result["open"] = True
            except Exception as e:
                result["error"] = f"Port check failed: {e}"
        return result

    def _check_ssl_certificate(self, account: EmailAccountConfig) -> Dict[str, Any]:
        """Validate the SSL certificate of the IMAP server."""
        result = {"valid": False, "expires_in_days": None, "error": None}
        try:
            # Create an SSL context that enforces TLS 1.2+ and validates certificates.
            if hasattr(ssl, "PROTOCOL_TLS_CLIENT"):
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.load_default_certs()
                context.check_hostname = True
                context.verify_mode = ssl.CERT_REQUIRED
            else:
                # Fallback for older Python versions without PROTOCOL_TLS_CLIENT.
                context = ssl.create_default_context()
            # Enforce a minimum TLS version of 1.2 to avoid insecure protocol versions.
            if hasattr(ssl, "TLSVersion"):
                context.minimum_version = ssl.TLSVersion.TLSv1_2
            else:
                # Fallback for older Python/OpenSSL versions: disable TLSv1 and TLSv1_1 explicitly.
                if hasattr(ssl, "OP_NO_TLSv1"):
                    context.options |= ssl.OP_NO_TLSv1
                if hasattr(ssl, "OP_NO_TLSv1_1"):
                    context.options |= ssl.OP_NO_TLSv1_1
            with socket.create_connection((account.imap_server, account.imap_port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=account.imap_server) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        result["valid"] = True
                        expiry_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        delta = expiry_date - datetime.now()
                        result["expires_in_days"] = delta.days
        except ssl.SSLCertVerificationError as e:
            result["error"] = f"SSL certificate verification failed: {e}"
        except Exception as e:
            result["error"] = f"SSL check failed: {e}"
        return result

    def _check_credentials(self, account: EmailAccountConfig) -> Dict[str, Any]:
        """Attempt a login to verify credentials."""
        result = {"valid": False, "error": None}
        try:
            conn = imaplib.IMAP4_SSL(account.imap_server, account.imap_port)
            conn.login(account.email, account.app_password)
            result["valid"] = True
            conn.logout()
        except imaplib.IMAP4.error as e:
            result["error"] = f"IMAP login failed: {e}"
        except Exception as e:
            result["error"] = f"Credential check failed with unexpected error: {e}"
        return result

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
        max_total_attachment_bytes: int = 100 * 1024 * 1024,
        max_attachment_count: int = 10,
    ):
        """
        Initialize ingestion manager

        Args:
            accounts: List of email account configurations
            rate_limit_delay: Delay between operations
            max_attachment_bytes: Maximum attachment bytes retained for analysis
            max_total_attachment_bytes: Maximum total size of all attachments per email
            max_attachment_count: Maximum number of attachments per email
        """
        self.accounts = accounts
        self.rate_limit_delay = rate_limit_delay
        self.max_attachment_bytes = max_attachment_bytes
        self.max_total_attachment_bytes = max_total_attachment_bytes
        self.max_attachment_count = max_attachment_count
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

            client = IMAPClient(
                account,
                self.rate_limit_delay,
                self.max_attachment_bytes,
                self.max_total_attachment_bytes,
                self.max_attachment_count
            )
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

    def diagnose_account_connection(self, email_address: str) -> Optional[Dict[str, Any]]:
        """
        Diagnose connection issues for a specific email account.

        Args:
            email_address: The email address of the account to diagnose.

        Returns:
            A dictionary with diagnostic results, or None if the account is not found.
        """
        account_to_diagnose = None
        for acc in self.accounts:
            if acc.email == email_address:
                account_to_diagnose = acc
                break

        if not account_to_diagnose:
            self.logger.error(f"Account '{email_address}' not found in configuration.")
            return None

        self.logger.info(f"Running diagnostics for {email_address}...")
        client = IMAPClient(account_to_diagnose, self.rate_limit_delay, self.max_attachment_bytes)
        return client.diagnose_connection_issues(account_to_diagnose)
