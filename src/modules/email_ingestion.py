"""
Email Ingestion Module
Handles IMAP connection and email retrieval from multiple providers
"""

import imaplib
import email
import os
import re
import time
import logging
import socket
import ssl
from typing import Any, Dict, List, Optional, Tuple, Union
from email.message import Message
from dataclasses import dataclass
from datetime import datetime
from email.header import decode_header, make_header
from email.utils import getaddresses

from ..utils.config import EmailAccountConfig
from ..utils.sanitization import sanitize_for_logging


# Security limits
MAX_SUBJECT_LENGTH = 1024

# Fallback maximum email size (500MB) to prevent DoS if no attachment limit is set
# This ensures we don't try to download indefinitely large emails in "unlimited" mode
DEFAULT_MAX_EMAIL_SIZE = 500 * 1024 * 1024


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
    headers: Dict[str, Union[str, List[str]]]
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
        # Set max email size based on attachment limits + 5MB overhead
        # If max_total_attachment_bytes is 0 (unlimited), we use a safe default of 500MB
        if max_total_attachment_bytes > 0:
            self.max_email_size = max_total_attachment_bytes + (5 * 1024 * 1024)
        else:
            self.max_email_size = DEFAULT_MAX_EMAIL_SIZE
        self.max_body_size = 1024 * 1024  # Default 1MB, overridden by manager
        self.connection: Optional[imaplib.IMAP4_SSL] = None
        self.logger = logging.getLogger(f"IMAPClient.{config.provider}")

    def _get_auth_tip(self, error_msg: str) -> Optional[str]:
        """Get actionable tip based on error and provider"""
        msg_lower = error_msg.lower()
        server_lower = self.config.imap_server.lower()

        # Check for authentication failures
        auth_keywords = ["authentication failed", "login failed", "invalid credentials", "logon failure", "authenticate"]
        if not any(k in msg_lower for k in auth_keywords):
            return None

        if "outlook" in server_lower or "office365" in server_lower:
            return "Personal Outlook/Hotmail accounts NO LONGER support passwords. You must use an App Password or OAuth (Enterprise)."

        if "gmail" in server_lower:
            return "Gmail requires 2-Step Verification enabled and an App Password to use IMAP."

        if "yahoo" in server_lower:
            return "Yahoo Mail requires an App Password generated from account security settings."

        return "Check your email and password. If using 2FA, you likely need an App Password."

    @staticmethod
    def _create_secure_ssl_context(verify_ssl: bool = True) -> ssl.SSLContext:
        """
        Create a secure SSL context with best practices.
        Enforces TLS 1.2+, and conditionally verifies certificates.
        """
        if hasattr(ssl, "PROTOCOL_TLS_CLIENT"):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_default_certs()
            context.check_hostname = verify_ssl
            context.verify_mode = ssl.CERT_REQUIRED if verify_ssl else ssl.CERT_NONE
        else:
            # Fallback for older Python versions without PROTOCOL_TLS_CLIENT.
            if hasattr(ssl, "PROTOCOL_TLS"):
                protocol = ssl.PROTOCOL_TLS
            else:
                protocol = ssl.PROTOCOL_SSLv23
            context = ssl.SSLContext(protocol)
            context.load_default_certs()
            context.check_hostname = verify_ssl
            context.verify_mode = ssl.CERT_REQUIRED if verify_ssl else ssl.CERT_NONE

        # Enforce a minimum TLS version of 1.2
        if hasattr(ssl, "TLSVersion"):
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        else:
            # Fallback for older Python/OpenSSL versions
            if hasattr(ssl, "OP_NO_TLSv1"):
                context.options |= ssl.OP_NO_TLSv1
            if hasattr(ssl, "OP_NO_TLSv1_1"):
                context.options |= ssl.OP_NO_TLSv1_1

        return context

    def connect(self) -> bool:
        """
        Establish connection to IMAP server

        Returns:
            True if connection successful
        """
        try:
            self.logger.info(f"Connecting to {self.config.imap_server}:{self.config.imap_port} (SSL={self.config.use_ssl})")

            context = self._create_secure_ssl_context(self.config.verify_ssl)

            if self.config.use_ssl:
                self.connection = imaplib.IMAP4_SSL(
                    self.config.imap_server,
                    self.config.imap_port,
                    ssl_context=context,
                    timeout=30  # Security: Prevent indefinite hangs
                )
            else:
                self.connection = imaplib.IMAP4(
                    self.config.imap_server,
                    self.config.imap_port,
                    timeout=30  # Security: Prevent indefinite hangs
                )
                self.connection.starttls(ssl_context=context)

            self.connection.login(self.config.email, self.config.app_password)
            self.logger.info(f"Successfully connected to {self.config.email}")
            return True

        except imaplib.IMAP4.error as e:
            self.logger.error(f"IMAP connection error: {e}")
            tip = self._get_auth_tip(str(e))
            if tip:
                self.logger.warning(f"💡 {tip}")
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
                safe_folder = sanitize_for_logging(folder)
                self.logger.debug(f"Selected folder: {safe_folder}")
                return True
            else:
                safe_folder = sanitize_for_logging(folder)
                self.logger.warning(f"Could not select folder {safe_folder}: {status}")
                return False
        except Exception as e:
            safe_folder = sanitize_for_logging(folder)
            self.logger.error(f"Error selecting folder {safe_folder}: {e}")
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

            safe_folder = sanitize_for_logging(folder)

            if status != "OK":
                self.logger.warning(f"Search failed in {safe_folder}")
                return []

            email_ids = messages[0].split()

            if not email_ids:
                self.logger.debug(f"No unseen emails in {safe_folder}")
                return []

            # Limit number of emails to fetch
            email_ids = email_ids[:limit]

            self.logger.info(f"Found {len(email_ids)} unseen emails in {safe_folder}")

            emails = []
            batch_size = 10  # Process in small batches to respect rate limits while improving speed

            for i in range(0, len(email_ids), batch_size):
                if i > 0:
                    time.sleep(self.rate_limit_delay)  # Rate limiting between batches

                batch_ids = email_ids[i : i + batch_size]
                # Join IDs with comma (b"1,2,3")
                ids_str = b",".join(batch_ids)

                try:
                    # 1. Check sizes first to prevent DoS
                    safe_ids = []
                    status, size_data = self.connection.fetch(ids_str, "(RFC822.SIZE)")

                    if status == "OK" and isinstance(size_data, list):
                        for item in size_data:
                            # Item is typically b'SEQ (RFC822.SIZE 12345)' or (b'SEQ (RFC822.SIZE 12345)', b'')
                            # imaplib can return different formats
                            info = item
                            if isinstance(item, tuple):
                                info = item[0]

                            if isinstance(info, bytes):
                                try:
                                    # Parse: b'1 (RFC822.SIZE 1024)'
                                    parts = info.split()
                                    seq = parts[0]
                                    # Find size in the string
                                    # Format is typically: SEQ (RFC822.SIZE <size>)
                                    # We look for the closing parenthesis or just last element
                                    # Safe parsing: look for RFC822.SIZE and take next element
                                    content = info.decode('ascii', errors='ignore')
                                    if 'RFC822.SIZE' in content:
                                        size_idx = content.find('RFC822.SIZE') + 11
                                        remaining = content[size_idx:].strip()
                                        # Remove trailing ')' if present
                                        size_str = remaining.split(')')[0].strip()
                                        size = int(size_str)

                                        if size > self.max_email_size:
                                            self.logger.warning(
                                                f"Skipping oversized email {seq.decode()} ({size} bytes > {self.max_email_size})"
                                            )
                                            continue

                                        safe_ids.append(seq)
                                except Exception as parse_err:
                                    self.logger.warning(f"Error parsing size for {info}: {parse_err}")
                                    continue

                    if not safe_ids:
                        continue

                    safe_ids_str = b",".join(safe_ids)

                    status, data = self.connection.fetch(safe_ids_str, "(RFC822)")
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
                            f"Failed to fetch batch {safe_ids_str}: {status}"
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

            # Extract headers with support for duplicates (e.g., Received)
            # Keys are normalized to lowercase to prevent case-sensitivity bypasses
            headers: Dict[str, Union[str, List[str]]] = {}
            for key, value in msg.items():
                key_lower = key.lower()
                decoded_val = self._decode_header_value(value)
                if key_lower in headers:
                    existing = headers[key_lower]
                    if isinstance(existing, list):
                        existing.append(decoded_val)
                    else:
                        headers[key_lower] = [existing, decoded_val]
                else:
                    headers[key_lower] = decoded_val

            subject = self._decode_header_value(msg.get("Subject", ""))
            if len(subject) > MAX_SUBJECT_LENGTH:
                subject = subject[:MAX_SUBJECT_LENGTH]
                self.logger.warning(f"Subject truncated to {MAX_SUBJECT_LENGTH} chars for email {email_id}")

            sender = self._format_addresses(msg.get("From", ""))
            recipient = self._format_addresses(msg.get("To", ""))

            # Extract body
            body_text = ""
            body_html = ""
            attachments = []
            current_total_size = 0

            safe_email_id = sanitize_for_logging(email_id)

            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition", ""))

                    # Extract text body
                    if content_type == "text/plain" and "attachment" not in content_disposition:
                        text_part = self._decode_part_payload(part)
                        if len(body_text) < self.max_body_size:
                            body_text += text_part
                            if len(body_text) > self.max_body_size:
                                body_text = body_text[:self.max_body_size]
                                self.logger.warning(f"Body text truncated to {self.max_body_size} bytes for email {safe_email_id}")

                    # Extract HTML body
                    elif content_type == "text/html" and "attachment" not in content_disposition:
                        html_part = self._decode_part_payload(part)
                        if len(body_html) < self.max_body_size:
                            body_html += html_part
                            if len(body_html) > self.max_body_size:
                                body_html = body_html[:self.max_body_size]
                                self.logger.warning(f"Body HTML truncated to {self.max_body_size} bytes for email {safe_email_id}")

                    # Extract attachments
                    elif "attachment" in content_disposition:
                        # Check attachment count limit
                        if len(attachments) >= self.max_attachment_count:
                            self.logger.warning(
                                f"Max attachment count ({self.max_attachment_count}) reached for email {safe_email_id}. Skipping remaining attachments."
                            )
                            continue

                        raw_filename = self._decode_header_value(part.get_filename() or "")
                        if raw_filename:
                            # Sanitize filename to prevent path traversal attacks
                            filename = self._sanitize_filename(raw_filename)
                            payload = part.get_payload(decode=True) or b""
                            original_size = len(payload)

                            safe_filename = sanitize_for_logging(filename)

                            # Check total size limit before adding
                            if self.max_total_attachment_bytes > 0 and (current_total_size + original_size) > self.max_total_attachment_bytes:
                                self.logger.warning(
                                    f"Max total attachment size ({self.max_total_attachment_bytes}) exceeded for email {safe_email_id}. Skipping attachment {safe_filename}."
                                )
                                continue

                            truncated = False
                            if self.max_attachment_bytes > 0 and original_size > self.max_attachment_bytes:
                                self.logger.warning(
                                    "Attachment %s exceeds max size (%d bytes); truncating for analysis",
                                    safe_filename,
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
                            if len(decoded) > self.max_body_size:
                                decoded = decoded[:self.max_body_size]
                                self.logger.warning(f"Body HTML truncated to {self.max_body_size} bytes for email {safe_email_id}")
                            body_html = decoded
                        else:
                            if len(decoded) > self.max_body_size:
                                decoded = decoded[:self.max_body_size]
                                self.logger.warning(f"Body text truncated to {self.max_body_size} bytes for email {safe_email_id}")
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
            safe_email_id = sanitize_for_logging(email_id)
            self.logger.error(f"Error parsing email {safe_email_id}: {e}")
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
            context = self._create_secure_ssl_context(self.config.verify_ssl)
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
            context = self._create_secure_ssl_context(self.config.verify_ssl)
            if account.use_ssl:
                conn = imaplib.IMAP4_SSL(account.imap_server, account.imap_port, ssl_context=context)
            else:
                conn = imaplib.IMAP4(account.imap_server, account.imap_port)
                conn.starttls(ssl_context=context)

            conn.login(account.email, account.app_password)
            result["valid"] = True
            conn.logout()
        except imaplib.IMAP4.error as e:
            result["error"] = f"IMAP login failed: {e}"
            tip = self._get_auth_tip(str(e))
            if tip:
                result["error"] += f" ({tip})"
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

    # Pre-compiled regex patterns for filename sanitization
    FILENAME_SANITIZE_PATTERN = re.compile(r'[^a-zA-Z0-9.\-_ ]')
    FILENAME_COLLAPSE_DOTS_PATTERN = re.compile(r'\.{2,}')

    @staticmethod
    def _sanitize_filename(filename: str) -> str:
        """
        Sanitize filename to prevent path traversal and ensure safety.

        Security: Prevents CWE-22 (Path Traversal) by:
        1. Normalizing path separators (cross-platform)
        2. Extracting only the basename (removes directory components)
        3. Whitelisting safe characters
        4. Preventing hidden files (leading dots)
        5. Collapsing multiple dots
        """
        if not filename:
            return ""

        # 1. Remove any directory components (basename only)
        # Handle both forward and backward slashes regardless of OS
        filename = os.path.basename(filename.replace('\\', '/'))

        # 2. Replace dangerous characters with underscore
        # Allow alphanumeric, dot, dash, underscore, space
        filename = IMAPClient.FILENAME_SANITIZE_PATTERN.sub('_', filename)

        # 3. Prevent hidden files (starting with dot)
        filename = filename.lstrip('.')

        # 4. Collapse multiple dots (e.g., file..exe)
        filename = IMAPClient.FILENAME_COLLAPSE_DOTS_PATTERN.sub('.', filename)

        return filename.strip() or "unnamed_attachment"

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
        max_body_size_bytes: int = 1024 * 1024,
    ):
        """
        Initialize ingestion manager

        Args:
            accounts: List of email account configurations
            rate_limit_delay: Delay between operations
            max_attachment_bytes: Maximum attachment bytes retained for analysis
            max_total_attachment_bytes: Maximum total size of all attachments per email
            max_attachment_count: Maximum number of attachments per email
            max_body_size_bytes: Maximum size of email body text/html in bytes
        """
        self.accounts = accounts
        self.rate_limit_delay = rate_limit_delay
        self.max_attachment_bytes = max_attachment_bytes
        self.max_total_attachment_bytes = max_total_attachment_bytes
        self.max_attachment_count = max_attachment_count
        self.max_body_size = max_body_size_bytes
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
            client.max_body_size = self.max_body_size
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

                self.logger.info(f"Fetching from {account.email}/{sanitize_for_logging(folder)}")

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
