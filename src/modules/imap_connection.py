"""
IMAP Connection Module
Handles IMAP connection management, folder operations, and email fetching

PATTERN RECOGNITION: This follows the Adapter pattern - it wraps Python's
imaplib to provide a higher-level, more secure interface for email operations.

SECURITY STORY: IMAP connections are security-critical because:
- Credentials are transmitted (we enforce TLS 1.2+)
- We download potentially malicious data (we enforce size limits)
- Connection errors can leak information (we sanitize error messages)
"""

import imaplib
import logging
import socket
import ssl
import time
from typing import List, Tuple, Optional, Dict, Any
from datetime import datetime

from ..utils.config import EmailAccountConfig
from ..utils.sanitization import sanitize_for_logging, redact_email
from ..utils.security_validators import (
    create_secure_ssl_context,
    calculate_max_email_size
)


logger = logging.getLogger(__name__)


def _apply_ssl_overrides(
    context: ssl.SSLContext,
    verify_ssl: bool,
    log_warning: callable
) -> None:
    """
    Apply SSL verification overrides to an SSL context.

    SECURITY STORY: This centralizes SSL override logic. When verify_ssl is False,
    we disable certificate validation. This should ONLY be used for:
    - Testing environments with self-signed certificates
    - Troubleshooting connection issues

    MAINTENANCE WISDOM: Module-level function lets both IMAPConnection and
    IMAPDiagnostics share the same SSL override behaviour without inheritance.
    Future security controls (certificate pinning, TLS version enforcement, etc.)
    only need to be added here.

    Args:
        context: SSL context to configure
        verify_ssl: When False, hostname checking and cert validation are disabled
        log_warning: Callable used to emit a warning when verification is disabled
    """
    if not verify_ssl:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        log_warning("SSL verification disabled - use only for testing!")


class IMAPConnection:
    """
    Manages IMAP connection and folder operations

    MAINTENANCE WISDOM: Keep connection management separate from parsing.
    This makes it easier to test connection logic without parsing emails,
    and parsing logic without needing an IMAP server.
    """

    def __init__(
        self,
        config: EmailAccountConfig,
        rate_limit_delay: int = 1,
        max_total_attachment_bytes: int = 100 * 1024 * 1024
    ):
        """
        Initialize IMAP connection manager

        Args:
            config: Email account configuration
            rate_limit_delay: Delay between batch operations (seconds)
            max_total_attachment_bytes: Max total attachment size (for email size calculation)
        """
        self.config = config
        self.rate_limit_delay = rate_limit_delay
        self.max_email_size = calculate_max_email_size(max_total_attachment_bytes)
        self.connection: Optional[imaplib.IMAP4_SSL] = None
        self.logger = logging.getLogger(f"IMAPConnection.{config.provider}")

    def connect(self) -> bool:
        """
        Establish connection to IMAP server with secure TLS

        SECURITY STORY: We enforce TLS 1.2+ to protect against protocol-level
        attacks (SSLv3 POODLE, TLS 1.0 BEAST, etc.). We also set a 30-second
        timeout to prevent indefinite hangs (DoS protection).

        Returns:
            True if connection successful, False otherwise
        """
        try:
            self.logger.info(
                f"Connecting to {self.config.imap_server}:{self.config.imap_port} "
                f"(SSL={self.config.use_ssl})"
            )

            # Create secure SSL context (TLS 1.2+ enforced)
            context = create_secure_ssl_context()
            _apply_ssl_overrides(context, self.config.verify_ssl, self.logger.warning)

            if self.config.use_ssl:
                self.connection = imaplib.IMAP4_SSL(
                    self.config.imap_server,
                    self.config.imap_port,
                    ssl_context=context,
                    timeout=30  # SECURITY: Prevent indefinite hangs
                )
            else:
                self.connection = imaplib.IMAP4(
                    self.config.imap_server,
                    self.config.imap_port,
                    timeout=30  # SECURITY: Prevent indefinite hangs
                )
                self.connection.starttls(ssl_context=context)

            # Authenticate
            self.connection.login(self.config.email, self.config.app_password)
            self.logger.info(f"Successfully connected to {redact_email(self.config.email)}")
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
        """
        Ensure the IMAP connection is alive, reconnecting if necessary

        INDUSTRY CONTEXT: IMAP connections can timeout or drop. Professional
        email clients always check connection health before operations.

        Returns:
            True if connection is ready, False if reconnection failed
        """
        if not self.connection:
            return self.connect()

        try:
            # NOOP command checks if connection is alive
            self.connection.noop()
            return True
        except Exception as exc:
            self.logger.warning(
                f"IMAP connection lost ({exc}), attempting reconnect"
            )
            self.disconnect()
            return self.connect()

    def disconnect(self):
        """
        Close IMAP connection gracefully
        """
        if not self.connection:
            return

        try:
            self.connection.logout()
            self.logger.info("Disconnected from IMAP server")
        except Exception:
            # Connection may already be closed
            self.logger.debug("Connection was already closed or logout failed")
        finally:
            self.connection = None

    def list_folders(self) -> List[str]:
        """
        List available mailbox folders

        Returns:
            List of folder names (e.g., ['INBOX', 'Sent', 'Spam'])
        """
        if not self.connection:
            return []

        try:
            status, folders = self.connection.list()
            if status == "OK":
                folder_names = []
                for folder in folders:
                    # Parse folder names from IMAP response
                    # Format: b'(\\HasNoChildren) "/" "INBOX"'
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
            folder: Folder name (e.g., 'INBOX')

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
                self.logger.warning(
                    f"Could not select folder {safe_folder}: {status}"
                )
                return False
        except Exception as e:
            safe_folder = sanitize_for_logging(folder)
            self.logger.error(f"Error selecting folder {safe_folder}: {e}")
            return False

    def fetch_unseen_emails(
        self,
        folder: str,
        limit: int = 50
    ) -> List[Tuple[str, bytes]]:
        """
        Fetch unseen emails from folder with size validation

        SECURITY STORY: We check email sizes BEFORE downloading them to
        prevent DoS attacks from extremely large emails. We also process
        in batches with rate limiting to avoid overwhelming the server.

        Args:
            folder: Folder name
            limit: Maximum number of emails to fetch

        Returns:
            List of (email_id, raw_email_bytes) tuples
        """
        if not self.select_folder(folder):
            return []

        return self._fetch_emails_internal(folder, limit)

    def _fetch_emails_internal(
        self,
        folder: str,
        limit: int = 50
    ) -> List[Tuple[str, bytes]]:
        """
        Internal fetch logic without folder selection
        (for backward compatibility with tests that mock select_folder)
        """
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

            self.logger.info(
                f"Found {len(email_ids)} unseen emails in {safe_folder}"
            )

            # Process in batches for rate limiting
            emails = []
            batch_size = 10

            for i in range(0, len(email_ids), batch_size):
                if i > 0:
                    time.sleep(self.rate_limit_delay)

                batch_ids = email_ids[i : i + batch_size]
                batch_emails = self._fetch_batch(batch_ids)
                emails.extend(batch_emails)

            return emails

        except Exception as e:
            self.logger.error(f"Error in fetch_unseen_emails: {e}")
            return []

    def _parse_email_payload(self, item: Any) -> Optional[Tuple[str, bytes]]:
        """
        Parse a single email payload from the IMAP fetch response.

        Args:
            item: An item from the IMAP fetch response data list.

        Returns:
            A tuple of (email_id, raw_bytes) if successful, None otherwise.

        Notes:
            The returned email_id is the IMAP message sequence number extracted
            from the FETCH response header (e.g., from b'123 (RFC822 {456}').
        """
        if not isinstance(item, tuple):
            return None

        # item is (header, body)
        # header: b'123 (RFC822 {456}'
        # body: raw email bytes
        try:
            header = item[0]
            raw_bytes = item[1]

            # Extract sequence number from header
            msg_seq = header.split()[0]
            if isinstance(raw_bytes, bytes):
                return (msg_seq.decode(), raw_bytes)
            else:
                self.logger.warning(
                    f"Unexpected payload type for email {msg_seq}: "
                    f"{type(raw_bytes)}"
                )
        except Exception as parse_err:
            self.logger.error(
                f"Error parsing email payload {item}: {parse_err}"
            )

        return None

    def _fetch_batch(self, email_ids: List[bytes]) -> List[Tuple[str, bytes]]:
        """
        Fetch a batch of emails with size pre-checking

        SECURITY STORY: Two-step process prevents DoS:
        1. First, check sizes (RFC822.SIZE) - lightweight operation
        2. Then, fetch only emails within size limit

        Args:
            email_ids: List of email IDs (as bytes)

        Returns:
            List of (email_id, raw_bytes) tuples
        """
        ids_str = b",".join(email_ids)
        emails = []

        try:
            # Step 1: Check sizes first (DoS prevention)
            safe_ids = self._check_email_sizes(email_ids)

            if not safe_ids:
                return []

            # Step 2: Fetch only safe-sized emails
            safe_ids_str = b",".join(safe_ids)
            status, data = self.connection.fetch(safe_ids_str, "(RFC822)")

            if status == "OK" and isinstance(data, list):
                for item in data:
                    parsed_email = self._parse_email_payload(item)
                    if parsed_email:
                        emails.append(parsed_email)
            else:
                self.logger.warning(
                    f"Failed to fetch batch {safe_ids_str}: {status}"
                )

        except Exception as e:
            self.logger.error(f"Error fetching email batch {ids_str}: {e}")

        return emails

    def _check_email_sizes(self, email_ids: List[bytes]) -> List[bytes]:
        """
        Check email sizes and filter out oversized ones

        Args:
            email_ids: List of email IDs to check

        Returns:
            List of email IDs that are within size limits
        """
        ids_str = b",".join(email_ids)
        safe_ids = []

        try:
            status, size_data = self.connection.fetch(ids_str, "(RFC822.SIZE)")

            if status == "OK" and isinstance(size_data, list):
                for item in size_data:
                    # Handle different imaplib response formats
                    info = item
                    if isinstance(item, tuple):
                        info = item[0]

                    if isinstance(info, bytes):
                        try:
                            # Parse: b'1 (RFC822.SIZE 1024)'
                            # SECURITY: Use 'replace' to maintain visibility of encoding issues
                            content = info.decode('ascii', errors='replace')

                            if 'RFC822.SIZE' in content:
                                # Extract sequence number
                                parts = info.split()
                                seq = parts[0]

                                # Extract size
                                size_idx = content.find('RFC822.SIZE') + 11
                                remaining = content[size_idx:].strip()
                                size_str = remaining.split(')')[0].strip()
                                size = int(size_str)

                                # Check against limit
                                if size > self.max_email_size:
                                    self.logger.warning(
                                        f"Skipping oversized email {seq.decode()} "
                                        f"({size} bytes > {self.max_email_size})"
                                    )
                                    continue

                                safe_ids.append(seq)
                        except Exception as parse_err:
                            self.logger.warning(
                                f"Error parsing size for {info}: {parse_err}"
                            )
                            continue

        except Exception as e:
            self.logger.error(f"Error checking email sizes: {e}")

        return safe_ids

    def _get_auth_tip(self, error_msg: str) -> Optional[str]:
        """
        Get actionable tip based on error and provider

        INDUSTRY CONTEXT: Major email providers now require app-specific
        passwords for IMAP access. This helps users troubleshoot authentication.

        Args:
            error_msg: Error message from IMAP server

        Returns:
            User-friendly tip or None
        """
        msg_lower = error_msg.lower()
        server_lower = self.config.imap_server.lower()

        # Check for authentication failures
        auth_keywords = [
            "authentication failed", "login failed", "invalid credentials",
            "logon failure", "authenticate"
        ]
        if not any(k in msg_lower for k in auth_keywords):
            return None

        if "outlook" in server_lower or "office365" in server_lower:
            return (
                "Personal Outlook/Hotmail accounts NO LONGER support passwords. "
                "You must use an App Password or OAuth (Enterprise)."
            )

        if "gmail" in server_lower:
            return (
                "Gmail requires 2-Step Verification enabled and an App Password "
                "to use IMAP."
            )

        if "yahoo" in server_lower:
            return (
                "Yahoo Mail requires an App Password generated from account "
                "security settings."
            )

        return (
            "Check your email and password. If using 2FA, you likely need "
            "an App Password."
        )


class IMAPDiagnostics:
    """
    Diagnostic utilities for troubleshooting IMAP connections

    MAINTENANCE WISDOM: Keep diagnostics separate from connection logic
    to avoid cluttering the main class. Users only need diagnostics when
    something goes wrong.
    """

    def __init__(self, config: EmailAccountConfig):
        """
        Initialize diagnostics

        Args:
            config: Email account configuration to diagnose
        """
        self.config = config
        self.logger = logging.getLogger(f"IMAPDiagnostics.{config.provider}")

    def diagnose_connection_issues(self) -> Dict[str, Any]:
        """
        Run comprehensive connection diagnostics

        Returns:
            Dictionary with diagnostic results for each check
        """
        self.logger.info(f"Running diagnostics for {redact_email(self.config.email)}...")

        return {
            "server_reachable": self._check_server_reachability(),
            "port_open": self._check_port_open(),
            "ssl_valid": self._check_ssl_certificate(),
            "credentials_valid": self._check_credentials(),
        }

    def _check_server_reachability(self) -> Dict[str, Any]:
        """
        Check if the IMAP server is reachable via DNS
        """
        result = {"host_resolved": None, "resolves_to": None, "error": None}
        try:
            ip_address = socket.gethostbyname(self.config.imap_server)
            result["host_resolved"] = True
            result["resolves_to"] = ip_address
        except socket.gaierror as e:
            result["host_resolved"] = False
            result["error"] = f"DNS lookup failed: {e}"
        return result

    def _check_port_open(self) -> Dict[str, Any]:
        """
        Check if the IMAP port is open and accepting connections
        """
        result = {"open": False, "error": None}
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            try:
                if sock.connect_ex((self.config.imap_server, self.config.imap_port)) == 0:
                    result["open"] = True
            except Exception as e:
                result["error"] = f"Port check failed: {e}"
        return result

    def _check_ssl_certificate(self) -> Dict[str, Any]:
        """
        Validate the SSL certificate of the IMAP server
        """
        result = {"valid": False, "expires_in_days": None, "error": None}
        try:
            context = create_secure_ssl_context()
            _apply_ssl_overrides(context, self.config.verify_ssl, self.logger.warning)

            with socket.create_connection(
                (self.config.imap_server, self.config.imap_port),
                timeout=5
            ) as sock:
                with context.wrap_socket(
                    sock,
                    server_hostname=self.config.imap_server
                ) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        result["valid"] = True
                        expiry_date = datetime.strptime(
                            cert["notAfter"],
                            "%b %d %H:%M:%S %Y %Z"
                        )
                        delta = expiry_date - datetime.now()
                        result["expires_in_days"] = delta.days
        except ssl.SSLCertVerificationError as e:
            result["error"] = f"SSL certificate verification failed: {e}"
        except Exception as e:
            result["error"] = f"SSL check failed: {e}"
        return result

    def _check_credentials(self) -> Dict[str, Any]:
        """
        Attempt a login to verify credentials
        """
        result = {"valid": False, "error": None}
        try:
            context = create_secure_ssl_context()
            _apply_ssl_overrides(context, self.config.verify_ssl, self.logger.warning)

            if self.config.use_ssl:
                conn = imaplib.IMAP4_SSL(
                    self.config.imap_server,
                    self.config.imap_port,
                    ssl_context=context
                )
            else:
                conn = imaplib.IMAP4(
                    self.config.imap_server,
                    self.config.imap_port
                )
                conn.starttls(ssl_context=context)

            conn.login(self.config.email, self.config.app_password)
            result["valid"] = True
            conn.logout()
        except imaplib.IMAP4.error as e:
            result["error"] = f"IMAP login failed: {e}"
        except Exception as e:
            result["error"] = f"Credential check failed with unexpected error: {e}"
        return result
