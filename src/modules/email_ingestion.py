"""
Email Ingestion Module
Main orchestrator for email retrieval from multiple providers.

This module has been refactored into smaller focused modules:
- email_data.py: EmailData dataclass
- email_parser.py: Email parsing logic
- imap_connection.py: IMAP connection management
- security_validators.py (utils): Security validation utilities

This file serves as the main entry point and maintains backward compatibility
by re-exporting all public APIs.

PATTERN RECOGNITION: This follows the Facade pattern - it provides a simple
interface to a complex subsystem (IMAP + parsing + security).
"""
from dataclasses import dataclass

import imaplib
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from ..utils.config import EmailAccountConfig
from ..utils.sanitization import redact_email, sanitize_for_logging
from ..utils.security_validators import (
    calculate_max_email_size,
    create_secure_ssl_context,
)

# Import from refactored modules
from .email_data import EmailData
from .email_parser import EmailParser
from .imap_connection import IMAPConnection, IMAPDiagnostics

# Re-export public API for backward compatibility
# MAINTENANCE WISDOM: This ensures all existing imports continue to work.
# Future you will thank present you for maintaining backward compatibility!
__all__ = [
    # Main classes
    "IMAPClient",
    "EmailIngestionManager",
    "EmailData",
]


class IMAPClient:
    """
    IMAP client for connecting to email servers.

    MAINTENANCE WISDOM: This is a compatibility wrapper that combines
    IMAPConnection and EmailParser to maintain the original API.

    New code should import IMAPConnection and EmailParser directly for
    better separation of concerns.
    """

    def __init__(
        self,
        config: EmailAccountConfig,
        rate_limit_delay: int = 1,
        max_attachment_bytes: int = 25 * 1024 * 1024,
        max_total_attachment_bytes: int = 100 * 1024 * 1024,
        max_attachment_count: int = 10,
    ):
        """
        Initialize IMAP client.

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

        # Calculate max email size based on attachment limits
        self.max_email_size = calculate_max_email_size(max_total_attachment_bytes)
        self.max_body_size = 1024 * 1024  # Default 1MB, overridden by manager

        # Create connection and parser components
        self.connection_manager = IMAPConnection(
            config=config,
            rate_limit_delay=rate_limit_delay,
            max_total_attachment_bytes=max_total_attachment_bytes,
        )

        self.parser = EmailParser(
            config=config,
            max_body_size=self.max_body_size,
            max_attachment_bytes=max_attachment_bytes,
            max_total_attachment_bytes=max_total_attachment_bytes,
            max_attachment_count=max_attachment_count,
        )

        # Create shared logger for backward compatibility
        # Use a private variable and property to sync with subcomponents
        self._logger = logging.getLogger(f"IMAPClient.{config.provider}")
        self.connection_manager.logger = self._logger
        self.parser.logger = self._logger

        # Expose connection for backward compatibility
        self.connection = None

    @property
    def logger(self):
        """Get logger (property for backward compatibility with tests)."""
        return self._logger

    @logger.setter
    def logger(self, value):
        """Set logger and propagate to subcomponents."""
        self._logger = value
        self.connection_manager.logger = value
        self.parser.logger = value

    def connect(self) -> bool:
        """
        Establish connection to IMAP server.

        Returns:
            True if connection successful

        """
        try:
            self.logger.info(
                f"Connecting to {self.config.imap_server}:{self.config.imap_port} "
                f"(SSL={self.config.use_ssl})"
            )

            # Create secure SSL context using our method (for backward compat with tests)
            context = self._create_secure_ssl_context()

            if self.config.use_ssl:
                self.connection = imaplib.IMAP4_SSL(
                    self.config.imap_server,
                    self.config.imap_port,
                    ssl_context=context,
                    timeout=30,  # SECURITY: Prevent indefinite hangs
                )
            else:
                self.connection = imaplib.IMAP4(
                    self.config.imap_server,
                    self.config.imap_port,
                    timeout=30,  # SECURITY: Prevent indefinite hangs
                )
                self.connection.starttls(ssl_context=context)

            # Authenticate
            self.connection.login(self.config.email, self.config.app_password)

            # Sync with connection_manager for other methods
            self.connection_manager.connection = self.connection

            self.logger.info(
                f"Successfully connected to {redact_email(self.config.email)}"
            )
            return True

        except imaplib.IMAP4.error as e:
            self.logger.error(f"IMAP connection error: {e}")
            tip = self.connection_manager._get_auth_tip(str(e))
            if tip:
                self.logger.warning(f"💡 {tip}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected connection error: {e}")
            return False

    def ensure_connection(self) -> bool:
        """
        Ensure the IMAP connection is alive, reconnecting if necessary.
        """
        success = self.connection_manager.ensure_connection()
        self.connection = self.connection_manager.connection
        return success

    def disconnect(self):
        """Close IMAP connection."""
        self.connection_manager.disconnect()
        self.connection = None

    def list_folders(self) -> List[str]:
        """
        List available folders.

        Returns:
            List of folder names

        """
        return self.connection_manager.list_folders()

    def select_folder(self, folder: str) -> bool:
        """
        Select a folder for operations.

        Args:
            folder: Folder name

        Returns:
            True if folder selected successfully

        """
        # Sync connection for backward compatibility with tests
        self.connection_manager.connection = self.connection
        return self.connection_manager.select_folder(folder)

    def fetch_unseen_emails(
        self, folder: str, limit: int = 50
    ) -> List[Tuple[str, bytes]]:
        """
        Fetch unseen emails from folder.

        Args:
            folder: Folder name
            limit: Maximum number of emails to fetch

        Returns:
            List of (email_id, raw_email) tuples

        """
        # Call select_folder first (can be mocked by tests)
        if not self.select_folder(folder):
            return []

        # Sync state for backward compatibility with tests
        self.connection_manager.connection = self.connection
        self.connection_manager.max_email_size = self.max_email_size

        # Delegate to connection_manager's internal fetch logic
        # but skip its select_folder call since we already did it
        return self.connection_manager._fetch_emails_internal(folder, limit)

    def parse_email(
        self, email_id: str, raw_email: bytes, folder: str
    ) -> Optional[EmailData]:
        """
        Parse raw email into EmailData object.

        Args:
            email_id: Email ID
            raw_email: Raw email bytes
            folder: Source folder

        Returns:
            EmailData object or None if parsing fails

        """
        # Sync parser settings for backward compatibility with tests
        self.parser.max_body_size = self.max_body_size
        self.parser.max_attachment_bytes = self.max_attachment_bytes
        self.parser.max_total_attachment_bytes = self.max_total_attachment_bytes
        self.parser.max_attachment_count = self.max_attachment_count
        return self.parser.parse_email(email_id, raw_email, folder)

    def diagnose_connection_issues(self, account: EmailAccountConfig) -> Dict[str, Any]:
        """
        Diagnose IMAP connection issues.

        Args:
            account: Account configuration to diagnose

        Returns:
            Dictionary with diagnostic results

        """
        diagnostics = IMAPDiagnostics(account)
        return diagnostics.diagnose_connection_issues()

    # Static methods for backward compatibility
    @staticmethod
    def _create_secure_ssl_context():
        """
        Create a secure SSL context (backward compatibility wrapper).
        """
        return create_secure_ssl_context()

    @staticmethod
    def _decode_part_payload(part):
        """
        Decode part payload (backward compatibility wrapper).
        """
        return EmailParser._decode_part_payload(part)

    @staticmethod
    def _decode_bytes(data: bytes, charset: Optional[str]) -> str:
        """
        Decode bytes (backward compatibility wrapper).
        """
        return EmailParser._decode_bytes(data, charset)


@dataclass
class EmailIngestionConfig:
    """Configuration for EmailIngestionManager."""

    rate_limit_delay: int = 1
    max_attachment_bytes: int = 25 * 1024 * 1024
    max_total_attachment_bytes: int = 100 * 1024 * 1024
    max_attachment_count: int = 10
    max_body_size_bytes: int = 1024 * 1024
    max_parallel_accounts: int = 3


class EmailIngestionManager:
    """
    Manages email ingestion from multiple accounts.

    PATTERN RECOGNITION: This is a Coordinator - it manages multiple
    IMAPClient instances and orchestrates email fetching across accounts.
    """

    def __init__(
        self,
        accounts: List[EmailAccountConfig],
        *args,
        config: Optional[EmailIngestionConfig] = None,
        **kwargs
    ):
        """
        Initialize ingestion manager.

        Args:
            accounts: List of email account configurations
            config: Configuration object. If individual parameters are passed via kwargs
                    for backward compatibility, they will override the config object.
            **kwargs: Backward compatibility for individual configuration parameters.
        """
        self.accounts = accounts

        # Merge kwargs into a config object for backward compatibility
        if config is None:
            config = EmailIngestionConfig()

        # Map positional arguments if they were passed
        if args:
            attr_names = [
                'rate_limit_delay',
                'max_attachment_bytes',
                'max_total_attachment_bytes',
                'max_attachment_count',
                'max_body_size_bytes',
                'max_parallel_accounts'
            ]
            if len(args) > len(attr_names):
                raise TypeError(f"EmailIngestionManager.__init__() takes from 1 to {len(attr_names)+2} positional arguments but {len(args)+2} were given")
            for attr_name, arg_val in zip(attr_names, args):
                setattr(config, attr_name, arg_val)

        for key, value in kwargs.items():
            if hasattr(config, key):
                setattr(config, key, value)
            else:
                raise TypeError(f"EmailIngestionManager.__init__() got an unexpected keyword argument '{key}'")


        self.rate_limit_delay = config.rate_limit_delay
        self.max_attachment_bytes = config.max_attachment_bytes
        self.max_total_attachment_bytes = config.max_total_attachment_bytes
        self.max_attachment_count = config.max_attachment_count
        self.max_body_size = config.max_body_size_bytes
        self.max_parallel_accounts = max(1, config.max_parallel_accounts)
        self.clients: Dict[str, IMAPClient] = {}
        self.logger = logging.getLogger("EmailIngestionManager")

    def initialize_clients(self) -> bool:
        """
        Initialize IMAP clients for all accounts.

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
                self.max_attachment_count,
            )
            client.max_body_size = self.max_body_size

            if client.connect():
                self.clients[account.email] = client
                success_count += 1
            else:
                self.logger.error(f"Failed to connect to {redact_email(account.email)}")

        if success_count == 0:
            self.logger.error("No email accounts connected successfully")
            return False

        self.logger.info(f"Connected to {success_count}/{len(self.accounts)} accounts")
        return True

    def _create_imap_client(self, account: EmailAccountConfig) -> IMAPClient:
        """Helper to create a fresh IMAP client matching manager settings."""
        client = IMAPClient(
            account,
            self.rate_limit_delay,
            self.max_attachment_bytes,
            self.max_total_attachment_bytes,
            self.max_attachment_count,
        )
        client.max_body_size = self.max_body_size
        return client

    def _parse_emails_parallel(
        self,
        client: IMAPClient,
        raw_emails: List[Tuple[str, bytes]],
        folder: str,
        folder_emails: List[EmailData],
    ) -> None:
        """Helper to parse emails concurrently."""
        with ThreadPoolExecutor(
            max_workers=min(
                32, len(raw_emails) if isinstance(raw_emails, list) else 32
            ),
            thread_name_prefix="EmailParse",
        ) as parse_executor:
            results = parse_executor.map(
                lambda args: client.parse_email(args[0], args[1], folder), raw_emails
            )
            for email_data in results:
                if email_data:
                    folder_emails.append(email_data)

    def _fetch_folder(
        self,
        account: EmailAccountConfig,
        folder: str,
        client,
        is_first: bool,
        max_per_folder: int,
    ) -> list:
        folder_emails = []
        cleanup_required = not is_first
        if not is_first:
            if not client.connect():
                self.logger.error(
                    f"Failed to connect for folder {sanitize_for_logging(folder)} "
                    f"on {redact_email(account.email)}"
                )
                return folder_emails
        try:
            self.logger.info(
                f"Fetching from {redact_email(account.email)}/"
                f"{sanitize_for_logging(folder)}"
            )
            raw_emails = client.fetch_unseen_emails(folder, max_per_folder)
            if raw_emails:
                self._parse_emails_parallel(client, raw_emails, folder, folder_emails)
        except Exception as e:
            self.logger.error(
                f"Error fetching from {sanitize_for_logging(folder)}: {e}"
            )
        finally:
            if cleanup_required:
                try:
                    client.disconnect()
                except Exception:  # nosec B110
                    pass
        return folder_emails

    def _process_account(
        self, account: EmailAccountConfig, max_per_folder: int
    ) -> List[EmailData]:
        emails: List[EmailData] = []
        persistent_client = self.clients.get(account.email)
        if persistent_client is None:
            return emails
        if account.folders and not persistent_client.ensure_connection():
            self.logger.error(
                f"Unable to reconnect to {redact_email(account.email)}; "
                f"skipping remaining folders"
            )
            return emails

        max_folder_workers = min(3, len(account.folders))
        if max_folder_workers < 1:
            return emails

        with ThreadPoolExecutor(
            max_workers=max_folder_workers, thread_name_prefix="FolderFetch"
        ) as folder_executor:
            futures = []
            for i, folder in enumerate(account.folders):
                is_first = i == 0
                client = (
                    persistent_client if is_first else self._create_imap_client(account)
                )
                futures.append(
                    folder_executor.submit(
                        self._fetch_folder,
                        account,
                        folder,
                        client,
                        is_first,
                        max_per_folder,
                    )
                )

            for future in as_completed(futures):
                emails.extend(future.result())

        return emails

    def fetch_all_emails(self, max_per_folder: int = 50) -> List[EmailData]:
        """
        Fetch emails from all configured accounts and folders in parallel.

        Accounts are processed concurrently using a ThreadPoolExecutor with up to
        ``max_parallel_accounts`` worker threads.  Each account runs in its own
        thread with an isolated IMAPClient, so IMAP connections are never shared.
        Per-account errors are caught and logged without blocking other accounts.

        Args:
            max_per_folder: Maximum emails to fetch per folder

        Returns:
            List of EmailData objects aggregated from all accounts

        """
        active_accounts = [
            account
            for account in self.accounts
            if account.enabled and account.email in self.clients
        ]

        if not active_accounts:
            self.logger.info("Fetched 0 emails total")
            return []

        all_emails: List[EmailData] = []

        with ThreadPoolExecutor(
            max_workers=self.max_parallel_accounts,
            thread_name_prefix="EmailIngestion",
        ) as executor:
            future_to_account = {
                executor.submit(self._process_account, account, max_per_folder): account
                for account in active_accounts
            }

            for future in as_completed(future_to_account):
                account = future_to_account[future]
                try:
                    account_emails = future.result()
                    all_emails.extend(account_emails)
                except Exception as exc:
                    # SECURITY: Per-account errors must not block other accounts.
                    # Log and continue so the pipeline keeps monitoring healthy accounts.
                    self.logger.error(
                        f"Error processing account {redact_email(account.email)}: {exc}",
                        exc_info=True,
                    )

        self.logger.info(f"Fetched {len(all_emails)} emails total")
        return all_emails

    def close_all_connections(self):
        """Close all IMAP connections."""
        for client in self.clients.values():
            try:
                client.disconnect()
            except Exception as e:
                # SECURITY: Log and continue so all clients are attempted
                self.logger.warning(f"Error closing connection: {e}")
        self.clients.clear()
        self.logger.info("All connections closed")

    def diagnose_account_connection(
        self, email_address: str
    ) -> Optional[Dict[str, Any]]:
        """
        Diagnose connection issues for a specific email account.

        Args:
            email_address: The email address of the account to diagnose

        Returns:
            A dictionary with diagnostic results, or None if account not found

        """
        account_to_diagnose = None
        for acc in self.accounts:
            if acc.email == email_address:
                account_to_diagnose = acc
                break

        if not account_to_diagnose:
            self.logger.error(
                f"Account '{redact_email(email_address)}' not found in configuration."
            )
            return None

        self.logger.info(f"Running diagnostics for {redact_email(email_address)}...")

        # Create a temporary client for diagnostics
        client = IMAPClient(
            account_to_diagnose, self.rate_limit_delay, self.max_attachment_bytes
        )
        return client.diagnose_connection_issues(account_to_diagnose)
