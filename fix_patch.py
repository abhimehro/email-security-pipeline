import re

with open("src/modules/email_ingestion.py", "r") as f:
    content = f.read()

# Add missing import
if "from concurrent.futures import ThreadPoolExecutor, as_completed" not in content:
    content = content.replace("from concurrent.futures import ThreadPoolExecutor", "from concurrent.futures import ThreadPoolExecutor, as_completed")

# Now modify _process_account to properly implement fail-fast logic for connections
# and use the initialize_clients logic for client creation (or similar).
old_process = '''    def _process_account(
        self, account: EmailAccountConfig, max_per_folder: int
    ) -> List[EmailData]:
        """
        Fetch and parse all emails for a single account across its configured folders.

        Folders are processed concurrently using a ThreadPoolExecutor. 
        A persistent client from `self.clients` is reused for the first folder,
        while temporary client connections are spun up for additional folders to
        avoid sharing stateful IMAP connections across threads.

        Args:
            account: The email account configuration to process
            max_per_folder: Maximum emails to fetch per folder

        Returns:
            List of EmailData objects collected from all folders of this account

        """
        emails: List[EmailData] = []
        
        # Guard against uninitialized client
        persistent_client = self.clients.get(account.email)
        if persistent_client is None:
            return emails
            
        max_folder_workers = min(3, len(account.folders))
        if max_folder_workers < 1:
            return emails

        def _fetch_from_folder(folder: str, is_first: bool) -> List[EmailData]:
            folder_emails = []
            
            if is_first:
                client = persistent_client
                if not client.ensure_connection():
                    self.logger.error(
                        f"Unable to reconnect to {redact_email(account.email)}; "
                        f"skipping folder {sanitize_for_logging(folder)}"
                    )
                    return folder_emails
                cleanup_required = False
            else:
                # Need fresh client for parallel fetching to avoid IMAP state clashes
                client = IMAPClient(
                    account,
                    self.rate_limit_delay,
                    self.max_attachment_bytes,
                    self.max_total_attachment_bytes,
                    self.max_attachment_count,
                )
                client.max_body_size = self.max_body_size
                if not client.connect():
                    self.logger.error(
                        f"Failed to connect for folder {sanitize_for_logging(folder)} "
                        f"on {redact_email(account.email)}"
                    )
                    return folder_emails
                cleanup_required = True

            try:
                self.logger.info(
                    f"Fetching from {redact_email(account.email)}/"
                    f"{sanitize_for_logging(folder)}"
                )

                raw_emails = client.fetch_unseen_emails(folder, max_per_folder)

                for email_id, raw_email in raw_emails:
                    email_data = client.parse_email(email_id, raw_email, folder)
                    if email_data:
                        folder_emails.append(email_data)
            except Exception as e:
                self.logger.error(
                    f"Error fetching from {sanitize_for_logging(folder)}: {e}"
                )
            finally:
                if cleanup_required:
                    try:
                        client.disconnect()
                    except Exception:
                        pass
                        
            return folder_emails

        with ThreadPoolExecutor(max_workers=max_folder_workers, thread_name_prefix=f"FolderFetch") as executor:
            futures = []
            for i, folder in enumerate(account.folders):
                futures.append(executor.submit(_fetch_from_folder, folder, i == 0))
                
            for future in as_completed(futures):
                emails.extend(future.result())

        return emails'''

new_process = '''    def _create_imap_client(self, account: EmailAccountConfig) -> IMAPClient:
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

    def _process_account(
        self, account: EmailAccountConfig, max_per_folder: int
    ) -> List[EmailData]:
        """
        Fetch and parse all emails for a single account across its configured folders.

        Folders are processed concurrently using a ThreadPoolExecutor. 
        A persistent client from `self.clients` is reused for the first folder,
        while temporary client connections are spun up for additional folders to
        avoid sharing stateful IMAP connections across threads.

        Args:
            account: The email account configuration to process
            max_per_folder: Maximum emails to fetch per folder

        Returns:
            List of EmailData objects collected from all folders of this account

        """
        emails: List[EmailData] = []
        
        # Guard against uninitialized client
        persistent_client = self.clients.get(account.email)
        if persistent_client is None:
            return emails
            
        # Original fail-fast logic: ensure connection on the persistent client first.
        # If the server is unreachable or credentials rotated, fail immediately before
        # spinning up concurrent tasks to avoid hammering the server.
        if account.folders and not persistent_client.ensure_connection():
            self.logger.error(
                f"Unable to reconnect to {redact_email(account.email)}; "
                f"skipping remaining folders"
            )
            return emails
            
        max_folder_workers = min(3, len(account.folders))
        if max_folder_workers < 1:
            return emails

        def _fetch_from_folder(folder: str, is_first: bool) -> List[EmailData]:
            folder_emails = []
            
            if is_first:
                client = persistent_client
                cleanup_required = False
            else:
                # Need fresh client for parallel fetching to avoid IMAP state clashes
                client = self._create_imap_client(account)
                if not client.connect():
                    self.logger.error(
                        f"Failed to connect for folder {sanitize_for_logging(folder)} "
                        f"on {redact_email(account.email)}"
                    )
                    return folder_emails
                cleanup_required = True

            try:
                self.logger.info(
                    f"Fetching from {redact_email(account.email)}/"
                    f"{sanitize_for_logging(folder)}"
                )

                raw_emails = client.fetch_unseen_emails(folder, max_per_folder)

                for email_id, raw_email in raw_emails:
                    email_data = client.parse_email(email_id, raw_email, folder)
                    if email_data:
                        folder_emails.append(email_data)
            except Exception as e:
                self.logger.error(
                    f"Error fetching from {sanitize_for_logging(folder)}: {e}"
                )
            finally:
                if cleanup_required:
                    try:
                        client.disconnect()
                    except Exception:
                        pass
                        
            return folder_emails

        with ThreadPoolExecutor(max_workers=max_folder_workers, thread_name_prefix=f"FolderFetch") as executor:
            futures = []
            for i, folder in enumerate(account.folders):
                futures.append(executor.submit(_fetch_from_folder, folder, i == 0))
                
            for future in as_completed(futures):
                emails.extend(future.result())

        return emails'''

if old_process in content:
    content = content.replace(old_process, new_process)
    with open("src/modules/email_ingestion.py", "w") as f:
        f.write(content)
    print("Fixed _process_account implementation.")
else:
    print("Could not find _process_account to patch.")
