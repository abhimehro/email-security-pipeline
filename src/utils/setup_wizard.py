import getpass
import os
import re
from pathlib import Path

# Check if Colors is available in the expected path, otherwise mock it
try:
    from src.utils.colors import Colors
except ImportError:

    class Colors:
        RESET = ""
        BOLD = ""
        CYAN = ""
        GREEN = ""
        YELLOW = ""
        RED = ""
        GREY = ""

        @classmethod
        def colorize(cls, text, color):
            return text


try:
    from src.modules.imap_connection import IMAPConnection
    from src.utils.config import EmailAccountConfig
    from src.utils.ui import Spinner
except ImportError:
    # If these imports fail, we might be in a constrained environment
    # or running standalone without full context. We can't verify credentials.
    EmailAccountConfig = None
    IMAPConnection = None
    Spinner = None

# Centralized Outlook troubleshooting tip to avoid duplication/drift
OUTLOOK_AUTH_ERROR_TIP = Colors.colorize(
    "Tip: Personal Outlook accounts NO LONGER support App Passwords.", Colors.YELLOW
)


def _is_valid_email(email: str) -> bool:
    """Check if the email format is valid."""
    # Disallow consecutive dots
    if ".." in email:
        return False
    # Simple regex for email validation (supports aliases with +)
    pattern = r"^[\w\.\-\+]+@[\w\.-]+\.\w+$"
    return re.match(pattern, email) is not None


def _styled_input(prompt: str) -> str:
    """Helper to conditionally apply BOLD styling to user input."""
    if Colors.ENABLED:
        prompt += Colors.BOLD

    try:
        val = input(prompt).strip()
    except EOFError:
        print()  # Print newline since input was interrupted
        raise KeyboardInterrupt()
    except KeyboardInterrupt:
        print()  # Print newline since input was interrupted
        raise
    finally:
        if Colors.ENABLED:
            import sys

            sys.stdout.write(Colors.RESET)
            sys.stdout.flush()

    return val


def _test_connection(email: str, app_password: str, provider_choice: str) -> bool:
    """
    Test the connection with provided credentials.
    Returns True if successful, False otherwise.
    """
    if not (EmailAccountConfig and IMAPConnection and Spinner):
        return True  # Cannot verify, assume valid to proceed

    print("\n" + Colors.colorize("Verifying credentials...", Colors.CYAN))

    # Defaults based on provider
    if provider_choice == "1":  # Gmail
        imap_server = "imap.gmail.com"
        imap_port = 993
        provider = "gmail"
        use_ssl = True
    elif provider_choice == "2":  # Proton
        imap_server = "127.0.0.1"
        imap_port = 1143
        provider = "proton"
        use_ssl = True
    elif provider_choice == "3":  # Outlook
        imap_server = "outlook.office365.com"
        imap_port = 993
        provider = "outlook"
        use_ssl = True
    else:
        return True  # Should not happen based on caller

    config = EmailAccountConfig(
        enabled=True,
        email=email,
        imap_server=imap_server,
        imap_port=imap_port,
        app_password=app_password,
        folders=["INBOX"],
        provider=provider,
        use_ssl=use_ssl,
    )

    try:
        success = False
        with Spinner("Connecting to IMAP server...") as spinner:
            # Suppress logging during check to avoid clutter
            import logging

            logging.disable(logging.CRITICAL)
            try:
                conn = IMAPConnection(config)
                success = conn.connect()
                if success:
                    conn.disconnect()
            finally:
                logging.disable(logging.NOTSET)

            if success:
                spinner.success("Connection successful!")
            else:
                spinner.fail("Connection failed.")

        if not success:
            if provider_choice == "3":
                print(OUTLOOK_AUTH_ERROR_TIP)
            return False

        return True

    except Exception as e:
        # We don't have access to the spinner here easily if the exception is outside,
        # but in most cases errors happen inside the context manager. If it happens
        # outside, we just print as before.
        error_msg = str(e).replace(app_password, "***") if app_password else str(e)
        print(
            Colors.colorize(f"✘ Error during connection test: {error_msg}", Colors.RED)
        )
        if provider_choice == "3":
            print(OUTLOOK_AUTH_ERROR_TIP)
        return False


def _select_provider() -> str:
    """Prompt user to select an email provider."""
    print(
        "\n" + Colors.colorize("Step 1 of 2: Choose your email provider", Colors.CYAN)
    )
    print(
        f"  {Colors.colorize('1.', Colors.BOLD)} Gmail {Colors.colorize('(Recommended)', Colors.GREEN)}"
    )
    print(
        f"  {Colors.colorize('2.', Colors.BOLD)} Proton Mail {Colors.colorize('(Requires Bridge)', Colors.GREY)}"
    )
    print(
        f"  {Colors.colorize('3.', Colors.BOLD)} Outlook {Colors.colorize('(Business Only)', Colors.YELLOW)}"
    )
    print(
        f"  {Colors.colorize('4.', Colors.BOLD)} Skip {Colors.colorize('(Manually edit .env)', Colors.GREY)}"
    )

    while True:
        try:
            prompt = (
                "\n"
                + Colors.colorize("? ", Colors.CYAN)
                + Colors.colorize("Select provider ", Colors.BOLD)
                + Colors.colorize("[1-4]", Colors.GREY)
                + Colors.colorize(": ", Colors.BOLD)
            )
            choice = _styled_input(prompt)
            if choice in ("1", "2", "3", "4"):
                return choice
            print(
                Colors.colorize("✘ Invalid choice. ", Colors.RED)
                + Colors.colorize("Please enter 1, 2, 3, or 4.", Colors.YELLOW)
            )
        except EOFError:
            return "4"


def _prompt_for_email(provider_name: str) -> str:
    """Prompt for a valid email address."""
    while True:
        prompt = (
            Colors.colorize("? ", Colors.CYAN)
            + Colors.colorize(f"Enter your {provider_name} email address ", Colors.BOLD)
            + Colors.colorize("*", Colors.RED)
            + Colors.colorize(": ", Colors.BOLD)
        )
        email = _styled_input(prompt)
        if not email:
            print(Colors.colorize("✘ Email is required.", Colors.RED))
            continue

        if _is_valid_email(email):
            return email

        print(
            Colors.colorize("✘ Invalid email format. ", Colors.RED)
            + Colors.colorize(
                "Please enter a valid email address (e.g., user@example.com).",
                Colors.YELLOW,
            )
        )


def _print_provider_help(choice: str) -> None:
    """Print context-specific help for the selected provider."""
    if choice == "1":  # Gmail
        print(
            "\n"
            + Colors.colorize(
                "Note: Use an App Password, not your login password.\nGenerate one at: Google Account -> Security -> 2-Step Verification -> App passwords",
                Colors.GREY,
            )
        )
    elif choice == "2":  # Proton
        print(
            "\n"
            + Colors.colorize(
                "Note: Use the password generated by Proton Mail Bridge.\nFind it in: Proton Mail Bridge app -> Mailbox details",
                Colors.GREY,
            )
        )
    elif choice == "3":  # Outlook
        print(
            "\n"
            + Colors.colorize(
                "Note: Personal Outlook accounts are not supported.\nBusiness accounts may require an App Password if MFA is enabled.",
                Colors.GREY,
            )
        )


def _prompt_for_password(provider_name: str) -> str:
    """Prompt user for an app password, handling visual styling and empty inputs."""
    prompt = (
        Colors.colorize("? ", Colors.CYAN)
        + Colors.colorize(f"Enter your {provider_name} app password ", Colors.BOLD)
        + Colors.colorize("*", Colors.RED)
        + Colors.colorize(": ", Colors.BOLD)
    )

    if Colors.ENABLED:
        prompt += Colors.BOLD

    def _get_input() -> str:
        try:
            return getpass.getpass(prompt).strip()
        except EOFError:
            print()  # Print newline since input was interrupted
            raise KeyboardInterrupt()
        except KeyboardInterrupt:
            print()  # Print newline since input was interrupted
            raise
        finally:
            if Colors.ENABLED:
                import sys

                sys.stdout.write(Colors.RESET)
                sys.stdout.flush()

    app_secret = _get_input()
    while not app_secret:
        print(Colors.colorize("✘ Password is required.", Colors.RED))
        app_secret = _get_input()

    return app_secret


def _get_credentials(choice: str, provider_name: str) -> tuple[str, str]:
    """Prompt user for email and app secret."""
    print(
        "\n"
        + Colors.colorize(
            f"Step 2 of 2: Configure {provider_name} Credentials", Colors.CYAN
        )
    )

    try:
        while True:  # Outer loop for retry mechanism
            email = _prompt_for_email(provider_name)

            _print_provider_help(choice)
            app_secret = _prompt_for_password(provider_name)

            # Test the connection immediately
            if _test_connection(email, app_secret, choice):
                return email, app_secret

            # If connection failed, ask user how to proceed
            print(
                "\n"
                + Colors.colorize(
                    "Connection failed. Would you like to try entering credentials again?",
                    Colors.YELLOW,
                )
            )
            print(
                f"  {Colors.colorize('y:', Colors.BOLD)} Try again {Colors.colorize('(Recommended)', Colors.GREEN)}"
            )
            print(
                f"  {Colors.colorize('n:', Colors.BOLD)} Proceed anyway {Colors.colorize('(Skip verification)', Colors.YELLOW)}"
            )

            prompt = (
                Colors.colorize("? ", Colors.CYAN)
                + Colors.colorize("Retry? ", Colors.BOLD)
                + Colors.colorize("[Y/n]", Colors.GREY)
                + Colors.colorize(" ", Colors.BOLD)
            )
            retry = _styled_input(prompt).lower()
            if retry not in ("", "y", "yes"):
                print(
                    Colors.colorize(
                        "Proceeding with entered credentials (unverified).", Colors.GREY
                    )
                )
                return email, app_secret

            # Loop continues to ask for email/password again
            print("\n" + Colors.colorize("Let's try again...", Colors.CYAN))

    except EOFError:
        return "", ""


def _generate_config_content(
    template_content: str, provider_key: str, email: str, app_secret: str
) -> str:
    """Generate configuration content by replacing template variables."""
    content = template_content

    # Helper to disable other providers
    all_providers = ["GMAIL", "PROTON", "OUTLOOK"]
    for provider in all_providers:
        if provider == provider_key:
            content = re.sub(
                f"{provider}_ENABLED=.*", lambda _: f"{provider}_ENABLED=true", content
            )
        else:
            content = re.sub(
                f"{provider}_ENABLED=.*", lambda _: f"{provider}_ENABLED=false", content
            )

    # Set email for selected provider
    content = re.sub(
        f"{provider_key}_EMAIL=.*", lambda _: f"{provider_key}_EMAIL={email}", content
    )
    # Set app_secret safely
    content = re.sub(
        f"{provider_key}_APP_PASSWORD=.*",
        lambda _: f"{provider_key}_APP_PASSWORD={app_secret}",
        content,
    )

    return content


def _write_config_file(config_file: str, new_content: str) -> bool:
    """Helper to write the configuration to a file securely."""
    if "\0" in config_file:
        print(
            Colors.colorize(
                f"✘ Error: Invalid configuration file path '{config_file}'.", Colors.RED
            )
        )
        return False

    # Restrict writes to files in the current working directory by accepting
    # only a plain filename (no directory components).
    candidate_name = Path(config_file).name
    if (
        not candidate_name
        or candidate_name in (".", "..")
        or candidate_name != config_file
    ):
        print(
            Colors.colorize(
                f"✘ Error: Unsafe configuration file path '{config_file}'. Use a filename only.",
                Colors.RED,
            )
        )
        return False

    config_path = (Path.cwd() / candidate_name).resolve()

    try:
        # Create file with restrictive permissions (600)
        # Using os.open to set mode atomically if possible, or chmod after
        fd = os.open(
            str(config_path),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )

        # os.open mode only applies to new files. If the file exists, we must explicitly set permissions.
        # We prioritize using the file descriptor (fchmod or chmod with FD) to prevent TOCTOU
        # vulnerabilities. Path-based chmod is only used as a final fallback on systems
        # that don't support FD-based permission changes (like some older Windows versions).
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError, NotImplementedError):
            try:
                # Some platforms support os.chmod(fd, mode)
                os.chmod(fd, 0o600)
            except (AttributeError, OSError, NotImplementedError, TypeError):
                # Final fallback to path-based chmod with inode verification.
                try:
                    stat_fd = os.fstat(fd)
                    config_path_str = str(config_path)
                    stat_path = (
                        os.lstat(config_path_str)
                        if hasattr(os, "lstat")
                        else os.stat(config_path_str)
                    )
                    if (
                        stat_fd.st_ino == stat_path.st_ino
                        and stat_fd.st_dev == stat_path.st_dev
                    ):
                        chmod_kwargs = (
                            {"follow_symlinks": False}
                            if os.chmod
                            in getattr(os, "supports_follow_symlinks", set())
                            else {}
                        )
                        os.chmod(config_path_str, 0o600, **chmod_kwargs)
                    else:
                        print(
                            f"\n{Colors.colorize('✘ Error: TOCTOU detected on ', Colors.RED)}"
                            f"{Colors.colorize(str(config_path), Colors.BOLD)}"
                        )
                        import sys

                        sys.exit(1)
                except OSError as exc:
                    print(
                        f"\n{Colors.colorize('✘ Error setting permissions: ' + str(exc), Colors.RED)}"
                    )
                    import sys

                    sys.exit(1)

        with os.fdopen(fd, "w") as f:
            f.write(new_content)

        print(
            "\n"
            + Colors.colorize(
                f"✔ Configuration saved to {str(config_path)}", Colors.GREEN
            )
        )
        return True
    except Exception as e:
        print(Colors.colorize(f"✘ Error writing config: {e}", Colors.RED))
        return False


def run_setup_wizard(
    config_file: str = ".env", template_file: str = ".env.example"
) -> bool:
    """
    Run an interactive setup wizard to configure the application.
    Returns True if setup was successful, False otherwise.
    """

    if not Path(template_file).exists():
        print(
            Colors.colorize(
                f"✘ Error: Template file '{template_file}' not found.", Colors.RED
            )
        )
        return False

    print(
        "\n"
        + Colors.colorize(
            "🧙 Welcome to the Email Security Pipeline Setup Wizard! 🧙", Colors.BOLD
        )
    )
    print(
        Colors.colorize("Let's get your environment configured quickly.", Colors.GREY)
    )
    print(Colors.colorize("(Press Ctrl+C at any time to cancel setup)", Colors.GREY))

    try:
        # 1. Select Provider
        choice = _select_provider()
        if choice == "4":
            return False

        provider_map = {
            "1": ("GMAIL", "Gmail"),
            "2": ("PROTON", "Proton Mail"),
            "3": ("OUTLOOK", "Outlook"),
        }
        selected_key, selected_name = provider_map[choice]

        # 2. Get Credentials
        email, app_secret = _get_credentials(choice, selected_name)
        if not email or not app_secret:
            return False

        # 3. Read Template
        try:
            with open(template_file, "r") as f:
                template_content = f.read()
        except Exception as e:
            print(Colors.colorize(f"✘ Error reading template: {e}", Colors.RED))
            return False

        # 4. Generate Config
        new_content = _generate_config_content(
            template_content, selected_key, email, app_secret
        )

        # 5. Write Config
        if not _write_config_file(config_file, new_content):
            return False

        print("\n" + Colors.colorize("Next Steps:", Colors.BOLD))
        print(
            f"1. Review {Colors.colorize(config_file, Colors.BOLD)} to ensure settings are correct."
        )
        print(
            f"2. Run the pipeline: {Colors.colorize('python src/main.py', Colors.CYAN)}"
        )

        return True

    except KeyboardInterrupt:
        warning = Colors.colorize("⚠", Colors.YELLOW)
        message = Colors.colorize(
            "Setup cancelled by user. No changes were made.", Colors.YELLOW
        )
        print(f"\n\n{warning} {message}")
        return False
