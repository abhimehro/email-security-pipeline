import os
import signal
import sys
from pathlib import Path
from typing import List, NoReturn, Optional

from src.utils.colors import Colors
from src.utils.config import Config
from src.utils.setup_wizard import run_setup_wizard


class AppRunner:
    """Encapsulates the startup, configuration verification, and execution logic of the Email Security Pipeline."""

    def _styled_input(self, prompt: str) -> str:
        """Conditionally apply BOLD styling to user input."""
        if Colors.ENABLED:
            prompt += Colors.BOLD

        try:
            val = input(prompt).strip()
        except EOFError:
            print()  # Print newline since input was interrupted
            raise KeyboardInterrupt() from None
        except KeyboardInterrupt:
            print()  # Print newline since input was interrupted
            raise
        finally:
            if Colors.ENABLED:
                import sys
                sys.stdout.write(Colors.RESET)
                sys.stdout.flush()

        return val

    def __init__(self, args: Optional[List[str]] = None) -> None:
        """
        Initialize the runner with CLI arguments.

        Args:
            args: Command line arguments (defaults to sys.argv)

        """
        self.args = args if args is not None else sys.argv

        if len(self.args) > 1 and self.args[1] in ("-h", "--help"):
            self.print_banner()
            self.print_help()
            sys.exit(0)

        raw_config_file = self.args[1] if len(self.args) > 1 else ".env"

        if "\0" in raw_config_file:
            print(
                Colors.colorize(
                    f"Error: Invalid configuration file path '{raw_config_file}'.",
                    Colors.RED,
                )
            )
            sys.exit(1)

        # Restrict config file paths to the current working directory tree.
        base_dir = Path.cwd().resolve()
        candidate = (base_dir / raw_config_file).resolve()

        try:
            candidate.relative_to(base_dir)
        except ValueError:
            print(
                Colors.colorize(
                    f"Error: Configuration file path must stay within '{base_dir}'.",
                    Colors.RED,
                )
            )
            sys.exit(1)

        self.config_file = str(candidate)

    def run(self) -> None:
        """Execute the main application flow."""
        self.setup_signal_handlers()
        self.print_banner()
        self.ensure_config_exists()
        self.validate_config()
        self.start_pipeline()

    def setup_signal_handlers(self) -> None:
        """Register handlers for graceful shutdown."""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    @staticmethod
    def _signal_handler(signum, frame) -> NoReturn:
        """Handle shutdown signals."""
        print(
            "\n"
            + Colors.colorize(
                "⚠ Received shutdown signal, stopping gracefully...", Colors.YELLOW
            )
        )
        raise KeyboardInterrupt

    def _set_secure_permissions(self, fd: int) -> None:
        """
        Set secure permissions (0o600) on a file descriptor.

        Uses fchmod if available (preferred), falls back to chmod with fd,
        then to path-based chmod with TOCTOU detection.
        Exits on security failures.
        """
        SECURE_MODE = 0o600

        # Primary: use fchmod (atomic, no TOCTOU)
        try:
            os.fchmod(fd, SECURE_MODE)
            return
        except AttributeError:
            pass  # fchmod not available on this platform

        # Fallback 1: chmod with file descriptor
        try:
            os.chmod(fd, SECURE_MODE)
            return
        except (AttributeError, TypeError):
            pass  # chmod doesn't support fd on this platform

        # Fallback 2: path-based chmod with TOCTOU detection
        try:
            # Get file stats via fd
            fd_stat = os.fstat(fd)

            # Get file stats via path
            path_stat = os.lstat(self.config_file)

            # TOCTOU detection: verify inode and device match
            if fd_stat.st_ino != path_stat.st_ino or fd_stat.st_dev != path_stat.st_dev:
                print(
                    Colors.colorize(
                        "❌ CRITICAL: TOCTOU detected during permission setting. Aborting.",
                        Colors.RED,
                    )
                )
                sys.exit(1)

            # Use follow_symlinks=False to prevent symlink attacks
            os.chmod(self.config_file, SECURE_MODE, follow_symlinks=False)
            return
        except OSError as e:
            print(
                Colors.colorize(
                    f"❌ CRITICAL: Failed to set secure permissions: {e}",
                    Colors.RED,
                )
            )
            sys.exit(1)

    def print_help(self) -> None:
        """Print usage instructions for the CLI."""
        print(Colors.colorize("Usage:", Colors.BOLD))
        print("  python src/main.py [CONFIG_FILE]\n")
        print(Colors.colorize("Arguments:", Colors.BOLD))
        print(
            "  CONFIG_FILE    Path to the environment configuration file (default: .env)\n"
        )
        print(Colors.colorize("Options:", Colors.BOLD))
        print("  -h, --help     Show this help message and exit\n")

    def print_banner(self) -> None:
        """Print the application startup banner."""
        print(Colors.colorize("=" * 80, Colors.CYAN))
        print(
            Colors.colorize(
                "Email Security Analysis Pipeline", Colors.BOLD + Colors.CYAN
            )
        )
        print(
            Colors.colorize(
                "Multi-layer threat detection for email security", Colors.GREY
            )
        )
        print(Colors.colorize("=" * 80, Colors.CYAN))
        print()

    def ensure_config_exists(self) -> None:
        """Check if the configuration file exists, and offer interactive setup if not."""
        if Path(self.config_file).exists():
            return

        if Path(".env.example").exists() and sys.stdin.isatty():
            self._handle_missing_config_interactive()
        else:
            self._handle_missing_config_non_interactive()

    def _handle_missing_config_interactive(self) -> None:
        """Handle missing configuration interactively (wizard or copy)."""
        print(
            Colors.colorize(
                f"⚠ Configuration file '{self.config_file}' not found.", Colors.YELLOW
            )
        )
        try:
            self._prompt_run_wizard()

            # Fallback to copy only if wizard wasn't run or failed
            if not Path(self.config_file).exists():
                prompt = Colors.colorize("? ", Colors.CYAN) + Colors.colorize(
                    f"Create '{self.config_file}' from template without wizard? {Colors.colorize('[Y/n]', Colors.GREY)} ",
                    Colors.BOLD,
                )
                response = self._styled_input(prompt).lower()
                if response in ("", "y", "yes"):
                    try:
                        with open(".env.example", "rb") as src:
                            content = src.read()
                        old_umask = os.umask(0o077)
                        try:
                            fd = os.open(
                                self.config_file,
                                os.O_WRONLY
                                | os.O_CREAT
                                | os.O_EXCL
                                | getattr(os, "O_NOFOLLOW", 0),
                                0o600,
                            )
                        finally:
                            os.umask(old_umask)

                        with os.fdopen(fd, "wb") as dst:
                            dst.write(content)

                        print(f"Created '{self.config_file}' from '.env.example'.")
                        print(
                            "IMPORTANT: Please edit .env with your actual credentials before proceeding."
                        )
                        sys.exit(0)
                    except Exception as e:
                        print(f"Error creating file: {e}")
                        sys.exit(1)
                else:
                    print("Please create a .env file based on .env.example")
                    sys.exit(1)
        except KeyboardInterrupt:
            warning = Colors.colorize("⚠", Colors.YELLOW)
            message = Colors.colorize(
                "Setup cancelled by user. No changes were made.", Colors.YELLOW
            )
            print(f"\n\n{warning} {message}")
            sys.exit(0)
        except EOFError:
            self._handle_missing_config_non_interactive()

    def _handle_missing_config_non_interactive(self) -> NoReturn:
        """Handle missing configuration when non-interactive or template is missing."""
        # In non-interactive mode (or when the setup wizard can't be used),
        # we cannot proceed without a configuration file. Always exit here
        # to honor the NoReturn type annotation and make the failure mode explicit.
        print(
            Colors.colorize(
                f"✘ Error: Configuration file '{self.config_file}' not found",
                Colors.RED,
            )
        )
        print(
            Colors.colorize(
                "Please create the configuration file based on .env.example",
                Colors.YELLOW,
            )
        )
        command = f'cp .env.example "{self.config_file}"'
        print(Colors.colorize("You can run: ", Colors.YELLOW) + Colors.colorize(command, Colors.CYAN))
        sys.exit(1)

    def validate_config(self) -> None:
        """Validate the configuration to ensure default credentials aren't used."""
        try:
            config_validator = Config(self.config_file)
            from src.utils.validators import check_default_credentials

            errors = check_default_credentials(config_validator)
            if errors:
                print(
                    "\n"
                    + Colors.colorize(
                        "❌ Configuration Error: Default credentials detected",
                        Colors.RED,
                    )
                )
                print(
                    Colors.colorize(
                        "The following issues must be resolved in your .env file before starting:",
                        Colors.GREY,
                    )
                    + "\n"
                )

                for error in errors:
                    print(f"  • {Colors.colorize(error, Colors.YELLOW)}")

                print(
                    f"\nPlease edit {Colors.colorize(self.config_file, Colors.BOLD)} with your actual credentials."
                )
                sys.exit(1)

        except Exception as e:
            print(
                Colors.colorize(
                    f"Warning: Could not validate configuration: {e}", Colors.YELLOW
                )
            )

    def _prompt_run_wizard(self) -> None:
        """Prompt the user to run the setup wizard."""
        print(
            "\n"
            + Colors.colorize(
                "Would you like to run the interactive setup wizard?", Colors.CYAN
            )
        )
        print(
            Colors.colorize(
                "(This will help you configure your email provider)", Colors.GREY
            )
        )

        prompt = Colors.colorize("? ", Colors.CYAN) + Colors.colorize(
            f"Run setup wizard? {Colors.colorize('[Y/n]', Colors.GREY)} ", Colors.BOLD
        )
        response = self._styled_input(prompt).lower()
        if response in ("", "y", "yes"):
            if run_setup_wizard(self.config_file):
                sys.exit(0)
            else:
                print(Colors.colorize("Setup skipped.", Colors.YELLOW))

    def _prompt_create_from_template(self) -> None:
        """Prompt the user to create a configuration file from the template."""
        prompt = Colors.colorize("? ", Colors.CYAN) + Colors.colorize(
            f"Create '{self.config_file}' from template without wizard? {Colors.colorize('[Y/n]', Colors.GREY)} ",
            Colors.BOLD,
        )
        response = self._styled_input(prompt).lower()
        if response in ("", "y", "yes"):
            try:
                self._create_config_from_template()
                sys.exit(0)
            except Exception as e:
                print(f"Error creating file: {e}")
                sys.exit(1)
        else:
            print("Please create a .env file based on .env.example")
            sys.exit(1)

    def _create_config_from_template(self) -> None:
        """Create the configuration file from .env.example with secure permissions."""
        with open(".env.example", "rb") as src:
            content = src.read()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        old_umask = os.umask(0o077)
        try:
            fd = os.open(
                self.config_file,
                flags,
                0o600,
            )
        finally:
            os.umask(old_umask)
        try:
            self._set_secure_permissions(fd)

            with os.fdopen(fd, "wb") as dst:
                dst.write(content)

            print(f"Created '{self.config_file}' from '.env.example'.")
            print(
                "IMPORTANT: Please edit .env with your actual credentials before proceeding."
            )
        except Exception:
            os.close(fd)
            raise

    def start_pipeline(self) -> None:
        """Instantiate and start the main pipeline."""
        from src.main import EmailSecurityPipeline

        print(Colors.colorize("🚀 Starting pipeline...", Colors.GREEN))
        pipeline = EmailSecurityPipeline(self.config_file)
        pipeline.start()
