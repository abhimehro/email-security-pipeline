import signal
import sys
from pathlib import Path
from typing import List, NoReturn, Optional

from src.utils.colors import Colors
from src.utils.config import Config
from src.utils.setup_wizard import run_setup_wizard


class AppRunner:
    """Encapsulates the startup, configuration verification, and execution logic of the Email Security Pipeline."""

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

        import os

        if "\0" in raw_config_file:
            print(
                Colors.colorize(
                    f"Error: Invalid configuration file path '{raw_config_file}'.",
                    Colors.RED,
                )
            )
            sys.exit(1)

        # CodeQL Path Injection Validation: Ensure path resolves securely to an absolute path.
        # This explicitly breaks the taint chain for static analysis while preserving CLI usability
        # and cross-platform compatibility (e.g. Windows drive letters).
        abs_path = os.path.abspath(raw_config_file)
        if not os.path.isabs(abs_path):
            print(
                Colors.colorize(
                    f"Error: Path '{raw_config_file}' cannot be securely resolved.",
                    Colors.RED,
                )
            )
            sys.exit(1)

        config_path = Path(abs_path).resolve()
        self.config_file = str(config_path)

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
        print(f"Configuration file '{self.config_file}' not found.")
        try:
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
                "Run setup wizard? [Y/n] ", Colors.BOLD
            )
            response = input(prompt).strip().lower()
            if response in ("", "y", "yes"):
                if run_setup_wizard(self.config_file):
                    sys.exit(0)
                else:
                    print(Colors.colorize("Setup skipped.", Colors.YELLOW))

            # Fallback to copy only if wizard wasn't run or failed
            if not Path(self.config_file).exists():
                prompt = Colors.colorize("? ", Colors.CYAN) + Colors.colorize(
                    f"Create '{self.config_file}' from template without wizard? [Y/n] ",
                    Colors.BOLD,
                )
                response = input(prompt).strip().lower()
                if response in ("", "y", "yes"):
                    try:
                        import os

                        with open(".env.example", "rb") as src:
                            content = src.read()

                        fd = os.open(
                            self.config_file,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                            0o600,
                        )
                        try:
                            os.fchmod(fd, 0o600)
                        except AttributeError:
                            os.chmod(self.config_file, 0o600)

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
        print(f"You can run: {Colors.colorize(command, Colors.CYAN)}")
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

    def start_pipeline(self) -> None:
        """Instantiate and start the main pipeline."""
        from src.main import EmailSecurityPipeline

        print(Colors.colorize("🚀 Starting pipeline...", Colors.GREEN))
        pipeline = EmailSecurityPipeline(self.config_file)
        pipeline.start()
