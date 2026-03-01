import sys
import signal
import shutil
from pathlib import Path
from typing import Optional, List, NoReturn

from src.utils.config import Config
from src.utils.colors import Colors
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
        self.config_file = self.args[1] if len(self.args) > 1 else ".env"

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
        print("\nReceived shutdown signal, stopping gracefully...")
        raise KeyboardInterrupt

    def print_banner(self) -> None:
        """Print the application startup banner."""
        print(Colors.colorize("=" * 80, Colors.CYAN))
        print(Colors.colorize("Email Security Analysis Pipeline", Colors.BOLD + Colors.CYAN))
        print(Colors.colorize("Multi-layer threat detection for email security", Colors.GREY))
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
            print(f"\n{Colors.CYAN}Would you like to run the interactive setup wizard?{Colors.RESET}")
            print(f"{Colors.GREY}(This will help you configure your email provider){Colors.RESET}")

            response = input("Run setup wizard? [Y/n] ").strip().lower()
            if response in ('', 'y', 'yes'):
                if run_setup_wizard(self.config_file):
                    sys.exit(0)
                else:
                    print(f"{Colors.YELLOW}Setup skipped.{Colors.RESET}")

            # Fallback to copy only if wizard wasn't run or failed
            if not Path(self.config_file).exists():
                response = input(f"Create '{self.config_file}' from template without wizard? [Y/n] ").strip().lower()
                if response in ('', 'y', 'yes'):
                    try:
                    try:
                        shutil.copy(".env.example", self.config_file)
                        import os
                        os.chmod(self.config_file, 0o600)
                        print(f"Created '{self.config_file}' from '.env.example'.")
                        print(f"Created '{self.config_file}' from '.env.example'.")
                        print("IMPORTANT: Please edit .env with your actual credentials before proceeding.")
                        sys.exit(0)
                    except Exception as e:
                        print(f"Error creating file: {e}")
                        sys.exit(1)
                else:
                    print("Please create a .env file based on .env.example")
                    sys.exit(1)
        except EOFError:
            self._handle_missing_config_non_interactive()

    def _handle_missing_config_non_interactive(self) -> NoReturn:
        """Handle missing configuration when non-interactive or template is missing."""
        if not Path(self.config_file).exists():
            print(f"Error: Configuration file '{self.config_file}' not found")
            print("Please create a .env file based on .env.example")
            print("You can run: cp .env.example .env")
            sys.exit(1)

    def validate_config(self) -> None:
        """Validate the configuration to ensure default credentials aren't used."""
        try:
            config_validator = Config(self.config_file)
            from src.utils.validators import check_default_credentials

            errors = check_default_credentials(config_validator)
            if errors:
                print(f"\n{Colors.RED}❌ Configuration Error: Default credentials detected{Colors.RESET}")
                print(f"{Colors.GREY}The following issues must be resolved in your .env file before starting:{Colors.RESET}\n")

                for error in errors:
                    print(f"  • {Colors.YELLOW}{error}{Colors.RESET}")

                print(f"\nPlease edit {Colors.BOLD}{self.config_file}{Colors.RESET} with your actual credentials.")
                sys.exit(1)

        except Exception as e:
            print(f"{Colors.YELLOW}Warning: Could not validate configuration: {e}{Colors.RESET}")

    def start_pipeline(self) -> None:
        """Instantiate and start the main pipeline."""
        from src.main import EmailSecurityPipeline
        print(f"{Colors.GREEN}🚀 Starting pipeline...{Colors.RESET}")
        pipeline = EmailSecurityPipeline(self.config_file)
        pipeline.start()
