#!/usr/bin/env python3
"""
Email Security Analysis Pipeline
Main orchestrator that coordinates all analysis modules
"""

import sys
import time
import logging
import signal
import shutil
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.config import Config
from src.utils.colors import Colors
from src.utils.ui import CountdownTimer
from src.utils.logging_utils import ColoredFormatter
from src.utils.sanitization import sanitize_for_logging
from src.modules.email_ingestion import EmailIngestionManager
from src.modules.spam_analyzer import SpamAnalyzer
from src.modules.nlp_analyzer import NLPThreatAnalyzer
from src.modules.media_analyzer import MediaAuthenticityAnalyzer
from src.modules.alert_system import AlertSystem, generate_threat_report


class EmailSecurityPipeline:
    """Main pipeline orchestrator"""

    def __init__(self, config_file: str = ".env"):
        """
        Initialize pipeline

        Args:
            config_file: Path to configuration file
        """
        # Load configuration
        self.config = Config(config_file)

        # Setup logging
        self._setup_logging()

        self.logger = logging.getLogger("EmailSecurityPipeline")
        self.logger.info("Initializing Email Security Pipeline")

        # Initialize modules
        self.ingestion_manager = EmailIngestionManager(
            self.config.email_accounts,
            self.config.system.rate_limit_delay,
            max_attachment_bytes=self.config.system.max_attachment_size_mb * 1024 * 1024,
            max_total_attachment_bytes=self.config.system.max_total_attachment_size_mb * 1024 * 1024,
            max_attachment_count=self.config.system.max_attachment_count,
            max_body_size_bytes=self.config.system.max_body_size_kb * 1024
        )

        self.spam_analyzer = SpamAnalyzer(self.config.analysis)
        self.nlp_analyzer = NLPThreatAnalyzer(self.config.analysis)
        self.media_analyzer = MediaAuthenticityAnalyzer(self.config.analysis)
        self.alert_system = AlertSystem(self.config.alerts)

        self.running = False

    def _setup_logging(self):
        """Setup logging configuration"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

        # Create logs directory if needed
        log_path = Path(self.config.system.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Configure handlers
        file_handler = logging.FileHandler(self.config.system.log_file)
        file_handler.setFormatter(logging.Formatter(log_format))

        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(ColoredFormatter(log_format))

        # Configure logging
        logging.basicConfig(
            level=getattr(logging, self.config.system.log_level.upper()),
            handlers=[file_handler, stream_handler]
        )

    def start(self):
        """Start the pipeline"""
        try:
            # Validate configuration
            self.config.validate()

            self.logger.info("Starting Email Security Pipeline")

            # Initialize email clients
            if not self.ingestion_manager.initialize_clients():
                raise RuntimeError("Failed to initialize email clients")

            self.running = True

            # Main monitoring loop
            self._monitoring_loop()

        except KeyboardInterrupt:
            self.logger.info("Received shutdown signal")
            self.stop()
        except Exception as e:
            self.logger.error(f"Fatal error: {e}", exc_info=True)
            self.stop()
            sys.exit(1)

    def stop(self):
        """Stop the pipeline"""
        self.logger.info("Stopping Email Security Pipeline")
        self.running = False
        self.ingestion_manager.close_all_connections()
        self.logger.info("Pipeline stopped")

    def _monitoring_loop(self):
        """Main monitoring loop"""
        iteration = 0

        while self.running:
            iteration += 1
            self.logger.info(f"=== Monitoring Cycle {iteration} ===")

            try:
                # Fetch emails
                emails = self.ingestion_manager.fetch_all_emails(
                    self.config.system.max_emails_per_batch
                )

                if not emails:
                    self.logger.info("No new emails to analyze")
                else:
                    self.logger.info(f"Analyzing {len(emails)} emails")

                    # Analyze each email
                    for email_data in emails:
                        self._analyze_email(email_data)

                # Wait before next check
                if self.running:
                    self.logger.info(
                        f"Waiting {self.config.system.check_interval} seconds "
                        f"until next check..."
                    )
                    CountdownTimer.wait(
                        self.config.system.check_interval,
                        f"{Colors.GREY}Waiting for next check{Colors.RESET}"
                    )

            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}", exc_info=True)
                CountdownTimer.wait(30, f"{Colors.RED}Retrying in{Colors.RESET}")

    def _analyze_email(self, email_data):
        """
        Analyze a single email

        Args:
            email_data: EmailData object
        """
        try:
            safe_subject = sanitize_for_logging(email_data.subject, max_length=50)
            self.logger.info(f"Analyzing email: {safe_subject}...")

            # Layer 1: Spam Analysis
            spam_result = self.spam_analyzer.analyze(email_data)
            symbol = Colors.get_risk_symbol(spam_result.risk_level)
            self.logger.debug(
                f"Spam analysis: score={spam_result.score:.2f}, "
                f"risk={spam_result.risk_level} {symbol}"
            )

            # Layer 2: NLP Threat Detection
            nlp_result = self.nlp_analyzer.analyze(email_data)
            symbol = Colors.get_risk_symbol(nlp_result.risk_level)
            self.logger.debug(
                f"NLP analysis: score={nlp_result.threat_score:.2f}, "
                f"risk={nlp_result.risk_level} {symbol}"
            )

            # Layer 3: Media Authenticity
            media_result = self.media_analyzer.analyze(email_data)
            symbol = Colors.get_risk_symbol(media_result.risk_level)
            self.logger.debug(
                f"Media analysis: score={media_result.threat_score:.2f}, "
                f"risk={media_result.risk_level} {symbol}"
            )

            # Generate threat report
            threat_report = generate_threat_report(
                email_data,
                spam_result,
                nlp_result,
                media_result
            )

            # Send alerts
            self.alert_system.send_alert(threat_report)

            symbol = Colors.get_risk_symbol(threat_report.risk_level)
            self.logger.info(
                f"Analysis complete: overall_score={threat_report.overall_threat_score:.2f}, "
                f"risk={threat_report.risk_level} {symbol}"
            )

        except Exception as e:
            self.logger.error(f"Error analyzing email: {e}", exc_info=True)


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print("\nReceived shutdown signal, stopping gracefully...")
    raise KeyboardInterrupt


def main():
    """Main entry point"""
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Print banner
    print(Colors.colorize("=" * 80, Colors.CYAN))
    print(Colors.colorize("Email Security Analysis Pipeline", Colors.BOLD + Colors.CYAN))
    print(Colors.colorize("Multi-layer threat detection for email security", Colors.GREY))
    print(Colors.colorize("=" * 80, Colors.CYAN))
    print()

    # Check for config file
    config_file = sys.argv[1] if len(sys.argv) > 1 else ".env"

    if not Path(config_file).exists():
        if Path(".env.example").exists() and sys.stdin.isatty():
            print(f"Configuration file '{config_file}' not found.")
            try:
                response = input(f"Would you like to create it from '.env.example'? [Y/n] ").strip().lower()
                if response in ('', 'y', 'yes'):
                    try:
                        shutil.copy(".env.example", config_file)
                        print(f"Created '{config_file}' from '.env.example'.")
                        print("IMPORTANT: Please edit .env with your actual credentials before proceeding.")
                        sys.exit(0)
                    except Exception as e:
                        print(f"Error creating file: {e}")
                        sys.exit(1)
                else:
                    print("Please create a .env file based on .env.example")
                    sys.exit(1)
            except EOFError:
                # Handle case where input stream is closed
                pass

        # Fallback for non-interactive mode or missing template
        if not Path(config_file).exists():
            print(f"Error: Configuration file '{config_file}' not found")
            print("Please create a .env file based on .env.example")
            print("You can run: cp .env.example .env")
            sys.exit(1)

    # Validate that configuration does not use default values
    try:
        # Load config temporarily for validation
        config_validator = Config(config_file)
        from src.utils.validators import check_default_credentials

        errors = check_default_credentials(config_validator)
        if errors:
            print(f"\n{Colors.RED}❌ Configuration Error: Default credentials detected{Colors.RESET}")
            print(f"{Colors.GREY}The following issues must be resolved in your .env file before starting:{Colors.RESET}\n")

            for error in errors:
                print(f"  • {Colors.YELLOW}{error}{Colors.RESET}")

            print(f"\nPlease edit {Colors.BOLD}{config_file}{Colors.RESET} with your actual credentials.")
            sys.exit(1)

    except Exception as e:
        print(f"{Colors.YELLOW}Warning: Could not validate configuration: {e}{Colors.RESET}")

    # Create and start pipeline
    print(f"{Colors.GREEN}🚀 Starting pipeline...{Colors.RESET}")
    pipeline = EmailSecurityPipeline(config_file)
    pipeline.start()


if __name__ == "__main__":
    main()
