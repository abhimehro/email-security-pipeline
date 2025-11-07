#!/usr/bin/env python3
"""
Email Security Analysis Pipeline
Main orchestrator that coordinates all analysis modules
"""

import sys
import time
import logging
import signal
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.config import Config
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
            self.config.system.rate_limit_delay
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

        # Resolve log level with safe fallback
        level_name = str(self.config.system.log_level).upper()
        level = logging._nameToLevel.get(level_name, logging.INFO)

        logging.basicConfig(
            level=level,
            format=log_format,
            handlers=[
                logging.FileHandler(self.config.system.log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )

        if level_name not in logging._nameToLevel:
            logging.getLogger("EmailSecurityPipeline").warning(
                "Invalid log level '%s'; defaulting to INFO",
                self.config.system.log_level
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
                    time.sleep(self.config.system.check_interval)

            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}", exc_info=True)
                time.sleep(30)  # Wait before retrying

    def _analyze_email(self, email_data):
        """
        Analyze a single email

        Args:
            email_data: EmailData object
        """
        try:
            self.logger.info(f"Analyzing email: {email_data.subject[:50]}...")

            # Layer 1: Spam Analysis
            spam_result = self.spam_analyzer.analyze(email_data)
            self.logger.debug(
                f"Spam analysis: score={spam_result.score:.2f}, "
                f"risk={spam_result.risk_level}"
            )

            # Layer 2: NLP Threat Detection
            nlp_result = self.nlp_analyzer.analyze(email_data)
            self.logger.debug(
                f"NLP analysis: score={nlp_result.threat_score:.2f}, "
                f"risk={nlp_result.risk_level}"
            )

            # Layer 3: Media Authenticity
            media_result = self.media_analyzer.analyze(email_data)
            self.logger.debug(
                f"Media analysis: score={media_result.threat_score:.2f}, "
                f"risk={media_result.risk_level}"
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

            self.logger.info(
                f"Analysis complete: overall_score={threat_report.overall_threat_score:.2f}, "
                f"risk={threat_report.risk_level}"
            )

        except Exception as e:
            self.logger.error(f"Error analyzing email: {e}", exc_info=True)


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    print("\nReceived shutdown signal, stopping gracefully...")
    sys.exit(0)


def main():
    """Main entry point"""
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Print banner
    print("=" * 80)
    print("Email Security Analysis Pipeline")
    print("Multi-layer threat detection for email security")
    print("=" * 80)
    print()

    # Check for config file
    config_file = sys.argv[1] if len(sys.argv) > 1 else ".env"

    if not Path(config_file).exists():
        print(f"Error: Configuration file '{config_file}' not found")
        print("Please create a .env file based on .env.example")
        print("You can run: cp .env.example .env")
        sys.exit(1)

    # Validate that .env is not the example file
    try:
        with open(config_file, 'r') as f:
            content = f.read()
            if 'your-email@gmail.com' in content or 'your-app-password-here' in content:
                print("Warning: .env file appears to contain example values.")
                print("Please update .env with your actual credentials before running.")
                sys.exit(1)
    except Exception as e:
        print(f"Warning: Could not validate .env file: {e}")

    # Create and start pipeline
    pipeline = EmailSecurityPipeline(config_file)
    pipeline.start()


if __name__ == "__main__":
    main()
