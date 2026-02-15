#!/usr/bin/env python3
"""
Email Security Analysis Pipeline
Main orchestrator that coordinates all analysis modules
"""

import sys
import time
import logging
from logging.handlers import RotatingFileHandler
import signal
import shutil
import concurrent.futures
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.config import Config, ConfigurationError
from src.utils.colors import Colors
from src.utils.ui import CountdownTimer, Spinner
from src.utils.setup_wizard import run_setup_wizard
from src.utils.logging_utils import ColoredFormatter
from src.utils.structured_logging import JSONFormatter
from src.utils.metrics import Metrics
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

        # Initialize metrics collection if enabled
        self.metrics = Metrics() if self.config.system.enable_metrics else None
        if self.metrics:
            self.logger.info("Metrics collection enabled")

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

        # Optimization: ThreadPool for parallel analysis
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=3)

        self.running = False

    def _setup_logging(self):
        """
        Setup logging configuration.
        
        Supports both text (colored, human-readable) and JSON (structured, machine-parseable) formats.
        
        TEACHING MOMENT: We use different formatters for file vs console because:
        - File logs should be machine-parseable (JSON) when LOG_FORMAT=json
        - Console logs should be human-readable with colors for local development
        
        This is similar to how nginx can log JSON to files but show colored output to stdout.
        """
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

        # Create logs directory if needed
        log_path = Path(self.config.system.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Configure file handler with rotation
        # Security: Use RotatingFileHandler to prevent disk space DoS (CWE-400)
        # MAINTENANCE WISDOM: Using configurable size limits means you can tune this
        # based on your disk space without changing code
        file_handler = RotatingFileHandler(
            self.config.system.log_file,
            maxBytes=self.config.system.log_rotation_size_mb * 1024 * 1024,
            backupCount=self.config.system.log_rotation_keep_files
        )
        
        # Choose formatter based on LOG_FORMAT configuration
        if self.config.system.log_format == "json":
            # JSON format: structured logs for log aggregation tools
            file_handler.setFormatter(JSONFormatter())
        else:
            # Text format: traditional format without colors for files
            file_handler.setFormatter(logging.Formatter(log_format))

        # Console handler always uses colored text for better UX
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

            # Print configuration summary
            self._print_configuration_summary()

            self.logger.info("Starting Email Security Pipeline")

            # Initialize email clients
            with Spinner("Initializing email clients..."):
                if not self.ingestion_manager.initialize_clients():
                    raise RuntimeError("Failed to initialize email clients")

            self.running = True

            # Main monitoring loop
            self._monitoring_loop()

        except KeyboardInterrupt:
            self.logger.info("Received shutdown signal")
            self.stop()
        except ConfigurationError as e:
            print(f"\n{Colors.RED}❌ Configuration Error:{Colors.RESET}")
            for error in e.args[0]:
                print(f"  • {Colors.YELLOW}{error}{Colors.RESET}")
            print(f"\nPlease check your configuration file.")
            self.stop()
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Fatal error: {e}", exc_info=True)
            self.stop()
            sys.exit(1)

    def stop(self):
        """Stop the pipeline"""
        self.logger.info("Stopping Email Security Pipeline")
        self.running = False
        self.ingestion_manager.close_all_connections()
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=True)
        self.logger.info("Pipeline stopped")

    def _monitoring_loop(self):
        """Main monitoring loop"""
        iteration = 0

        while self.running:
            iteration += 1
            self.logger.info(f"=== Monitoring Cycle {iteration} ===")

            try:
                # Fetch emails
                with Spinner("Checking for new emails..."):
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

                # Log metrics summary periodically (every 10 iterations)
                if self.metrics and iteration % 10 == 0:
                    self._log_metrics_summary()

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
                if self.metrics:
                    self.metrics.record_error("monitoring_loop_error")
                CountdownTimer.wait(30, f"{Colors.RED}Retrying in{Colors.RESET}")

    def _analyze_email(self, email_data):
        """
        Analyze a single email

        Args:
            email_data: EmailData object
        """
        # Track processing time for performance monitoring
        start_time = time.time()
        
        try:
            safe_subject = sanitize_for_logging(email_data.subject, max_length=50)
            self.logger.info(f"Analyzing email: {safe_subject}...")

            # Parallel Analysis Layer
            # Optimization: Run independent analyzers concurrently
            future_spam = self.executor.submit(self.spam_analyzer.analyze, email_data)
            future_nlp = self.executor.submit(self.nlp_analyzer.analyze, email_data)
            future_media = self.executor.submit(self.media_analyzer.analyze, email_data)

            # Retrieve results (will wait if not ready)
            # Layer 1: Spam Analysis
            spam_result = future_spam.result()
            spam_symbol = Colors.get_risk_symbol(spam_result.risk_level)
            self.logger.debug(
                f"Spam analysis: score={spam_result.score:.2f}, "
                f"risk={spam_result.risk_level} {spam_symbol}"
            )

            # Layer 2: NLP Threat Detection
            nlp_result = future_nlp.result()
            nlp_symbol = Colors.get_risk_symbol(nlp_result.risk_level)
            self.logger.debug(
                f"NLP analysis: score={nlp_result.threat_score:.2f}, "
                f"risk={nlp_result.risk_level} {nlp_symbol}"
            )

            # Layer 3: Media Authenticity
            media_result = future_media.result()
            media_symbol = Colors.get_risk_symbol(media_result.risk_level)
            self.logger.debug(
                f"Media analysis: score={media_result.threat_score:.2f}, "
                f"risk={media_result.risk_level} {media_symbol}"
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

            # Calculate processing time
            processing_time_ms = (time.time() - start_time) * 1000

            # Record metrics if enabled
            if self.metrics:
                self.metrics.record_email_processed()
                self.metrics.record_processing_time(processing_time_ms)
                
                # Record threats detected with consistent classification
                # Only treat medium/high risk emails as "threats" in metrics.
                # Using .lower() here keeps us robust if upstream ever changes casing.
                if threat_report.risk_level.lower() in {"medium", "high"}:
                    # Determine threat type based on highest scoring layer
                    # Priority order for tie-breaking: spam > phishing > malware
                    # (i.e., spam_result > nlp_result > media_result)
                    threat_type = "unknown"
                    max_score = max(spam_result.score, nlp_result.threat_score, media_result.threat_score)
                    
                    # If all scores are 0, default to "spam" for consistency
                    if max_score == 0:
                        threat_type = "spam"
                    elif spam_result.score == max_score:
                        threat_type = "spam"
                    elif nlp_result.threat_score == max_score:
                        threat_type = "phishing"
                    elif media_result.threat_score == max_score:
                        threat_type = "malware"
                    
                    self.metrics.record_threat(threat_type, threat_report.risk_level.lower())

            self.logger.info(
                f"Analysis complete: overall_score={threat_report.overall_threat_score:.2f}, "
                f"risk={threat_report.risk_level}, time={processing_time_ms:.0f}ms"
            )

        except Exception as e:
            # Record error in metrics
            if self.metrics:
                self.metrics.record_error("analysis_error")
            self.logger.error(f"Error analyzing email: {e}", exc_info=True)

    def _log_metrics_summary(self):
        """
        Log a summary of collected metrics.
        
        TEACHING MOMENT: We log metrics periodically instead of on every email
        because it reduces log volume. Imagine processing 1000 emails - you don't
        want 1000 metric log entries, you want a summary every N iterations.
        
        INDUSTRY CONTEXT: Professional teams export these metrics to monitoring
        systems like Prometheus or CloudWatch every 60 seconds for dashboards
        and alerting.
        """
        if not self.metrics:
            return
        
        summary = self.metrics.get_summary()
        
        # Log with extra fields for structured logging
        self.logger.info(
            f"Metrics Summary: {summary['emails_processed']} emails processed, "
            f"{len(summary['threats_detected'])} threat types detected, "
            f"avg processing time: {summary['processing_time_stats'].get('avg_ms', 0):.0f}ms"
        )
        
        # Log detailed metrics at debug level
        self.logger.debug(f"Detailed metrics: {summary}")

    def _print_configuration_summary(self):
        """Print a summary of the current configuration"""
        print(f"\n{Colors.BOLD}📊 System Configuration:{Colors.RESET}")

        # Accounts
        print(f"  • {Colors.CYAN}Monitored Accounts:{Colors.RESET}")
        for account in self.config.email_accounts:
            status = f"{Colors.GREEN}Active{Colors.RESET}" if account.enabled else f"{Colors.GREY}Disabled{Colors.RESET}"
            print(f"    - {account.provider.title()}: {account.email} ({status})")

        # Analysis
        print(f"  • {Colors.CYAN}Analysis Layers:{Colors.RESET}")
        print(
            f"    - Spam Detection:   {Colors.GREEN}Active{Colors.RESET} "
            f"(Threshold: {self.config.analysis.spam_threshold})"
        )
        print(
            f"    - NLP Analysis:     {Colors.GREEN}Active{Colors.RESET} "
            f"(Threshold: {self.config.analysis.nlp_threshold})"
        )

        media_status = (
            f"{Colors.GREEN}Active{Colors.RESET}"
            if self.config.analysis.check_media_attachments
            else f"{Colors.GREY}Disabled{Colors.RESET}"
        )
        deepfake_status = (
            "Enabled"
            if self.config.analysis.deepfake_detection_enabled
            else "Disabled"
        )
        print(f"    - Media Check:      {media_status} (Deepfake: {deepfake_status})")

        # Alerts
        print(f"  • {Colors.CYAN}Alert Channels:{Colors.RESET}")
        channels = []
        if self.config.alerts.console:
            channels.append("Console")
        if self.config.alerts.webhook_enabled:
            channels.append("Webhook")
        if self.config.alerts.slack_enabled:
            channels.append("Slack")

        if channels:
            print(f"    - Enabled: {', '.join(channels)}")
        else:
            print(f"    - Enabled: {Colors.YELLOW}None{Colors.RESET}")

        print(f"  • {Colors.CYAN}System:{Colors.RESET}")
        print(f"    - Log Level:  {self.config.system.log_level}")
        print(f"    - Log Format: {self.config.system.log_format}")
        if self.config.system.enable_metrics:
            print(f"    - Metrics:    {Colors.GREEN}Enabled{Colors.RESET}")
        print(f"    - Interval:   {self.config.system.check_interval}s")

        # Documentation footer
        print(f"\n📚 {Colors.GREY}For help, see README.md or OUTLOOK_TROUBLESHOOTING.md{Colors.RESET}\n")


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
                # Offer Setup Wizard
                print(f"\n{Colors.CYAN}Would you like to run the interactive setup wizard?{Colors.RESET}")
                print(f"{Colors.GREY}(This will help you configure your email provider){Colors.RESET}")

                response = input(f"Run setup wizard? [Y/n] ").strip().lower()
                if response in ('', 'y', 'yes'):
                    if run_setup_wizard(config_file):
                        # Setup successful
                        sys.exit(0)
                    else:
                         # Wizard failed or skipped
                         print(f"{Colors.YELLOW}Setup skipped.{Colors.RESET}")

                # Fallback to copy only if wizard wasn't run or failed
                if not Path(config_file).exists():
                    response = input(f"Create '{config_file}' from template without wizard? [Y/n] ").strip().lower()
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
