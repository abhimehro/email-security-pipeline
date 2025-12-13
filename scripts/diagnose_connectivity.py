#!/usr/bin/env python3
"""
Run connection diagnostics for a specific email account configured in the environment.
"""

import argparse
import sys
import os
import logging
import json

# Add the project root directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.modules.email_ingestion import EmailIngestionManager
from src.utils.config import Config

# Set up basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    """
    Main function to run the connection diagnostics.
    """
    parser = argparse.ArgumentParser(description="Run connection diagnostics for an email account.")
    parser.add_argument("email", help="The email address of the account to diagnose.")
    args = parser.parse_args()

    # Load email configurations from environment variables
    config = Config()
    email_accounts = config.email_accounts
    if not email_accounts:
        logging.error("No email accounts are configured. Please check your .env file.")
        sys.exit(1)

    # Initialize the Email Ingestion Manager
    manager = EmailIngestionManager(email_accounts)

    # Run the diagnostics
    diagnostics = manager.diagnose_account_connection(args.email)

    if diagnostics:
        print(json.dumps(diagnostics, indent=2))
    else:
        logging.error(f"Diagnostics could not be run for {args.email}. "
                      f"Ensure the email address is correct and configured.")
        sys.exit(1)

if __name__ == "__main__":
    main()
