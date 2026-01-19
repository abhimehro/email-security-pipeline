
import time
import re
import sys
import logging
from dataclasses import dataclass
from typing import List, Dict, Union, Any
from datetime import datetime

# Fix path to include current directory so we can import src
sys.path.append('.')

from src.modules.nlp_analyzer import NLPThreatAnalyzer
from src.modules.email_ingestion import EmailData

# Setup logging
logging.basicConfig(level=logging.ERROR) # Reduce noise

class MockConfig:
    check_social_engineering = True
    check_urgency_markers = True
    check_authority_impersonation = True
    check_psychological_triggers = True
    nlp_threshold = 0.7
    nlp_model = None

def run_test():
    analyzer = NLPThreatAnalyzer(MockConfig())
    # Disable ML explicitly
    analyzer.model = None
    analyzer.tokenizer = None

    # Test cases
    emails = [
        EmailData(
            message_id="1",
            subject="URGENT: Verify your account immediately",
            body_text="Dear user, we noticed unusual activity. Please verify your account or it will be suspended. Act now! From: CEO of Bank.",
            body_html="",
            sender="sender@example.com",
            recipient="me@example.com",
            date=datetime.now(),
            headers={},
            attachments=[],
            raw_email=None,
            account_email="me@example.com",
            folder="Inbox"
        ),
        EmailData(
            message_id="2",
            subject="You won a prize!",
            body_text="Congratulations winner! Click here to claim your free gift. This is a limited time offer. Don't delay.",
            body_html="",
            sender="sender@example.com",
            recipient="me@example.com",
            date=datetime.now(),
            headers={},
            attachments=[],
            raw_email=None,
            account_email="me@example.com",
            folder="Inbox"
        ),
        EmailData(
            message_id="3",
            subject="Security Alert from Google",
            body_text="We detected unauthorized access. Reset your password within 24 hours. This is an official notice.",
            body_html="",
            sender="sender@example.com",
            recipient="me@example.com",
            date=datetime.now(),
            headers={},
            attachments=[],
            raw_email=None,
            account_email="me@example.com",
            folder="Inbox"
        ),
        # A long text to measure performance
        EmailData(
            message_id="4",
            subject="Long email",
            body_text=("Urgent " * 100) + ("Verify account " * 100) + ("Bank " * 100) + ("Free " * 100),
            body_html="",
            sender="sender@example.com",
            recipient="me@example.com",
            date=datetime.now(),
            headers={},
            attachments=[],
            raw_email=None,
            account_email="me@example.com",
            folder="Inbox"
        )
    ]

    start_time = time.time()
    results = []
    for _ in range(100): # Run 100 times to get measurable time
        for email in emails:
            results.append(analyzer.analyze(email))
    end_time = time.time()

    print(f"Total time: {end_time - start_time:.4f} seconds")

    # Print results of first run for verification
    first_run_results = results[:len(emails)]
    for i, res in enumerate(first_run_results):
        print(f"Email {i+1} Score: {res.threat_score:.2f}")
        print(f"  SE: {len(res.social_engineering_indicators)}")
        print(f"  UG: {len(res.urgency_markers)}")
        print(f"  AU: {len(res.authority_impersonation)}")
        print(f"  PS: {len(res.psychological_triggers)}")

if __name__ == "__main__":
    run_test()
