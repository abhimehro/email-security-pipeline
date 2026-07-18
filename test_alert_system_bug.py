import logging
from src.modules.alert_system import AlertSystem
from src.modules.alert_system import ThreatReport
from datetime import datetime
from src.utils.config import Config
from src.modules.email_data import EmailData

config = Config()
alert_system = AlertSystem(config=config)

report = ThreatReport(
    email=EmailData(
        id="test-id",
        folder="INBOX",
        sender="test@example.com",
        subject="Test Email",
        date=datetime.now(),
        body="Test body",
        raw_content=b"Test body"
    ),
    timestamp=datetime.now().isoformat(),
    sender="test@example.com",
    subject="Test Email",
    overall_threat_score=10.0,
    risk_level="LOW",
    reasons=["test reason"],
    spam_result=None,
    nlp_result=None,
    media_result=None,
    raw_email_path=None
)

alert_system._console_clean_report(report)
print("Finished clean report")
