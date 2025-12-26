
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from src.utils.colors import Colors
from src.modules.alert_system import AlertSystem, ThreatReport

class MockConfig:
    def __init__(self):
        self.threat_low = 10
        self.console = True
        self.webhook_enabled = False
        self.slack_enabled = False

def test_alert():
    config = MockConfig()
    alert_system = AlertSystem(config)

    report = ThreatReport(
        email_id="123",
        subject="Urgent: Account Suspended",
        sender="security@gmai1.com",
        recipient="user@example.com",
        date="2023-10-27T10:00:00",
        overall_threat_score=85.5,
        risk_level="high",
        spam_analysis={
            'indicators': ['Spoofed sender', 'Suspicious link'],
            'score': 80,
            'risk_level': 'high',
            'suspicious_urls': [],
            'header_issues': []
        },
        nlp_analysis={
            'social_engineering_indicators': ['Urgency', 'Threat'],
            'authority_impersonation': ['Claiming to be Security Team'],
            'threat_score': 80,
            'risk_level': 'high',
            'urgency_markers': [],
            'psychological_triggers': []
        },
        media_analysis={
            'file_type_warnings': [],
            'threat_score': 0,
            'risk_level': 'low',
            'suspicious_attachments': [],
            'size_anomalies': [],
            'potential_deepfakes': []
        },
        recommendations=["Do not reply", "Mark as spam"],
        timestamp="2023-10-27T10:00:05"
    )

    alert_system._console_alert(report)

if __name__ == "__main__":
    test_alert()
