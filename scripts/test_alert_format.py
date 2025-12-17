
import sys
import os
from datetime import datetime
from unittest.mock import Mock

# Assuming we run this from the root of the repo
sys.path.append(os.getcwd())

# Import using the full package path to avoid relative import issues
from src.modules.alert_system import AlertSystem, ThreatReport
from src.utils.config import AlertConfig

def test_console_alert():
    # Mock config
    config = Mock(spec=AlertConfig)
    config.console = True
    config.webhook_enabled = False
    config.slack_enabled = False
    config.threat_low = 30

    alert_system = AlertSystem(config)

    # Create a dummy threat report
    report = ThreatReport(
        email_id="test-123",
        subject="URGENT: Verify your account immediately",
        sender="security@goggle.com",
        recipient="user@company.com",
        date=datetime.now().isoformat(),
        overall_threat_score=85.5,
        risk_level="high",
        spam_analysis={
            'score': 8.0,
            'risk_level': 'high',
            'indicators': ['SPF fail', 'DKIM fail', 'Blacklisted sender'],
            'suspicious_urls': ['http://fake-google-login.com'],
            'header_issues': []
        },
        nlp_analysis={
            'score': 0.85,
            'risk_level': 'high',
            'social_engineering_indicators': ['Urgency detected', 'Fear tactic'],
            'urgency_markers': ['immediately', '24 hours'],
            'authority_impersonation': ['Google Security Team'],
            'psychological_triggers': []
        },
        media_analysis={
            'score': 0.0,
            'risk_level': 'low',
            'suspicious_attachments': [],
            'file_type_warnings': [],
            'size_anomalies': [],
            'potential_deepfakes': []
        },
        recommendations=[
            "⚠️ HIGH RISK: Move to spam folder immediately",
            "🎣 Potential phishing: Do not click links or provide credentials",
            "🔗 Suspicious URLs detected: Verify links before clicking"
        ],
        timestamp=datetime.now().isoformat()
    )

    print("Testing Console Alert Format:")
    alert_system._console_alert(report)

if __name__ == "__main__":
    test_console_alert()
