
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.config import AlertConfig
from src.modules.alert_system import AlertSystem

def test_redaction():
    # Mock config
    config = AlertConfig(
        console=True,
        webhook_enabled=False,
        webhook_url=None,
        slack_enabled=False,
        slack_webhook=None,
        threat_low=30.0,
        threat_medium=60.0,
        threat_high=80.0
    )

    alert_system = AlertSystem(config)

    scenarios = [
        (
            "https://user:password@example.com/resource",
            "https://user:[REDACTED]@example.com/resource",
            "Credentials in URL"
        ),
        (
            "https://example.com?token=secret123",
            "https://example.com?token=%5BREDACTED%5D",
            "Query params (Encoded)"
        ),
        (
            "https://hooks.slack.com/services/T000/B000/TOKEN123",
            "https://hooks.slack.com/services/T000/B000/[REDACTED]",
            "Slack webhook"
        ),
        (
            "https://user:pass@[::1]:8080/resource",
            "https://user:[REDACTED]@[::1]:8080/resource",
            "IPv6 with credentials"
        ),
        (
            "https://user%40name:pass@example.com",
            "https://user%40name:[REDACTED]@example.com",
            "Special chars in username"
        ),
        (
            "https://:password@example.com",
            "https://:[REDACTED]@example.com",
            "Password only"
        )
    ]

    failures = []

    print("Running redaction tests...")
    for url, expected, desc in scenarios:
        redacted = alert_system._redact_url_secrets(url)

        if redacted != expected:
            print(f"❌ FAIL: {desc}")
            print(f"  Input:    {url}")
            print(f"  Expected: {expected}")
            print(f"  Actual:   {redacted}")
            failures.append(desc)
        else:
            print(f"✅ PASS: {desc}")

    print()
    if failures:
        print(f"Test failed for: {', '.join(failures)}")
        assert False, f"Test failed for: {', '.join(failures)}"
    else:
        print("All tests passed!")

if __name__ == "__main__":
    test_redaction()
