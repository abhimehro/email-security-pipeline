from src.modules.alert_system import AlertSystem
import urllib.parse

class DummyConfig:
    webhook_url = "https://example.com"
    console = True

a = AlertSystem(DummyConfig())
msg = "Error connecting to https://discord.com/api/webhooks/1234/MY_SECRET_TOKEN"
print("Original:", msg)
print("Redacted:", a._sanitize_error_message(Exception(msg)))

msg2 = "Error connecting to /api/webhooks/1234/MY_SECRET_TOKEN in discord"
print("Original:", msg2)
print("Redacted:", a._sanitize_error_message(Exception(msg2)))
