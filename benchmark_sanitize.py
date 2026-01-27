
import time
import re
import os
from src.modules.email_ingestion import IMAPClient, EmailAccountConfig

# Mock config
config = EmailAccountConfig(
    enabled=True,
    email="test@example.com",
    imap_server="imap.example.com",
    imap_port=993,
    app_password="pass",
    folders=["INBOX"],
    provider="test",
    use_ssl=True,
    verify_ssl=True
)

client = IMAPClient(config)

# Test filenames
filenames = [
    "simple.txt",
    "path/to/file.exe",
    "../../etc/passwd",
    "file..with..dots.txt",
    "invalid<char>.png",
    "a" * 100 + ".txt",
    ".hidden_file",
] * 1000  # 7000 filenames

start_time = time.time()
for filename in filenames:
    client._sanitize_filename(filename)
end_time = time.time()

print(f"Time taken: {end_time - start_time:.6f} seconds")
