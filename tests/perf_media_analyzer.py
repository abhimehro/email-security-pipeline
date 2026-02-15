import time
import sys
import logging
import concurrent.futures
from unittest.mock import MagicMock
from src.modules.media_analyzer import MediaAuthenticityAnalyzer
from src.modules.email_data import EmailData
from src.utils.config import AnalysisConfig

# Monkeypatch ThreadPoolExecutor to verify creation
original_tpe = concurrent.futures.ThreadPoolExecutor
tpe_creation_count = 0

class TrackingTPE(original_tpe):
    def __init__(self, *args, **kwargs):
        global tpe_creation_count
        tpe_creation_count += 1
        super().__init__(*args, **kwargs)

concurrent.futures.ThreadPoolExecutor = TrackingTPE

# Mock configuration
config = MagicMock(spec=AnalysisConfig)
config.check_media_attachments = True
config.deepfake_detection_enabled = True
config.media_analysis_timeout = 5
config.deepfake_provider = "simulator"

# Mock EmailData
def create_mock_email(num_attachments=1):
    attachments = []
    # Valid MP4 header (ftyp at offset 4) + enough data to pass size check
    mp4_data = b'\x00\x00\x00\x18ftypmp42' + b'\x00' * 2000

    for i in range(num_attachments):
        attachments.append({
            'filename': f'video_{i}.mp4',
            'content_type': 'video/mp4',
            'size': len(mp4_data),
            'data': mp4_data,
            'truncated': False
        })

    return EmailData(
        message_id="123",
        subject="Test Email",
        sender="sender@example.com",
        recipient="recipient@example.com",
        date=None,
        body_text="Test body",
        body_html=None,
        headers={},
        attachments=attachments,
        raw_email=None,
        account_email="me@example.com",
        folder="INBOX"
    )

def run_benchmark():
    global tpe_creation_count
    analyzer = MediaAuthenticityAnalyzer(config)

    # Mock internal methods to simulate work without actual OpenCV/IO
    analyzer._check_deepfake_indicators = MagicMock(return_value=(0.0, []))

    # Increase count to make overhead visible
    email_data = create_mock_email(num_attachments=500)

    print("Starting benchmark with 500 attachments...")
    tpe_creation_count = 0
    start_time = time.time()
    analyzer.analyze(email_data)
    end_time = time.time()

    duration = end_time - start_time
    print(f"Time to analyze 500 attachments: {duration:.4f} seconds")
    print(f"ThreadPoolExecutor created {tpe_creation_count} times")
    return duration

if __name__ == "__main__":
    logging.basicConfig(level=logging.CRITICAL)
    run_benchmark()
