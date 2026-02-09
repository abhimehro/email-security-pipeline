import pytest
import time
from unittest.mock import MagicMock, patch
from src.modules.media_analyzer import MediaAuthenticityAnalyzer, MediaAnalysisResult
from src.modules.email_ingestion import EmailData

@pytest.fixture
def analyzer():
    config = MagicMock()
    config.check_media_attachments = True
    config.deepfake_detection_enabled = True
    config.media_analysis_timeout = 1  # 1 second timeout
    return MediaAuthenticityAnalyzer(config)

def test_deepfake_analysis_timeout(analyzer):
    # Mock data
    email_data = MagicMock(spec=EmailData)
    email_data.attachments = [{
        'filename': 'video.mp4',
        'content_type': 'video/mp4',
        'size': 1024 * 1024,
        'data': b'fake_data' * 1000,
        'truncated': False
    }]

    # Mock _check_file_extension and others to return 0 score so deepfake check runs
    analyzer._check_file_extension = MagicMock(return_value=(0.0, []))
    analyzer._check_content_type_mismatch = MagicMock(return_value=(0.0, ""))
    analyzer._check_size_anomaly = MagicMock(return_value=(0.0, ""))

    # Mock _check_deepfake_indicators to sleep longer than timeout
    def slow_function(*args, **kwargs):
        time.sleep(2)
        return 10.0, ["Should not be returned"]

    # We patch the INSTANCE method. Since we already instantiated analyzer, we can just replace it.
    # Note: Because the method is called in a separate thread, but we are just replacing the python function object on the instance,
    # and ThreadPoolExecutor uses the callable passed to submit.
    # We submit self._check_deepfake_indicators.
    analyzer._check_deepfake_indicators = slow_function

    # Run analysis
    start_time = time.time()
    result = analyzer.analyze(email_data)
    duration = time.time() - start_time

    # Verification
    # 1. It should not take much longer than timeout (allow some overhead)
    assert duration < 1.5, f"Analysis took too long: {duration}s"

    # 2. It should log warning/error (we check the result side effects)
    # result.size_anomalies should contain the timeout message
    assert any("Deepfake analysis timed out" in s for s in result.size_anomalies)

    # 3. Threat score should NOT include the deepfake score (10.0)
    # Since other checks returned 0, total score should be 0.0
    assert result.threat_score == 0.0
