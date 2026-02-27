
import pytest
from src.modules.spam_analyzer import SpamAnalyzer, SpamAnalysisResult
from src.utils.config import AnalysisConfig

@pytest.fixture
def spam_analyzer():
    # Mock config
    config = AnalysisConfig(
        spam_threshold=5.0,
        spam_check_headers=True,
        spam_check_urls=True,
        nlp_model="test",
        nlp_threshold=0.5,
        nlp_batch_size=1,
        check_social_engineering=True,
        check_urgency_markers=True,
        check_authority_impersonation=True,
        check_media_attachments=True,
        deepfake_detection_enabled=True,
        media_analysis_timeout=1,
        deepfake_provider="simulator",
        deepfake_api_key=None,
        deepfake_api_url=None,
        deepfake_model_path=None
    )
    return SpamAnalyzer(config)

def test_check_urls_correctness(spam_analyzer):
    # Test with duplicates and mix of suspicious/safe URLs
    urls = [
        "http://google.com",
        "http://bit.ly/suspicious",
        "http://bit.ly/suspicious", # Duplicate suspicious
        "http://example.com",
        "http://192.168.1.1/admin", # Suspicious IP
        "http://very-long-suspicious-subdomain-that-is-way-too-long.example.com", # Suspicious length
        "http://google.com", # Duplicate safe
    ]

    score, suspicious = spam_analyzer._check_urls(urls)

    # Updated expectation after optimization (double counting removed):
    # google.com -> 0
    # bit.ly -> 0.5 (combined only) * 2 instances = 1.0
    # example.com -> 0
    # 192.168.1.1 -> 0.5 * 1 = 0.5
    # very-long... -> 0.5 * 1 = 0.5
    # Total score = 2.0 (was 3.0)

    assert score == 2.0
    assert len(suspicious) == 4 # bit.ly (2) + ip (1) + long (1)

def test_shorteners_still_caught(spam_analyzer):
    # Verify shorteners removed from SHORTENER_PATTERN are still caught by COMBINED
    urls = [
        "http://goo.gl/test",
        "http://tinyurl.com/abc"
    ]
    score, suspicious = spam_analyzer._check_urls(urls)
    assert score == 1.0 # 0.5 * 2
    assert len(suspicious) == 2
