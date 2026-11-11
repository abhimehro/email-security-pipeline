import pytest

from src.modules.spam_analyzer import SpamAnalyzer
from src.utils.config import AnalysisConfig


@pytest.fixture
def spam_analyzer():
    # Mock config
    config = AnalysisConfig(
        spam_threshold=5.0,
        spam_check_headers=True,
        spam_check_urls=True,
        nlp_model="test",
        nlp_model_revision="main",
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
        deepfake_model_path=None,
    )
    return SpamAnalyzer(config)


def test_check_urls_correctness(spam_analyzer):
    # Test with duplicates and mix of suspicious/safe URLs
    urls = [
        "http://google.com",
        "http://bit.ly/suspicious",
        "http://bit.ly/suspicious",  # Duplicate suspicious
        "http://example.com",
        "http://192.168.1.1/admin",  # Suspicious IP
        "http://very-long-suspicious-subdomain-that-is-way-too-long.example.com",  # Suspicious length
        "http://google.com",  # Duplicate safe
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
    assert len(suspicious) == 4  # bit.ly (2) + ip (1) + long (1)


def test_shorteners_still_caught(spam_analyzer):
    # Verify shorteners removed from SHORTENER_PATTERN are still caught by COMBINED
    urls = ["http://goo.gl/test", "http://tinyurl.com/abc"]
    score, suspicious = spam_analyzer._check_urls(urls)
    assert score == 1.0  # 0.5 * 2
    assert len(suspicious) == 2


@pytest.mark.parametrize(
    "html_content,expected_detected",
    [
        ("<p style='font-size: 0px'>hidden text</p>", True),
        ("<p style='font-size: 1px'>hidden text</p>", True),
        ("<p style='font-size: 2px'>hidden text</p>", True),
        ("<p style='font-size: 3px'>normal text</p>", False),
        ("<p style='font-size: 14px'>normal text</p>", False),
        ("<p style='color: #ffffff; background-color: #ffffff'>hidden</p>", True),
        ("<p style='color: #fff; background: #fff'>hidden</p>", True),
        ("<p style='color: #333333;'>normal text</p>", False),
        ("<p style='color: #333333; background: #ffffff;'>normal text</p>", False),
        ("<p style='background: #ffffff;'>normal text</p>", False),
        ("<p>clean plain html without style</p>", False),
        (
            "<div style='font-size: 0px; color: #fff; background: #fff'>both</div>",
            True,
        ),
    ],
)
def test_hidden_text_detection_cases(spam_analyzer, html_content, expected_detected):
    score, indicators = spam_analyzer._check_hidden_text(html_content.lower())
    if expected_detected:
        assert score == 2.0
        assert "Hidden text detected" in indicators
    else:
        assert score == 0.0
        assert indicators == []
