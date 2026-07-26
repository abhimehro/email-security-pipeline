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

def test_auth_results(spam_analyzer):
    headers = {
        "authentication-results": [
            "spf=fail",
            "dkim=permerror",
            "dkim=neutral",
            "dkim=fail"
        ]
    }
    score, issues = spam_analyzer._check_auth_results(headers, spf_fail=False)
    assert "DKIM verification failed (Authentication-Results)" in issues
    assert "SPF verification failed (Authentication-Results)" in issues
    assert score == 4.5

def test_auth_results_case_insensitivity(spam_analyzer):
    headers = {
        "authentication-results": [
            "SPF=Fail",
            "DKIM=permerror"
        ]
    }
    score, issues = spam_analyzer._check_auth_results(headers, spf_fail=False)
    assert "DKIM verification failed (Authentication-Results)" in issues
    assert "SPF verification failed (Authentication-Results)" in issues
    assert score == 4.5

def test_auth_results_empty(spam_analyzer):
    headers = {}
    score, issues = spam_analyzer._check_auth_results(headers, spf_fail=False)
    assert issues == []
    assert score == 0.0
