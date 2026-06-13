import unittest
from datetime import datetime
from unittest.mock import MagicMock
from email.message import Message

from src.modules.email_data import EmailData
from src.modules.spam_analyzer import SpamAnalyzer
from src.modules.nlp_analyzer import NLPThreatAnalyzer
from src.utils.config import AnalysisConfig

class TestCachingIntegration(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock(spec=AnalysisConfig)
        self.config.spam_check_urls = True
        self.config.spam_check_headers = True
        self.config.check_social_engineering = True
        self.config.check_urgency_markers = True
        self.config.check_authority_impersonation = True
        self.config.nlp_threshold = 0.5
        self.config.spam_threshold = 0.5
        
        self.config.enable_ml_model = True
        self.config.nlp_model = "distilbert-base-uncased"
        self.config.nlp_model_revision = "main"
        self.config.nlp_batch_size = 1
        
        self.spam_analyzer = SpamAnalyzer(self.config)
        
        # Override torch check so ML model is seemingly enabled
        import src.modules.nlp_analyzer
        original_torch = src.modules.nlp_analyzer.torch
        src.modules.nlp_analyzer.torch = MagicMock()
        
        # Avoid AutoModel loading
        original_automodel = src.modules.nlp_analyzer.AutoModelForSequenceClassification
        src.modules.nlp_analyzer.AutoModelForSequenceClassification = MagicMock()
        
        original_tokenizer = src.modules.nlp_analyzer.AutoTokenizer
        src.modules.nlp_analyzer.AutoTokenizer = MagicMock()
        
        self.nlp_analyzer = NLPThreatAnalyzer(self.config)
        
        # Avoid real transformer logic by mocking _analyze_core_impl directly, so cache executes
        self.nlp_analyzer._analyze_core_impl = MagicMock(return_value={"threat_score": 0.9, "label": "phishing"})
        
        self.original_torch = original_torch
        self.original_automodel = original_automodel
        self.original_tokenizer = original_tokenizer
        
    def tearDown(self):
        import src.modules.nlp_analyzer
        src.modules.nlp_analyzer.torch = self.original_torch
        src.modules.nlp_analyzer.AutoModelForSequenceClassification = self.original_automodel
        src.modules.nlp_analyzer.AutoTokenizer = self.original_tokenizer

    def _create_email_data(self, subject: str, body: str, sender: str = "test@example.com") -> EmailData:
        email = EmailData(
            message_id="test-id",
            subject=subject,
            sender=sender,
            recipient="victim@example.com",
            date=datetime.now(),
            body_text=body,
            body_html=body,
            headers={},
            attachments=[],
            raw_email=Message(),
            account_email="test@example.com",
            folder="INBOX",
        )
        return email

    def test_caching_clear_integration_across_modules(self):
        """
        SECURITY STORY: The caching layer improves performance for repetitive
        analysis, but tests must verify cache clearing operates correctly across
        multiple analyzer instances. If not, state could leak across tests or
        long-running processes might accumulate stale data.
        """
        email_data = self._create_email_data(
            subject="URGENT: Verify Your Account Now!!!", 
            body="Your account will be SUSPENDED unless you click here immediately: http://evil-phishing-site.com/login?verify=now Act now or lose access forever! Limited time offer!", 
            sender="security@definitely-not-your-bank.com"
        )
        
        # Trigger analyzers to populate their caches
        self.spam_analyzer.analyze(email_data)
        
        # NLP analyzer's `analyze` will call `analyze_with_transformer` if ML features are enabled
        self.nlp_analyzer.analyze(email_data)
        
        # Verify both caches are populated by the integration flow
        self.assertGreater(len(self.spam_analyzer.url_cache), 0, "SpamAnalyzer url_cache should be populated")
        self.assertGreater(len(self.nlp_analyzer._cache), 0, "NLPThreatAnalyzer _cache should be populated")
        
        # Verify that repeating the analysis hits the cache
        self.nlp_analyzer._analyze_core_impl.reset_mock()
        self.nlp_analyzer.analyze(email_data)
        self.nlp_analyzer._analyze_core_impl.assert_not_called()
        
        # Clear the caches
        self.spam_analyzer.url_cache.clear()
        self.nlp_analyzer._cache.clear()
        
        # Verify both caches are cleared
        self.assertEqual(len(self.spam_analyzer.url_cache), 0, "SpamAnalyzer url_cache should be empty after clear")
        self.assertEqual(len(self.nlp_analyzer._cache), 0, "NLPThreatAnalyzer _cache should be empty after clear")
        
        # Verify that after clearing, analysis calls the implementation again
        self.nlp_analyzer.analyze(email_data)
        self.nlp_analyzer._analyze_core_impl.assert_called_once()

if __name__ == "__main__":
    unittest.main()
