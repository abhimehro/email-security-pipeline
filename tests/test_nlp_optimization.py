
import unittest
from unittest.mock import MagicMock, patch
from src.modules.nlp_analyzer import NLPThreatAnalyzer

# Mock config
class MockConfig:
    def __init__(self):
        self.check_social_engineering = True
        self.check_urgency_markers = True
        self.check_authority_impersonation = True
        self.check_psychological_triggers = True
        self.nlp_threshold = 0.5
        self.nlp_model = 'distilbert-base-uncased'

class TestNLPOptimization(unittest.TestCase):
    def setUp(self):
        self.config = MockConfig()
        self.analyzer = NLPThreatAnalyzer(self.config)

        # Mock model and tokenizer
        self.analyzer.model = MagicMock()
        self.analyzer.tokenizer = MagicMock()

        # Ensure device is set to avoid attribute errors if code accesses it
        self.analyzer.device = 'cpu'

    @patch('src.modules.nlp_analyzer.torch')
    def test_truncation_optimization(self, mock_torch):
        # Setup
        # Create text much longer than 4096 chars
        long_text = "A" * 10000

        # Setup tokenizer mock to return something valid
        self.analyzer.tokenizer.return_value = {"input_ids": [1]}
        # Mock model output
        mock_output = MagicMock()
        mock_output.logits = MagicMock()
        self.analyzer.model.return_value = mock_output

        # We need to mock torch.softmax and torch.no_grad
        mock_torch.softmax.return_value = MagicMock()
        mock_torch.softmax.return_value.__getitem__.return_value = [0.1] # threat prob

        # Action
        self.analyzer.analyze_with_transformer(long_text)

        # Verify
        # The tokenizer should be called with truncated text (4096 chars)
        args, kwargs = self.analyzer.tokenizer.call_args
        text_arg = args[0]

        self.assertEqual(len(text_arg), 4096)
        self.assertEqual(text_arg, "A" * 4096)

    @patch('src.modules.nlp_analyzer.torch')
    def test_caching_behavior(self, mock_torch):
        # Setup tokenizer to count calls
        self.analyzer.tokenizer.return_value = {"input_ids": [1]}
        mock_output = MagicMock()
        mock_output.logits = MagicMock()
        self.analyzer.model.return_value = mock_output
        mock_torch.softmax.return_value.__getitem__.return_value = [0.1]

        text1 = "Short text"
        text2 = "Short text" # Identical

        # Action
        self.analyzer.analyze_with_transformer(text1)
        self.analyzer.analyze_with_transformer(text2)

        # Verify
        # Tokenizer should be called only once due to LRU cache on _analyze_with_transformer_core
        self.assertEqual(self.analyzer.tokenizer.call_count, 1)

    @patch('src.modules.nlp_analyzer.torch')
    def test_caching_with_long_text_truncation(self, mock_torch):
        # Setup
        self.analyzer.tokenizer.return_value = {"input_ids": [1]}
        mock_output = MagicMock()
        mock_output.logits = MagicMock()
        self.analyzer.model.return_value = mock_output
        mock_torch.softmax.return_value.__getitem__.return_value = [0.1]

        # Construct two texts that differ ONLY after the 4096 char mark
        # They should both be truncated to the same string, thus hitting the cache
        long_text1 = "A" * 5000 + "1"
        long_text2 = "A" * 5000 + "2"

        # Action
        self.analyzer.analyze_with_transformer(long_text1)
        self.analyzer.analyze_with_transformer(long_text2)

        # Verify
        # Tokenizer call count should be 1 because truncation makes them identical
        self.assertEqual(self.analyzer.tokenizer.call_count, 1)

        # Arguments should be truncated
        args, kwargs = self.analyzer.tokenizer.call_args
        self.assertEqual(len(args[0]), 4096)

if __name__ == '__main__':
    unittest.main()
