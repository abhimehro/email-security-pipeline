"""
Unit tests for NLPThreatAnalyzer.analyze_with_transformer and _analyze_core_impl.

Tests cover:
  - analyze_with_transformer: truncation to 4096 characters, cache hit, cache miss + store
  - _analyze_core_impl: missing model/tokenizer/torch, happy path (mocking torch), and exception handling
"""

import unittest
import hashlib
import functools
from unittest.mock import MagicMock, patch

from src.modules.nlp_analyzer import NLPThreatAnalyzer


class MockConfig:
    def __init__(self):
        self.check_social_engineering = True
        self.check_urgency_markers = True
        self.check_authority_impersonation = True
        self.check_psychological_triggers = False
        self.nlp_threshold = 0.5
        self.nlp_model = "distilbert-base-uncased"
        self.nlp_model_revision = "main"
        self.enable_ml_model = True


@functools.total_ordering
class DummyProb:
    """A dummy class to simulate a PyTorch tensor with an item() method."""

    def __init__(self, val):
        self.val = val

    def item(self):
        return self.val

    def __lt__(self, other):
        return self.val < other.val

    def __eq__(self, other):
        return self.val == other.val


class TestAnalyzeWithTransformer(unittest.TestCase):
    def setUp(self):
        self.config = MockConfig()
        self.analyzer = NLPThreatAnalyzer(self.config)

    def test_analyze_with_transformer_truncation_and_cache_miss(self):
        """Test that long text is truncated, cache is checked, _analyze_core_impl is called, and result is cached."""
        self.analyzer._cache = MagicMock()
        self.analyzer._cache.get.return_value = None
        self.analyzer._analyze_core_impl = MagicMock(
            return_value={"threat_probability": 0.9}
        )

        long_text = "A" * 5000

        result = self.analyzer.analyze_with_transformer(long_text)

        truncated_text = "A" * 4096
        self.analyzer._analyze_core_impl.assert_called_once_with(truncated_text)
        self.assertEqual(result, {"threat_probability": 0.9})

        text_hash = hashlib.sha256(truncated_text.encode()).hexdigest()
        self.analyzer._cache.get.assert_called_once_with(text_hash)
        self.analyzer._cache.put.assert_called_once_with(
            text_hash, {"threat_probability": 0.9}
        )

    def test_analyze_with_transformer_cache_hit(self):
        """Test that _analyze_core_impl is bypassed if result is in cache."""
        self.analyzer._cache = MagicMock()
        self.analyzer._cache.get.return_value = {"threat_probability": 0.1}
        self.analyzer._analyze_core_impl = MagicMock()

        text = "Hello World"

        result = self.analyzer.analyze_with_transformer(text)

        self.analyzer._analyze_core_impl.assert_not_called()
        self.assertEqual(result, {"threat_probability": 0.1})

        text_hash = hashlib.sha256(text.encode()).hexdigest()
        self.analyzer._cache.get.assert_called_once_with(text_hash)
        self.analyzer._cache.put.assert_not_called()


class TestAnalyzeCoreImpl(unittest.TestCase):
    def setUp(self):
        self.config = MockConfig()
        self.analyzer = NLPThreatAnalyzer(self.config)
        self.analyzer.logger = MagicMock()

    def test_missing_model(self):
        """Return error if model is None."""
        self.analyzer.model = None
        self.analyzer.tokenizer = MagicMock()
        self.assertEqual(
            self.analyzer._analyze_core_impl("test"), {"error": "Model not loaded"}
        )

    def test_missing_tokenizer(self):
        """Return error if tokenizer is None."""
        self.analyzer.model = MagicMock()
        self.analyzer.tokenizer = None
        self.assertEqual(
            self.analyzer._analyze_core_impl("test"), {"error": "Model not loaded"}
        )

    @patch("src.modules.nlp_analyzer.torch", None)
    def test_missing_torch(self):
        """Return error if torch is not available."""
        self.analyzer.model = MagicMock()
        self.analyzer.tokenizer = MagicMock()
        self.assertEqual(
            self.analyzer._analyze_core_impl("test"), {"error": "Torch not available"}
        )

    @patch("src.modules.nlp_analyzer.torch")
    def test_happy_path(self, mock_torch):
        """Successfully mock torch execution and return probabilities."""
        self.analyzer.model = MagicMock()
        self.analyzer.tokenizer = MagicMock()

        # Setup tokenizer output
        mock_input_val = MagicMock()
        mock_input_val.to.return_value = "moved_input_ids"
        self.analyzer.tokenizer.return_value = {"input_ids": mock_input_val}

        # Setup device resolution from model parameters
        mock_parameter = MagicMock()
        mock_parameter.device = "mock_device"
        self.analyzer.model.parameters.return_value = iter([mock_parameter])
        self.analyzer.device = None

        # Setup model outputs
        mock_outputs = MagicMock()
        mock_outputs.logits = "mock_logits"
        self.analyzer.model.return_value = mock_outputs

        # Setup torch.softmax return value
        mock_preds = [[DummyProb(0.8), DummyProb(0.2)]]
        mock_torch.softmax.return_value = mock_preds

        result = self.analyzer._analyze_core_impl("test_text")

        self.analyzer.tokenizer.assert_called_with(
            "test_text", return_tensors="pt", truncation=True, max_length=512
        )
        mock_input_val.to.assert_called_with("mock_device")
        self.analyzer.model.assert_called_with(input_ids="moved_input_ids")
        mock_torch.softmax.assert_called_with("mock_logits", dim=-1)

        self.assertEqual(result, {"threat_probability": 0.8, "confidence": 0.8})

    @patch("src.modules.nlp_analyzer.torch")
    def test_happy_path_with_explicit_device(self, mock_torch):
        """Successfully mock torch execution when device is explicitly set on analyzer."""
        self.analyzer.model = MagicMock()
        self.analyzer.tokenizer = MagicMock()
        self.analyzer.device = "explicit_device"

        # Setup tokenizer output
        mock_input_val = MagicMock()
        mock_input_val.to.return_value = "moved_input_ids"
        self.analyzer.tokenizer.return_value = {"input_ids": mock_input_val}

        # Setup model outputs
        mock_outputs = MagicMock()
        mock_outputs.logits = "mock_logits"
        self.analyzer.model.return_value = mock_outputs

        # Setup torch.softmax return value
        mock_preds = [[DummyProb(0.7), DummyProb(0.3)]]
        mock_torch.softmax.return_value = mock_preds

        result = self.analyzer._analyze_core_impl("test_text")

        mock_input_val.to.assert_called_with("explicit_device")

        self.assertEqual(result, {"threat_probability": 0.7, "confidence": 0.7})

    @patch("src.modules.nlp_analyzer.torch")
    def test_exception_handling(self, mock_torch):
        """Catch exceptions during tokenization/modeling and return error dictionary."""
        self.analyzer.model = MagicMock()
        self.analyzer.tokenizer = MagicMock()

        self.analyzer.tokenizer.side_effect = Exception("Tokenizer failed")

        result = self.analyzer._analyze_core_impl("test")

        self.assertEqual(result, {"error": "Tokenizer failed"})
        self.analyzer.logger.error.assert_called_with(
            "Transformer analysis error: Tokenizer failed"
        )


if __name__ == "__main__":
    unittest.main()
