import unittest
from unittest.mock import MagicMock

from src.modules.media_analyzer import MediaAuthenticityAnalyzer


class TestMediaAnalyzerAdvanceFrame(unittest.TestCase):
    def setUp(self):
        config = MagicMock()
        self.analyzer = MediaAuthenticityAnalyzer(config)

    def test_advance_small_jump(self):
        cap = MagicMock()
        cap.grab.side_effect = [True] * 10
        result = self.analyzer._advance_to_frame(cap, current_frame=0, target_frame=10)
        self.assertEqual(result, 10)
        self.assertEqual(cap.grab.call_count, 10)
        cap.set.assert_not_called()

    def test_advance_large_jump(self):
        cap = MagicMock()
        result = self.analyzer._advance_to_frame(cap, current_frame=0, target_frame=40)
        self.assertEqual(result, 40)
        cap.set.assert_called_once()
        cap.grab.assert_not_called()

    def test_advance_error_path_grab_fails(self):
        cap = MagicMock()
        # Fails on 6th grab
        cap.grab.side_effect = [True, True, True, True, True, False]
        result = self.analyzer._advance_to_frame(cap, current_frame=0, target_frame=10)
        # loop runs until current_frame reaches 5 and then break
        self.assertEqual(result, 5)
        self.assertEqual(cap.grab.call_count, 6)
        cap.set.assert_not_called()


if __name__ == "__main__":
    unittest.main()
