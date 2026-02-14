
import numpy as np
import cv2
import unittest
from unittest.mock import MagicMock
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.modules.media_analyzer import MediaAuthenticityAnalyzer

class TestMediaOptimization(unittest.TestCase):
    def setUp(self):
        self.config = MagicMock()
        self.config.check_media_attachments = True
        self.config.deepfake_detection_enabled = True
        # Maintain consistency with other tests that configure a media analysis timeout
        self.config.media_analysis_timeout = 30
        self.analyzer = MediaAuthenticityAnalyzer(self.config)

    def original_check_compression_artifacts(self, gray_frames):
        score = 0.0
        issues = []
        high_freq_noise_count = 0
        frames_to_check = gray_frames[:5]

        for gray in frames_to_check:
            dft = cv2.dft(np.float32(gray), flags=cv2.DFT_COMPLEX_OUTPUT)
            dft_shift = np.fft.fftshift(dft)
            magnitude = cv2.magnitude(dft_shift[:,:,0], dft_shift[:,:,1])
            magnitude_spectrum = 20 * np.log(magnitude + 1)

            h, w = gray.shape
            center_h, center_w = h // 2, w // 2
            mask_size = min(h, w) // 8
            magnitude_spectrum[center_h-mask_size:center_h+mask_size, center_w-mask_size:center_w+mask_size] = 0

            if np.mean(magnitude_spectrum) > 150:
                high_freq_noise_count += 1

        if len(frames_to_check) > 0 and (high_freq_noise_count / len(frames_to_check) > 0.6):
            score += 1.0
            issues.append("Unusual high-frequency noise patterns detected")

        return score, issues

    def test_optimization_equivalence(self):
        print("\nVerifying optimization equivalence...")
        # Generate random frames (white noise)
        np.random.seed(42)
        frames = []
        for _ in range(5):
            frames.append(np.random.randint(0, 255, (256, 256), dtype=np.uint8))

        # Run original logic
        orig_score, orig_issues = self.original_check_compression_artifacts(frames)
        print(f"Original: score={orig_score}, issues={orig_issues}")

        # Run current optimized class logic and verify it matches the original fftshift-based approach
        opt_score, opt_issues = self.analyzer._check_compression_artifacts(frames)
        print(f"Current: score={opt_score}, issues={opt_issues}")

        self.assertEqual(orig_score, opt_score)
        self.assertEqual(orig_issues, opt_issues)

        # Test 2: Structured image (black image with white square)
        # This has specific frequency components
        frames2 = []
        for _ in range(5):
            img = np.zeros((256, 256), dtype=np.uint8)
            cv2.rectangle(img, (50, 50), (200, 200), 255, -1)
            frames2.append(img)

        orig_score2, orig_issues2 = self.original_check_compression_artifacts(frames2)
        print(f"Original (Structured): score={orig_score2}, issues={orig_issues2}")

        opt_score2, opt_issues2 = self.analyzer._check_compression_artifacts(frames2)
        print(f"Current (Structured): score={opt_score2}, issues={opt_issues2}")

        self.assertEqual(orig_score2, opt_score2)
        self.assertEqual(orig_issues2, opt_issues2)

if __name__ == '__main__':
    unittest.main()
