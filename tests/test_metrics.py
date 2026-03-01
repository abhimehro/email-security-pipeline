"""
Tests for metrics collection functionality
"""

import unittest
from datetime import datetime, timedelta
from pathlib import Path
import sys
import time

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.metrics import Metrics


class TestMetrics(unittest.TestCase):
    """Test cases for Metrics class"""

    def setUp(self):
        """Set up test fixtures"""
        self.metrics = Metrics()

    def test_initialization(self):
        """Test that metrics are initialized correctly"""
        self.assertEqual(self.metrics.emails_processed, 0)
        self.assertEqual(len(self.metrics.threats_detected), 0)
        self.assertEqual(len(self.metrics.processing_time_ms), 0)
        self.assertEqual(len(self.metrics.errors_count), 0)
        self.assertIsInstance(self.metrics.start_time, datetime)

    def test_record_email_processed(self):
        """Test recording processed emails"""
        self.metrics.record_email_processed()
        self.assertEqual(self.metrics.emails_processed, 1)

        self.metrics.record_email_processed()
        self.assertEqual(self.metrics.emails_processed, 2)

    def test_record_threat(self):
        """Test recording threats"""
        self.metrics.record_threat("phishing", "high")

        # Should record both the type and the type_severity combination
        self.assertEqual(self.metrics.threats_detected["phishing"], 1)
        self.assertEqual(self.metrics.threats_detected["phishing_high"], 1)

    def test_record_multiple_threats(self):
        """Test recording multiple threats of different types"""
        self.metrics.record_threat("phishing", "high")
        self.metrics.record_threat("phishing", "medium")
        self.metrics.record_threat("spam", "low")

        # Phishing should have 2 total
        self.assertEqual(self.metrics.threats_detected["phishing"], 2)
        self.assertEqual(self.metrics.threats_detected["phishing_high"], 1)
        self.assertEqual(self.metrics.threats_detected["phishing_medium"], 1)

        # Spam should have 1
        self.assertEqual(self.metrics.threats_detected["spam"], 1)
        self.assertEqual(self.metrics.threats_detected["spam_low"], 1)

    def test_record_processing_time(self):
        """Test recording processing times"""
        self.metrics.record_processing_time(100.5)
        self.metrics.record_processing_time(200.3)

        self.assertEqual(len(self.metrics.processing_time_ms), 2)
        self.assertEqual(self.metrics.processing_time_ms[0], 100.5)
        self.assertEqual(self.metrics.processing_time_ms[1], 200.3)

    def test_record_error(self):
        """Test recording errors"""
        self.metrics.record_error("imap_connection")
        self.metrics.record_error("imap_connection")
        self.metrics.record_error("analysis_timeout")

        self.assertEqual(self.metrics.errors_count["imap_connection"], 2)
        self.assertEqual(self.metrics.errors_count["analysis_timeout"], 1)

    def test_get_summary_empty(self):
        """Test getting summary with no data"""
        summary = self.metrics.get_summary()

        self.assertEqual(summary["emails_processed"], 0)
        self.assertEqual(summary["threats_detected"], {})
        self.assertEqual(summary["processing_time_stats"], {})
        self.assertEqual(summary["errors"], {})
        self.assertGreaterEqual(summary["uptime_seconds"], 0)
        self.assertEqual(summary["sample_count"], 0)

    def test_get_summary_with_data(self):
        """Test getting summary with data"""
        # Add some data
        self.metrics.record_email_processed()
        self.metrics.record_email_processed()
        self.metrics.record_threat("phishing", "high")
        self.metrics.record_processing_time(100.0)
        self.metrics.record_processing_time(200.0)
        self.metrics.record_processing_time(150.0)
        self.metrics.record_error("test_error")

        summary = self.metrics.get_summary()

        self.assertEqual(summary["emails_processed"], 2)
        self.assertEqual(summary["threats_detected"]["phishing"], 1)
        self.assertEqual(summary["errors"]["test_error"], 1)
        self.assertEqual(summary["sample_count"], 3)

        # Check processing time stats
        stats = summary["processing_time_stats"]
        self.assertEqual(stats["avg_ms"], 150.0)
        self.assertEqual(stats["min_ms"], 100.0)
        self.assertEqual(stats["max_ms"], 200.0)
        self.assertEqual(stats["p50_ms"], 150.0)

    def test_processing_time_percentiles(self):
        """Test that percentile calculations work correctly"""
        # Add 100 data points
        for i in range(100):
            self.metrics.record_processing_time(float(i))

        summary = self.metrics.get_summary()
        stats = summary["processing_time_stats"]

        # Check percentiles
        self.assertEqual(stats["min_ms"], 0.0)
        self.assertEqual(stats["max_ms"], 99.0)
        self.assertEqual(stats["avg_ms"], 49.5)
        self.assertAlmostEqual(stats["p95_ms"], 95.0, delta=1.0)
        self.assertAlmostEqual(stats["p99_ms"], 99.0, delta=1.0)

    def test_reset(self):
        """Test resetting metrics"""
        # Add some data
        self.metrics.record_email_processed()
        self.metrics.record_threat("phishing", "high")
        self.metrics.record_processing_time(100.0)
        self.metrics.record_error("test_error")

        # Record the start time before reset
        old_start_time = self.metrics.start_time

        # Small delay to ensure time difference
        time.sleep(0.01)

        # Reset
        self.metrics.reset()

        # Everything should be cleared
        self.assertEqual(self.metrics.emails_processed, 0)
        self.assertEqual(len(self.metrics.threats_detected), 0)
        self.assertEqual(len(self.metrics.processing_time_ms), 0)
        self.assertEqual(len(self.metrics.errors_count), 0)

        # Start time should be updated
        self.assertGreater(self.metrics.start_time, old_start_time)

    def test_uptime_calculation(self):
        """Test that uptime is calculated correctly"""
        # Set a known start time
        self.metrics.start_time = datetime.now() - timedelta(seconds=60)

        summary = self.metrics.get_summary()

        # Uptime should be approximately 60 seconds (with small tolerance)
        self.assertGreater(summary["uptime_seconds"], 59)
        self.assertLess(summary["uptime_seconds"], 61)

    def test_single_processing_time(self):
        """Test stats calculation with a single data point"""
        self.metrics.record_processing_time(123.5)

        summary = self.metrics.get_summary()
        stats = summary["processing_time_stats"]

        # All stats should be the same value
        self.assertEqual(stats["avg_ms"], 123.5)
        self.assertEqual(stats["min_ms"], 123.5)
        self.assertEqual(stats["max_ms"], 123.5)
        self.assertEqual(stats["p50_ms"], 123.5)
        self.assertEqual(stats["p95_ms"], 123.5)
        self.assertEqual(stats["p99_ms"], 123.5)

    def test_bounded_processing_time(self):
        """Test that processing time metrics are bounded to prevent memory leaks"""
        # Add 1500 data points (more than the limit of 1000)
        for i in range(1500):
            self.metrics.record_processing_time(float(i))

        # Should be capped at 1000
        self.assertEqual(len(self.metrics.processing_time_ms), 1000)

        # Should keep the most recent values
        # The values were 0..1499, so the last 1000 should be 500..1499
        # The oldest value in the deque (index 0) should be 500.0
        self.assertEqual(self.metrics.processing_time_ms[0], 500.0)
        # The newest value (index -1) should be 1499.0
        self.assertEqual(self.metrics.processing_time_ms[-1], 1499.0)


if __name__ == '__main__':
    unittest.main()
