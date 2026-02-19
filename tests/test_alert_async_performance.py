"""
Test async alert dispatch performance optimization
"""

import unittest
import time
from unittest.mock import MagicMock, patch
from src.modules.alert_system import AlertSystem, ThreatReport
from src.utils.config import AlertConfig


class TestAsyncAlertPerformance(unittest.TestCase):
    """Test that alerts are dispatched asynchronously and don't block"""

    def setUp(self):
        self.config = MagicMock(spec=AlertConfig)
        self.config.console = False  # Disable console for clean testing
        self.config.webhook_enabled = True
        self.config.webhook_url = "https://webhook.example.com/alert"
        self.config.slack_enabled = True
        self.config.slack_webhook = "https://hooks.slack.com/services/test"
        self.config.threat_low = 10
        self.config.threat_medium = 50
        self.config.threat_high = 80

        self.alert_system = AlertSystem(self.config)

        self.sample_report = ThreatReport(
            email_id="test-123",
            subject="Test Email",
            sender="sender@example.com",
            recipient="recipient@example.com",
            date="2024-01-01",
            overall_threat_score=75.0,
            risk_level="medium",
            spam_analysis={},
            nlp_analysis={},
            media_analysis={},
            recommendations=["Review carefully"],
            timestamp="2024-01-01T12:00:00"
        )

    def tearDown(self):
        """Clean up resources"""
        if hasattr(self.alert_system, 'shutdown'):
            self.alert_system.shutdown()

    @patch('src.modules.alert_system.requests.post')
    def test_send_alert_returns_immediately(self, mock_post):
        """Test that send_alert returns quickly even with slow HTTP calls"""
        
        # Simulate slow webhook (5 seconds)
        def slow_post(*args, **kwargs):
            time.sleep(5)
            response = MagicMock()
            response.status_code = 200
            return response
        
        mock_post.side_effect = slow_post
        
        # send_alert should return immediately, not block for 10s (5s webhook + 5s slack)
        start_time = time.time()
        self.alert_system.send_alert(self.sample_report)
        elapsed = time.time() - start_time
        
        # Should return in <0.1s (not 10s for both HTTP calls)
        self.assertLess(elapsed, 0.5, 
                       f"send_alert blocked for {elapsed:.2f}s - should be non-blocking")
        
        # Verify alerts were queued (shutdown will wait for completion)
        self.alert_system.shutdown()
        
        # After shutdown, both alerts should have been sent
        self.assertEqual(mock_post.call_count, 2, 
                        "Both webhook and Slack alerts should be sent")

    @patch('src.modules.alert_system.requests.post')
    def test_parallel_alert_dispatch(self, mock_post):
        """Test that multiple alerts can be dispatched in parallel"""
        
        # Simulate slow HTTP calls
        def slow_post(*args, **kwargs):
            time.sleep(2)
            response = MagicMock()
            response.status_code = 200
            return response
        
        mock_post.side_effect = slow_post
        
        # Send 3 alerts
        start_time = time.time()
        for i in range(3):
            report = ThreatReport(
                email_id=f"test-{i}",
                subject=f"Test Email {i}",
                sender="sender@example.com",
                recipient="recipient@example.com",
                date="2024-01-01",
                overall_threat_score=75.0,
                risk_level="medium",
                spam_analysis={},
                nlp_analysis={},
                media_analysis={},
                recommendations=[],
                timestamp="2024-01-01T12:00:00"
            )
            self.alert_system.send_alert(report)
        
        # All sends should return immediately
        elapsed = time.time() - start_time
        self.assertLess(elapsed, 0.5, "Multiple sends should not block")
        
        # Wait for all alerts to complete
        self.alert_system.shutdown()
        
        # 3 emails × 2 channels = 6 HTTP calls
        self.assertEqual(mock_post.call_count, 6)

    @patch('src.modules.alert_system.requests.post')
    def test_error_handling_in_async_alerts(self, mock_post):
        """Test that errors in async alerts don't crash the system"""
        
        # Simulate webhook failure
        mock_post.side_effect = Exception("Network error")
        
        # Should not raise exception
        try:
            self.alert_system.send_alert(self.sample_report)
            self.alert_system.shutdown()
        except Exception as e:
            self.fail(f"Async alert error should not propagate: {e}")

    @patch('src.modules.alert_system.requests.post')
    def test_shutdown_waits_for_pending_alerts(self, mock_post):
        """Test that shutdown waits for in-flight alerts to complete"""
        
        call_times = []
        
        def track_post(*args, **kwargs):
            call_times.append(time.time())
            time.sleep(1)
            response = MagicMock()
            response.status_code = 200
            return response
        
        mock_post.side_effect = track_post
        
        # Send alert (should queue immediately)
        self.alert_system.send_alert(self.sample_report)
        
        # Shutdown should wait for completion
        start_shutdown = time.time()
        self.alert_system.shutdown()
        shutdown_duration = time.time() - start_shutdown
        
        # Shutdown should have waited for the 1s HTTP calls
        self.assertGreaterEqual(shutdown_duration, 1.0, 
                               "shutdown() should wait for pending alerts")
        
        # Both alerts should have completed
        self.assertEqual(mock_post.call_count, 2)

    def test_console_alerts_remain_synchronous(self):
        """Test that console alerts (no I/O) remain synchronous"""
        
        self.config.console = True
        self.config.webhook_enabled = False
        self.config.slack_enabled = False
        
        alert_system = AlertSystem(self.config)
        
        # Console alerts should execute synchronously
        with patch('builtins.print') as mock_print:
            alert_system.send_alert(self.sample_report)
            # Print should be called immediately (synchronous)
            self.assertTrue(mock_print.called)
        
        alert_system.shutdown()


if __name__ == '__main__':
    unittest.main()
