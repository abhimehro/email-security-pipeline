#!/usr/bin/env python3
"""
Benchmark for async alert dispatch performance improvement

Measures the time saved by making HTTP alert delivery non-blocking.
This demonstrates the performance impact documented in issue #250.
"""

import time
import sys
from unittest.mock import MagicMock, patch
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.modules.alert_system import AlertSystem, ThreatReport
from src.utils.config import AlertConfig


def create_test_config():
    """Create test configuration"""
    config = MagicMock(spec=AlertConfig)
    config.console = False
    config.webhook_enabled = True
    config.webhook_url = "https://webhook.example.com/alert"
    config.slack_enabled = True
    config.slack_webhook = "https://hooks.slack.com/services/test"
    config.threat_low = 10
    return config


def create_threat_report(email_id="test-123"):
    """Create sample threat report"""
    return ThreatReport(
        email_id=email_id,
        subject="Suspicious Email",
        sender="attacker@evil.com",
        recipient="victim@example.com",
        date="2024-01-01",
        overall_threat_score=85.0,
        risk_level="high",
        spam_analysis={"score": 75.0},
        nlp_analysis={"threat_score": 0.9},
        media_analysis={"threat_score": 20.0},
        recommendations=["Delete immediately", "Block sender"],
        timestamp="2024-01-01T12:00:00"
    )


@patch('src.modules.alert_system.requests.post')
def benchmark_async_alerts(mock_post, num_emails=10):
    """
    Benchmark alert dispatch with async optimization
    
    Simulates processing multiple emails with slow webhook/Slack endpoints.
    Measures how long it takes to dispatch all alerts.
    """
    
    # Simulate slow HTTP calls (3s webhook + 3s Slack = 6s per email without async)
    call_count = 0
    
    def slow_http_post(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        time.sleep(3)  # Simulate slow endpoint
        response = MagicMock()
        response.status_code = 200
        return response
    
    mock_post.side_effect = slow_http_post
    
    config = create_test_config()
    alert_system = AlertSystem(config)
    
    print(f"\n{'='*70}")
    print(f"Async Alert Dispatch Performance Benchmark")
    print(f"{'='*70}\n")
    
    print(f"Scenario: Processing {num_emails} high-threat emails")
    print(f"Each email triggers 2 HTTP alerts (webhook + Slack)")
    print(f"Each HTTP call takes 3 seconds (simulated slow endpoint)\n")
    
    # Baseline calculation (if synchronous)
    baseline_time = num_emails * 2 * 3  # emails × channels × 3s
    print(f"📊 Expected time (synchronous blocking):")
    print(f"   {num_emails} emails × 2 channels × 3s = {baseline_time}s\n")
    
    # Measure async dispatch
    print(f"⚡ Actual time (async non-blocking):")
    start_time = time.time()
    
    for i in range(num_emails):
        report = create_threat_report(f"test-{i}")
        alert_system.send_alert(report)
    
    dispatch_time = time.time() - start_time
    
    # Wait for all alerts to complete
    alert_system.shutdown()
    total_time = time.time() - start_time
    
    print(f"   Dispatch time: {dispatch_time:.3f}s (time to queue all alerts)")
    print(f"   Total time:    {total_time:.3f}s (including completion)\n")
    
    # Calculate improvement
    speedup = baseline_time / total_time if total_time > 0 else 0
    time_saved = baseline_time - total_time
    
    print(f"🎯 Performance Results:")
    print(f"   Speedup:      {speedup:.1f}x faster")
    print(f"   Time saved:   {time_saved:.1f}s ({time_saved/60:.1f} minutes)")
    print(f"   HTTP calls:   {call_count} (all completed)\n")
    
    print(f"💡 Impact Analysis:")
    if num_emails >= 100:
        scaled_saved = (time_saved / num_emails) * 100
        print(f"   For 100 emails/hour:  ~{scaled_saved/60:.1f} minutes saved per hour")
        print(f"   For 1000 emails/day:  ~{scaled_saved*10/60:.1f} minutes saved per day")
    else:
        print(f"   Pipeline no longer blocks on slow HTTP endpoints")
        print(f"   Can process next email immediately after analysis completes")
    
    print(f"\n{'='*70}\n")
    
    return {
        'dispatch_time': dispatch_time,
        'total_time': total_time,
        'baseline_time': baseline_time,
        'speedup': speedup,
        'time_saved': time_saved
    }


if __name__ == "__main__":
    # Run benchmark with different email counts
    print("\n" + "="*70)
    print("Running Alert Dispatch Performance Benchmarks")
    print("="*70)
    
    # Quick test with 5 emails
    results = benchmark_async_alerts(num_emails=5)
    
    # Verify the optimization works
    assert results['speedup'] > 2.0, f"Expected >2x speedup, got {results['speedup']:.1f}x"
    print(f"✅ Benchmark passed: {results['speedup']:.1f}x speedup achieved\n")
