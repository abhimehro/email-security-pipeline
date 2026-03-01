"""
Metrics Collection Module
Tracks system performance and threat detection statistics
"""

from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Deque


@dataclass
class Metrics:
    """
    Collects operational metrics for monitoring system health.

    PATTERN RECOGNITION: This is similar to how web servers track request counts,
    response times, and error rates. Professional teams use this data to:
    - Set up alerting (e.g., "alert if threat detection drops to 0 for 1 hour")
    - Create dashboards showing trends over time
    - Identify performance bottlenecks (e.g., "media analysis is slow")
    - Capacity planning (e.g., "we process 1000 emails/day, need to scale")

    INDUSTRY CONTEXT: Professional teams handle this by sending metrics to
    systems like Prometheus, Datadog, or CloudWatch. This class provides the
    foundation for that integration - you can periodically export these metrics
    to your monitoring system of choice.
    """

    # Count of emails processed since startup
    emails_processed: int = 0

    # Count of threats detected by type
    # TEACHING MOMENT: Counter is like a dictionary that defaults to 0
    # So threats_detected['phishing'] += 1 works even if 'phishing' wasn't set
    threats_detected: Counter = field(default_factory=Counter)

    # Processing time for each email in milliseconds
    # MAINTENANCE WISDOM: We store individual times rather than just an average
    # because you can calculate average, median, p95, p99 from the raw data
    # but you can't go backwards from an average to individual times.
    # SECURITY STORY: We use a bounded deque (maxlen=1000) to prevent memory
    # leaks and CPU exhaustion (DoS) from sorting massive lists.
    processing_time_ms: Deque[float] = field(default_factory=lambda: deque(maxlen=1000))

    # Count of errors by type
    errors_count: Counter = field(default_factory=Counter)

    # When metrics collection started
    start_time: datetime = field(default_factory=datetime.now)

    def record_email_processed(self):
        """
        Record that an email was processed.

        Call this for every email, whether it was clean or threatening.
        """
        self.emails_processed += 1

    def record_threat(self, threat_type: str, severity: str = "unknown"):
        """
        Record that a threat was detected.

        Args:
            threat_type: Type of threat (e.g., "phishing", "spam", "malware")
            severity: Threat severity (e.g., "low", "medium", "high", "critical")

        Example:
            metrics.record_threat("phishing", "high")
        """
        # Track both the specific threat type and severity
        self.threats_detected[threat_type] += 1
        self.threats_detected[f"{threat_type}_{severity}"] += 1

    def record_processing_time(self, time_ms: float):
        """
        Record how long it took to process an email.

        Args:
            time_ms: Processing time in milliseconds

        TEACHING MOMENT: We use milliseconds instead of seconds because
        email processing should be fast (< 1 second typically). Using
        milliseconds gives us better precision for performance analysis.
        """
        self.processing_time_ms.append(time_ms)

    def record_error(self, error_type: str):
        """
        Record that an error occurred.

        Args:
            error_type: Type of error (e.g., "imap_connection", "analysis_timeout")
        """
        self.errors_count[error_type] += 1

    def get_summary(self) -> Dict:
        """
        Get a summary of all metrics.

        Returns:
            Dictionary containing metrics summary suitable for logging or export

        INDUSTRY CONTEXT: Professional teams export this summary to monitoring
        systems every 60 seconds. You can pipe this to a file, send it to an
        API endpoint, or display it in a dashboard.
        """
        # Calculate processing time statistics if we have data
        stats = {}
        if self.processing_time_ms:
            sorted_times = sorted(self.processing_time_ms)
            n = len(sorted_times)
            stats = {
                "avg_ms": sum(sorted_times) / n,
                "min_ms": sorted_times[0],
                "max_ms": sorted_times[-1],
                "p50_ms": sorted_times[n // 2],  # Median
                "p95_ms": sorted_times[int(n * 0.95)] if n > 1 else sorted_times[0],
                "p99_ms": sorted_times[int(n * 0.99)] if n > 1 else sorted_times[0],
            }

        return {
            "uptime_seconds": (datetime.now() - self.start_time).total_seconds(),
            "emails_processed": self.emails_processed,
            "threats_detected": dict(self.threats_detected),
            "processing_time_stats": stats,
            "errors": dict(self.errors_count),
            "sample_count": len(self.processing_time_ms),
        }

    def reset(self):
        """
        Reset all metrics to initial state.

        TEACHING MOMENT: Use this carefully! You typically only reset metrics
        when you're exporting them to a monitoring system and starting a new
        collection window. Don't reset if you want cumulative statistics since
        startup.
        """
        self.emails_processed = 0
        self.threats_detected.clear()
        self.processing_time_ms.clear()
        self.errors_count.clear()
        self.start_time = datetime.now()
