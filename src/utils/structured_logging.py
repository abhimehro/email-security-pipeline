"""
Structured Logging Module
Provides JSON-formatted logging for better integration with log aggregation tools
"""

import json
import logging
from typing import Any, Dict


class JSONFormatter(logging.Formatter):
    """
    Custom formatter that outputs log records as JSON.
    
    This is similar to using ELK (Elasticsearch, Logstash, Kibana) formatters
    but implements a simple version without external dependencies.
    
    SECURITY STORY: Structured logs help detect attack patterns by making
    it easy to query for specific events. For example, you can quickly find
    all "failed login" attempts or "high threat" emails across thousands of
    log entries using tools like jq, Splunk, or CloudWatch Logs Insights.
    
    PATTERN RECOGNITION: This is similar to how web servers use JSON access logs
    (nginx with json_log format) because structured data is easier to analyze
    than parsing free-form text with regex.
    """

    # Fields that might contain sensitive data - never log their full values
    SENSITIVE_FIELDS = {
        'password', 'token', 'api_key', 'secret', 'credential',
        'app_password', 'webhook_url', 'slack_webhook'
    }

    def format(self, record: logging.LogRecord) -> str:
        """
        Format a log record as JSON.
        
        Args:
            record: Python logging.LogRecord to format
            
        Returns:
            JSON string with structured log data
        """
        # Base log data that's always included
        log_data = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Include exception info if present
        # MAINTENANCE WISDOM: Future you will thank present you for including
        # the full traceback in structured logs - it makes debugging production
        # issues 10x faster when you can search for specific error types
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Include any extra fields added via logger.info("msg", extra={"key": "value"})
        # This allows adding context like email_id, threat_score, etc.
        if hasattr(record, "extra_fields"):
            # Security: Filter sensitive fields before logging
            filtered_extra = {
                k: self._sanitize_value(k, v)
                for k, v in record.extra_fields.items()
            }
            log_data.update(filtered_extra)

        return json.dumps(log_data, default=str)

    def _sanitize_value(self, key: str, value: Any) -> Any:
        """
        Sanitize potentially sensitive values before logging.
        
        SECURITY STORY: This protects against the attack where credentials
        accidentally get logged (e.g., someone adds extra_fields={'password': pwd}).
        Instead of logging the actual password, we log "[REDACTED]" which still
        tells you a password field was present without exposing the value.
        
        Args:
            key: Field name
            value: Field value
            
        Returns:
            Original value or "[REDACTED]" for sensitive fields
        """
        # Check if key contains any sensitive field name
        key_lower = key.lower()
        if any(sensitive in key_lower for sensitive in self.SENSITIVE_FIELDS):
            return "[REDACTED]"
        return value
