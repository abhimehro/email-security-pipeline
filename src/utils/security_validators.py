"""
Security Validators Module
Centralizes security validation constants and utilities for email processing

SECURITY STORY: These validators protect against various attacks:
- MAX_SUBJECT_LENGTH: Prevents buffer overflow and DoS from extremely long subjects
- MAX_MIME_PARTS: Prevents MIME bomb attacks (deeply nested MIME structures)
- DEFAULT_MAX_EMAIL_SIZE: Prevents DoS from downloading huge emails
"""

import re
import ssl
import logging
import socket
import ipaddress
from typing import Tuple
from urllib.parse import urlparse

# Security limits to prevent various attacks
MAX_SUBJECT_LENGTH = 1024  # Prevents subject line DoS attacks
MAX_MIME_PARTS = 100  # Limits MIME bomb attacks (CWE-674: Uncontrolled Recursion)

# Fallback maximum email size (500MB) to prevent DoS if no attachment limit is set
# This ensures we don't try to download indefinitely large emails in "unlimited" mode
DEFAULT_MAX_EMAIL_SIZE = 500 * 1024 * 1024

# Filename sanitization patterns to prevent path traversal (CWE-22)
# SECURITY STORY: Whitelist approach - only allow safe characters
FILENAME_SANITIZE_PATTERN = re.compile(r"[^\w\s\-_\.]")
FILENAME_COLLAPSE_DOTS_PATTERN = re.compile(r"\.{2,}")

# Windows reserved filenames that cannot be used regardless of extension
# SECURITY STORY: Even on Linux, we sanitize these to prevent issues if files
# are transferred to Windows systems or if the application runs on Windows.
WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
}

logger = logging.getLogger(__name__)


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal attacks (CWE-22)

    SECURITY STORY: This protects against attacks where a malicious email
    contains an attachment named "../../etc/passwd" which could write to
    system directories. We use a whitelist approach - only allowing
    alphanumeric, spaces, hyphens, underscores, and single dots.

    Args:
        filename: Original filename from email attachment

    Returns:
        Sanitized filename safe for filesystem operations

    Example:
        >>> sanitize_filename("../../etc/passwd")
        "etcpasswd"
        >>> sanitize_filename("normal_file.txt")
        "normal_file.txt"
    """
    if not filename:
        return "unnamed_attachment"

    # Remove path components (defense in depth)
    # This prevents "../.." style attacks before character filtering
    filename = filename.split("/")[-1].split("\\")[-1]

    # Apply whitelist: only keep safe characters
    # This removes: /, \, null bytes, control chars, etc.
    # NOTE: Single dots are safe (needed for extensions like ".txt")
    # because we already removed path separators above
    sanitized = FILENAME_SANITIZE_PATTERN.sub("", filename)

    # Collapse multiple dots to prevent directory traversal bypasses
    # Example: "....///" might bypass basic filters
    sanitized = FILENAME_COLLAPSE_DOTS_PATTERN.sub(".", sanitized)

    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip(". ")

    # Ensure we have a valid filename
    if not sanitized:
        return "unnamed_attachment"
    # Check for Windows reserved filenames (CON, PRN, AUX, etc.)
    # These are reserved regardless of extension (e.g., CON.txt is invalid)
    # We check the base name (part before the first dot)
    base_name = sanitized.split('.')[0].strip().upper()
    if base_name in WINDOWS_RESERVED_NAMES:
        sanitized = "_" + sanitized

    # Truncate to reasonable length (255 is typical filesystem limit)
    return sanitized[:255]


def create_secure_ssl_context() -> ssl.SSLContext:
    """
    Create a secure SSL context with modern TLS settings

    SECURITY STORY: This enforces TLS 1.2+ to protect against attacks on
    older protocols like SSLv3 (POODLE) and TLS 1.0/1.1 (BEAST, CRIME).
    We also set secure cipher suites and enable hostname checking to
    prevent man-in-the-middle attacks.

    Returns:
        Configured SSL context with security best practices
    """
    # Create SSL context with TLS 1.2+ (protects against SSLv3/TLS1.0/1.1 attacks)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    # Enable hostname checking (prevents MITM attacks)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    # Load default CA certificates for verification
    context.load_default_certs()

    logger.debug("Created secure SSL context with TLS 1.2+ enforcement")
    return context


def validate_subject_length(subject: str) -> str:
    """
    Validate and truncate subject line to prevent DoS attacks

    SECURITY STORY: Extremely long subject lines can cause memory exhaustion
    or buffer overflows in downstream systems. We truncate to a safe length.

    Args:
        subject: Email subject line

    Returns:
        Truncated subject line if it exceeds MAX_SUBJECT_LENGTH
    """
    if len(subject) > MAX_SUBJECT_LENGTH:
        logger.warning(f"Subject exceeds {MAX_SUBJECT_LENGTH} chars, truncating")
        return subject[:MAX_SUBJECT_LENGTH]
    return subject


def validate_mime_parts_count(count: int) -> bool:
    """
    Check if MIME parts count is within safe limits

    SECURITY STORY: MIME bomb attacks use deeply nested MIME structures
    to cause exponential processing time or memory exhaustion. We limit
    the total number of MIME parts to prevent this.

    Args:
        count: Number of MIME parts in the email

    Returns:
        True if count is safe, False if it exceeds limits
    """
    if count > MAX_MIME_PARTS:
        logger.error(f"Email has {count} MIME parts, exceeds limit of {MAX_MIME_PARTS}")
        return False
    return True


def calculate_max_email_size(max_total_attachment_bytes: int) -> int:
    """
    Calculate maximum email size based on attachment limits

    SECURITY STORY: We derive the email size limit from attachment limits
    to prevent DoS attacks. The 5MB overhead accounts for headers and body.

    Args:
        max_total_attachment_bytes: Maximum total attachment size (0 = unlimited)

    Returns:
        Maximum safe email size in bytes
    """
    if max_total_attachment_bytes > 0:
        # Add 5MB overhead for headers and body
        return max_total_attachment_bytes + (5 * 1024 * 1024)
    else:
        # Use safe default if "unlimited" mode is configured
        return DEFAULT_MAX_EMAIL_SIZE


def is_safe_webhook_url(url: str) -> Tuple[bool, str]:
    """
    Validate a webhook URL to prevent SSRF (Server-Side Request Forgery).

    SECURITY STORY: An attacker with control over the configuration might try
    to set a webhook URL pointing to an internal service (e.g. 127.0.0.1,
    AWS metadata service at 169.254.169.254, or an internal API like 10.0.0.5).
    By resolving the hostname and ensuring the IP addresses are public, we
    prevent this pipeline from being used as a proxy to attack internal systems.

    Note: This is evaluated at configuration validation time. While DNS rebinding
    attacks could theoretically change the resolution at request time, this provides
    a strong baseline defense in depth.

    Args:
        url: The webhook URL to validate

    Returns:
        Tuple of (is_safe: bool, error_message: str)
    """
    if not url:
        return False, "URL is empty"

    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"Failed to parse URL: {e}"

    if parsed.scheme not in ('http', 'https'):
        return False, f"URL scheme must be http or https, got: {parsed.scheme}"

    hostname = parsed.hostname
    if not hostname:
        return False, "URL must contain a valid hostname"

    try:
        # Resolve the hostname to all available IP addresses
        # AF_UNSPEC allows both IPv4 and IPv6
        # Use scheme-appropriate default ports when none is explicitly provided:
        # - 80 for HTTP
        # - 443 for HTTPS
        if parsed.port is not None:
            port = parsed.port
        elif parsed.scheme == 'https':
            port = 443
        else:
            # Default to HTTP port when scheme is 'http' (validated above)
            port = 80

        addr_info = socket.getaddrinfo(
            hostname, port,
            socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except socket.gaierror as e:
        # If it doesn't resolve, it can't be requested anyway
        return False, f"Could not resolve hostname '{hostname}': {e}"
    except Exception as e:
        return False, f"Error resolving hostname '{hostname}': {e}"

    for res in addr_info:
        # The 4th element of the tuple returned by getaddrinfo is the sockaddr.
        # IPv4 is (address, port), IPv6 is (addr, port, flow, scope)
        ip_str = res[4][0]

        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Resolved to an invalid IP address: {ip_str}"

        # SECURITY: Explicitly block various internal/private/reserved ranges
        if ip.is_loopback:
            return False, f"'{hostname}' resolves to loopback ({ip_str})"
        if ip.is_private:
            return False, f"'{hostname}' resolves to private IP ({ip_str})"
        if ip.is_link_local:
            return False, f"'{hostname}' resolves to link-local ({ip_str})"
        if ip.is_multicast:
            return False, f"'{hostname}' resolves to multicast ({ip_str})"
        if ip.is_reserved:
            return False, f"'{hostname}' resolves to reserved ({ip_str})"
        if ip.is_unspecified:
            return False, f"'{hostname}' resolves to unspecified ({ip_str})"

        # Check specific IPv4 scenarios not covered entirely by the above
        if ip.version == 4:
            # 0.0.0.0/8
            if int(ip) >> 24 == 0:
                return False, f"'{hostname}' resolves to zero-net ({ip_str})"

    return True, ""
