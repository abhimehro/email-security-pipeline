"""
Email Parser Module
Handles parsing of raw email bytes into structured EmailData objects

PATTERN RECOGNITION: This follows the Parser pattern - it takes unstructured 
data (raw email bytes) and transforms it into a structured object (EmailData).

SECURITY STORY: Email parsing is security-critical because emails can contain:
- Malicious headers with injection attacks
- MIME bombs (deeply nested structures)
- Path traversal in attachment filenames
- Oversized attachments or bodies to cause DoS

This module enforces limits and sanitization at every step.
"""

import email
import logging
from typing import Dict, List, Optional, Union, Any, Tuple
from email.message import Message
from email.header import decode_header, make_header
from email.utils import getaddresses, parsedate_to_datetime
from datetime import datetime

from .email_data import EmailData
from ..utils.config import EmailAccountConfig
from ..utils.sanitization import sanitize_for_logging
from ..utils.security_validators import (
    MAX_SUBJECT_LENGTH,
    MAX_MIME_PARTS,
    sanitize_filename,
    validate_subject_length
)


logger = logging.getLogger(__name__)


class EmailParser:
    """
    Parses raw email bytes into structured EmailData objects
    
    MAINTENANCE WISDOM: Keep parsing logic separate from I/O (IMAP connection).
    This makes it easier to test - you can parse test emails without needing
    an IMAP server.
    """
    
    def __init__(
        self,
        config: EmailAccountConfig,
        max_body_size: int = 1024 * 1024,  # 1MB default
        max_attachment_bytes: int = 25 * 1024 * 1024,  # 25MB default
        max_total_attachment_bytes: int = 100 * 1024 * 1024,  # 100MB default
        max_attachment_count: int = 10
    ):
        """
        Initialize email parser
        
        Args:
            config: Email account configuration (for account_email field)
            max_body_size: Maximum size for body text/HTML
            max_attachment_bytes: Maximum bytes per attachment
            max_total_attachment_bytes: Maximum total attachment size per email
            max_attachment_count: Maximum number of attachments per email
        """
        self.config = config
        self.max_body_size = max_body_size
        self.max_attachment_bytes = max_attachment_bytes
        self.max_total_attachment_bytes = max_total_attachment_bytes
        self.max_attachment_count = max_attachment_count
        self.logger = logging.getLogger(f"EmailParser.{config.provider}")
    
    def parse_email(self, email_id: str, raw_email: bytes, folder: str) -> Optional[EmailData]:
        """
        Parse raw email into EmailData object
        
        SECURITY STORY: This is the security boundary - untrusted email bytes
        come in, and we validate/sanitize everything before creating EmailData.
        
        Args:
            email_id: Email identifier (sequence number from IMAP)
            raw_email: Raw email bytes from IMAP server
            folder: Source folder name
            
        Returns:
            EmailData object if parsing succeeds, None if it fails
        """
        try:
            msg = email.message_from_bytes(raw_email)
            
            # Extract and validate headers
            headers = self._extract_headers(msg)
            
            # Extract and validate metadata
            subject = self._extract_subject(msg, email_id)
            sender = self._format_addresses(msg.get("From", ""))
            recipient = self._format_addresses(msg.get("To", ""))
            date = self._extract_date(msg)
            
            # Extract body and attachments
            body_text, body_html, attachments = self._extract_content(msg, email_id)
            
            return EmailData(
                message_id=msg.get("Message-ID", email_id),
                subject=subject,
                sender=sender,
                recipient=recipient,
                date=date,
                body_text=body_text,
                body_html=body_html,
                headers=headers,
                attachments=attachments,
                raw_email=msg,
                account_email=self.config.email,
                folder=folder
            )
            
        except Exception as e:
            safe_email_id = sanitize_for_logging(email_id)
            self.logger.error(f"Error parsing email {safe_email_id}: {e}")
            return None
    
    def _extract_headers(self, msg: Message) -> Dict[str, Union[str, List[str]]]:
        """
        Extract all headers from email, supporting duplicates
        
        SECURITY STORY: Keys are normalized to lowercase to prevent 
        case-sensitivity bypasses (e.g., "X-Spam" vs "x-spam").
        Duplicate headers (like "Received") are stored as lists.
        
        Args:
            msg: Email message object
            
        Returns:
            Dictionary of headers (lowercase keys)
        """
        headers: Dict[str, Union[str, List[str]]] = {}
        
        for key, value in msg.items():
            key_lower = key.lower()
            decoded_val = self._decode_header_value(value)
            
            if key_lower in headers:
                # Handle duplicate headers
                existing = headers[key_lower]
                if isinstance(existing, list):
                    existing.append(decoded_val)
                else:
                    headers[key_lower] = [existing, decoded_val]
            else:
                headers[key_lower] = decoded_val
        
        return headers
    
    def _extract_subject(self, msg: Message, email_id: str) -> str:
        """
        Extract and validate subject line
        
        SECURITY STORY: Truncate extremely long subjects to prevent DoS.
        """
        subject = self._decode_header_value(msg.get("Subject", ""))
        
        if len(subject) > MAX_SUBJECT_LENGTH:
            subject = subject[:MAX_SUBJECT_LENGTH]
            safe_id = sanitize_for_logging(email_id)
            self.logger.warning(
                f"Subject truncated to {MAX_SUBJECT_LENGTH} chars for email {safe_id}"
            )
        
        return subject
    
    def _extract_date(self, msg: Message) -> datetime:
        """
        Extract date from email, with fallback to current time
        
        Args:
            msg: Email message object
            
        Returns:
            Parsed datetime or current time if parsing fails
        """
        date_str = msg.get("Date", "")
        try:
            return parsedate_to_datetime(date_str)
        except Exception:
            return datetime.now()
    
    def _extract_content(
        self, 
        msg: Message, 
        email_id: str
    ) -> Tuple[str, str, List[Dict[str, Any]]]:
        """
        Extract body text, HTML, and attachments from email
        
        SECURITY STORY: This is where we enforce limits on:
        - Number of MIME parts (prevent MIME bombs)
        - Body size (prevent memory exhaustion)
        - Attachment count and size (prevent DoS)
        - Filename sanitization (prevent path traversal)
        
        Args:
            msg: Email message object
            email_id: Email identifier for logging
            
        Returns:
            Tuple of (body_text, body_html, attachments)
        """
        safe_email_id = sanitize_for_logging(email_id)
        
        if msg.is_multipart():
            return self._extract_multipart_content(msg, safe_email_id)
        else:
            return self._extract_singlepart_content(msg, safe_email_id)
    
    def _extract_multipart_content(
        self, 
        msg: Message, 
        safe_email_id: str
    ) -> Tuple[str, str, List[Dict[str, Any]]]:
        """
        Extract content from multipart email
        
        SECURITY STORY: We use list accumulation instead of string concatenation
        to avoid O(N^2) performance (which could be a DoS vector).
        """
        # Use lists for efficient accumulation
        body_text_parts = []
        body_html_parts = []
        body_text_len = 0
        body_html_len = 0
        
        attachments = []
        current_total_size = 0
        
        part_count = 0
        for part in msg.walk():
            part_count += 1
            
            # SECURITY: Prevent MIME bomb attacks
            if part_count > MAX_MIME_PARTS:
                self.logger.warning(
                    f"Email {safe_email_id} exceeds max MIME parts ({MAX_MIME_PARTS}). "
                    f"Truncating remaining parts."
                )
                break
            
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            
            # Extract text body
            if content_type == "text/plain" and "attachment" not in content_disposition:
                if body_text_len < self.max_body_size:
                    text_part = self._decode_part_payload(part)
                    body_text_parts, body_text_len = self._append_body_part(
                        body_text_parts, body_text_len, text_part,
                        "Body text", safe_email_id
                    )
            
            # Extract HTML body
            elif content_type == "text/html" and "attachment" not in content_disposition:
                if body_html_len < self.max_body_size:
                    html_part = self._decode_part_payload(part)
                    body_html_parts, body_html_len = self._append_body_part(
                        body_html_parts, body_html_len, html_part,
                        "Body HTML", safe_email_id
                    )
            
            # Extract attachments
            elif "attachment" in content_disposition:
                attachment = self._extract_attachment(
                    part, attachments, current_total_size, safe_email_id
                )
                if attachment:
                    attachments.append(attachment)
                    current_total_size += attachment["size"]
        
        # Join accumulated parts
        body_text = "".join(body_text_parts)
        body_html = "".join(body_html_parts)
        
        return body_text, body_html, attachments
    
    def _extract_singlepart_content(
        self, 
        msg: Message, 
        safe_email_id: str
    ) -> Tuple[str, str, List[Dict[str, Any]]]:
        """
        Extract content from single-part email
        """
        body_text = ""
        body_html = ""
        
        content_type = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                decoded = self._decode_bytes(payload, msg.get_content_charset())
                
                if content_type == "text/html":
                    if len(decoded) > self.max_body_size:
                        decoded = decoded[:self.max_body_size]
                        self.logger.warning(
                            f"Body HTML truncated to {self.max_body_size} bytes "
                            f"for email {safe_email_id}"
                        )
                    body_html = decoded
                else:
                    if len(decoded) > self.max_body_size:
                        decoded = decoded[:self.max_body_size]
                        self.logger.warning(
                            f"Body text truncated to {self.max_body_size} bytes "
                            f"for email {safe_email_id}"
                        )
                    body_text = decoded
        except Exception:
            pass
        
        return body_text, body_html, []
    
    def _append_body_part(
        self,
        parts: List[str],
        current_len: int,
        new_part: str,
        body_type: str,
        safe_email_id: str
    ) -> Tuple[List[str], int]:
        """
        Append body part with size checking and truncation
        
        Args:
            parts: List of body parts accumulated so far
            current_len: Current total length
            new_part: New part to append
            body_type: "Body text" or "Body HTML" for logging
            safe_email_id: Sanitized email ID for logging
            
        Returns:
            Tuple of (updated_parts, updated_len)
        """
        remaining = self.max_body_size - current_len
        
        if len(new_part) > remaining:
            # Truncate to fit
            new_part = new_part[:remaining]
            parts.append(new_part)
            new_len = current_len + len(new_part)
            self.logger.warning(
                f"{body_type} truncated to {self.max_body_size} bytes "
                f"for email {safe_email_id}"
            )
            return parts, new_len
        else:
            parts.append(new_part)
            return parts, current_len + len(new_part)
    
    def _extract_attachment(
        self,
        part: Message,
        attachments: List[Dict[str, Any]],
        current_total_size: int,
        safe_email_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Extract attachment from MIME part with security checks
        
        SECURITY STORY: We enforce three limits:
        1. Maximum attachment count (prevent resource exhaustion)
        2. Maximum per-attachment size (prevent memory exhaustion)
        3. Maximum total attachment size per email (prevent DoS)
        
        Returns:
            Attachment dict if valid, None if rejected
        """
        # Check attachment count limit
        if len(attachments) >= self.max_attachment_count:
            self.logger.warning(
                f"Max attachment count ({self.max_attachment_count}) reached "
                f"for email {safe_email_id}. Skipping remaining attachments."
            )
            return None
        
        # Get and sanitize filename
        raw_filename = self._decode_header_value(part.get_filename() or "")
        if not raw_filename:
            return None
        
        filename = sanitize_filename(raw_filename)
        safe_filename = sanitize_for_logging(filename)
        
        # Get attachment data
        payload = part.get_payload(decode=True) or b""
        original_size = len(payload)
        
        # Check total size limit
        if self.max_total_attachment_bytes > 0:
            if (current_total_size + original_size) > self.max_total_attachment_bytes:
                self.logger.warning(
                    f"Max total attachment size ({self.max_total_attachment_bytes}) "
                    f"exceeded for email {safe_email_id}. Skipping attachment {safe_filename}."
                )
                return None
        
        # Check and truncate individual attachment size
        truncated = False
        if self.max_attachment_bytes > 0 and original_size > self.max_attachment_bytes:
            self.logger.warning(
                "Attachment %s exceeds max size (%d bytes); truncating for analysis",
                safe_filename,
                original_size,
            )
            payload = payload[:self.max_attachment_bytes]
            truncated = True
        
        return {
            "filename": filename,
            "content_type": part.get_content_type(),
            "size": original_size,
            "data": payload,
            "truncated": truncated,
        }
    
    @staticmethod
    def _decode_header_value(value: str) -> str:
        """
        Decode RFC 2047 encoded header value
        
        SECURITY STORY: Email headers can use various encodings (quoted-printable,
        base64, etc.). We decode them safely, with fallback to original value.
        
        Args:
            value: Raw header value
            
        Returns:
            Decoded string
        """
        if not value:
            return ""
        try:
            return str(make_header(decode_header(value)))
        except Exception:
            return value
    
    @classmethod
    def _format_addresses(cls, header_value: str) -> str:
        """
        Parse and format email addresses from header
        
        Args:
            header_value: Raw address header (From, To, Cc, etc.)
            
        Returns:
            Formatted address string
            
        Example:
            >>> _format_addresses('"John Doe" <john@example.com>')
            'John Doe <john@example.com>'
        """
        if not header_value:
            return ""
        
        formatted = []
        for name, address in getaddresses([header_value]):
            name_clean = cls._decode_header_value(name)
            if name_clean and address:
                formatted.append(f"{name_clean} <{address}>")
            elif address:
                formatted.append(address)
            elif name_clean:
                formatted.append(name_clean)
        
        return ", ".join(formatted)
    
    @staticmethod
    def _decode_part_payload(part: Message) -> str:
        """
        Decode MIME part payload to string
        
        Args:
            part: MIME part
            
        Returns:
            Decoded string content
        """
        payload = part.get_payload(decode=True)
        if not payload:
            return ""
        return EmailParser._decode_bytes(payload, part.get_content_charset())
    
    @staticmethod
    def _decode_bytes(data: bytes, charset: Optional[str]) -> str:
        """
        Decode bytes to string with charset fallback
        
        SECURITY STORY: We use 'replace' error handling instead of 'strict'
        to prevent parsing failures from malformed input. This ensures we
        can still process emails with encoding issues.
        
        Args:
            data: Bytes to decode
            charset: Charset name (can be None or invalid)
            
        Returns:
            Decoded string
        """
        encoding = charset or "utf-8"
        try:
            return data.decode(encoding, errors="replace")
        except LookupError:
            # Unknown charset, fallback to UTF-8
            return data.decode("utf-8", errors="replace")
