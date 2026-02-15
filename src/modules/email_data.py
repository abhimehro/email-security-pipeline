"""
Email Data Model
Contains the EmailData dataclass for storing parsed email information
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Union
from email.message import Message


@dataclass
class EmailData:
    """
    Container for parsed email data
    
    This dataclass holds all relevant information extracted from an email,
    including metadata, content, and attachments.
    """
    message_id: str
    subject: str
    sender: str
    recipient: str
    date: datetime
    body_text: str
    body_html: str
    headers: Dict[str, Union[str, List[str]]]
    attachments: List[Dict[str, Any]]
    raw_email: Message
    account_email: str
    folder: str
