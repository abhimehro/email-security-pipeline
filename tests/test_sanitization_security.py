
import pytest
from src.utils.sanitization import sanitize_for_logging

def test_sanitize_bidi_characters():
    """Test that BiDi control characters are removed to prevent log spoofing."""
    # Right-to-Left Override (U+202E)
    # This reverses the text display.
    # "User admin[RLO]nimda" -> "User adminadmin" (if rendered blindly)
    # Actually [RLO] flips direction. "User admin\u202Enimda" -> "User adminadmin" (displayed reversed)
    input_text = "User admin\u202Enimda"
    # We expect the \u202E to be removed
    expected = "User adminnimda"
    assert sanitize_for_logging(input_text) == expected

def test_sanitize_c1_controls():
    """Test that C1 control characters (0x80-0x9F) are removed."""
    # U+0090 is Device Control String
    input_text = "Data\u0090Loss"
    expected = "DataLoss"
    assert sanitize_for_logging(input_text) == expected

def test_sanitize_line_separators():
    """Test that unicode line separators are removed or replaced."""
    # U+2028 is Line Separator
    input_text = "Line1\u2028Line2"
    # Should be removed or replaced. Current logic (proposed) removes them.
    # Ideally it should be replaced by space or escaped, but removing is safer than allowing multiline.
    # Let's assume removal for now as they are "formatting" or "separator" that we want to flatten.
    expected = "Line1Line2"
    assert sanitize_for_logging(input_text) == expected

def test_sanitize_format_characters():
    """Test that other format characters like Zero Width Space are removed."""
    # U+200B Zero Width Space
    input_text = "Hid\u200Bden"
    expected = "Hidden"
    assert sanitize_for_logging(input_text) == expected
