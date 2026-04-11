from src.utils.sanitization import sanitize_for_logging

# A string containing \n and an unprintable \x00 character
text = "Hello\nWorld\x00"

print(repr(sanitize_for_logging(text)))
