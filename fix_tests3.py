import re

with open("tests/test_email_parser_body_size.py", "r") as f:
    content = f.read()

# It seems there are multiple definitions of the classes. Let's just keep the last one.
# Re-read and strip everything and construct from scratch from origin/main to be safe.
