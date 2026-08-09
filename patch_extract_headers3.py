import re

with open("src/modules/email_parser.py", "r") as f:
    content = f.read()

search = """        # ⚡ BOLT: Optimization - only decode when RFC 2047 encoding is present.
        # This provides a significant speedup for header parsing which is a hot path.
        for key, value in msg.items():
            key_lower = key.lower()

            # Optimization: Avoid function call and decoding overhead for plain text
            decoded_val = self._decode_header_value(value) if "=?" in value else value

            existing = headers.get(key_lower)
            if existing is not None:
                # Handle duplicate headers
                if type(existing) is list:
                    existing.append(decoded_val)
                else:
                    headers[key_lower] = [existing, decoded_val]
            else:
                headers[key_lower] = decoded_val"""

replace = """        # ⚡ BOLT: Optimization - only decode when RFC 2047 encoding is present.
        # This provides a significant speedup for header parsing which is a hot path.
        for key, value in msg.items():
            key_lower = key.lower()

            # Optimization: Avoid function call and decoding overhead for plain text
            decoded_val = value
            if "=?" in value:
                decoded_val = self._decode_header_value(value)

            existing = headers.get(key_lower)
            if existing is None:
                headers[key_lower] = decoded_val
            elif type(existing) is list:
                existing.append(decoded_val)
            else:
                headers[key_lower] = [existing, decoded_val]"""

new_content = content.replace(search, replace)
if new_content == content:
    print("Failed to replace extract headers logic")
else:
    with open("src/modules/email_parser.py", "w") as f:
        f.write(new_content)
    print("Flattened nested ifs in msg.items() successfully")
