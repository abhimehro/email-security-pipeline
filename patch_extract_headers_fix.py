import re

with open("src/modules/email_parser.py", "r") as f:
    content = f.read()

search = """    def _extract_headers(self, msg: Message) -> Dict[str, Union[str, List[str]]]:
        \"\"\"
        Extract all headers from email, supporting duplicates.

        SECURITY STORY: Keys are normalized to lowercase to prevent
        case-sensitivity bypasses (e.g., "X-Spam" vs "x-spam").
        Duplicate headers (like "Received") are stored as lists.

        Args:
            msg: Email message object

        Returns:
            Dictionary of headers (lowercase keys)

        \"\"\"
        headers: Dict[str, Union[str, List[str]]] = {}

        for key, value in msg.items():
            key_lower = key.lower()
            decoded_val = self._decode_header_value(value) if "=?" in value else value

            existing = headers.get(key_lower)
            if existing is not None:
                # Handle duplicate headers
                if type(existing) is list:
                    existing.append(decoded_val)
                else:
                    headers[key_lower] = [existing, decoded_val]
            else:
                headers[key_lower] = decoded_val

        return headers"""

replace = """    def _extract_headers(self, msg: Message) -> Dict[str, Union[str, List[str]]]:
        \"\"\"
        Extract all headers from email, supporting duplicates.

        SECURITY STORY: Keys are normalized to lowercase to prevent
        case-sensitivity bypasses (e.g., "X-Spam" vs "x-spam").
        Duplicate headers (like "Received") are stored as lists.

        Args:
            msg: Email message object

        Returns:
            Dictionary of headers (lowercase keys)

        \"\"\"
        headers: Dict[str, Union[str, List[str]]] = {}

        for key, value in msg.items():
            key_lower = key.lower()
            decoded_val = self._decode_header_value(value) if "=?" in value else value
            self._insert_header(headers, key_lower, decoded_val)
        return headers

    def _insert_header(
        self, headers: Dict[str, Union[str, List[str]]], key: str, value: str
    ) -> None:
        existing = headers.get(key)
        if existing is not None:
            if type(existing) is list:
                existing.append(value)
            else:
                headers[key] = [existing, value]
        else:
            headers[key] = value"""

new_content = content.replace(search, replace)
if new_content == content:
    print("Failed to replace extract headers logic")
else:
    with open("src/modules/email_parser.py", "w") as f:
        f.write(new_content)
    print("Fixed extract headers successfully")
