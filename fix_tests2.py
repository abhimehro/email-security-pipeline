import re

with open("tests/test_email_parser_body_size.py", "r") as f:
    content = f.read()

# Add back TestAddBodyContent
test_add_body_content = """# ---------------------------------------------------------------------------
# TestAddBodyContent – direct tests for _add_body_content
# ---------------------------------------------------------------------------


class TestAddBodyContent(unittest.TestCase):
    \"\"\"
    Tests for EmailParser._add_body_content.

    The method signature is:
        _add_body_content(content_type, part_data, ctx)
            -> None  (mutates ctx.body_dict in place)

    Key contracts:
        content_type == 'text/html' → accumulates into html_parts / html_len
        anything else               → accumulates into text_parts / text_len
        current_len >= max_body_size → _append_body_part is NOT called
    \"\"\"

    def setUp(self):
        self.parser = _make_parser(max_body_size=_SMALL_MAX)

    def test_plain_text_routes_to_text_parts(self):
        \"\"\"content_type='text/plain' must update text_parts and text_len only.\"\"\"
        ctx = ParseContext(safe_email_id="id-1", body_dict=_make_body_dict(), attachments=[])
        self.parser._add_body_content("text/plain", "hello", ctx)
        body_dict = ctx.body_dict
        self.assertEqual(body_dict["text_parts"], ["hello"])
        self.assertEqual(body_dict["text_len"], 5)
        self.assertEqual(body_dict["html_parts"], [])
        self.assertEqual(body_dict["html_len"], 0)

    def test_html_routes_to_html_parts(self):
        \"\"\"content_type='text/html' must update html_parts and html_len only.\"\"\"
        ctx = ParseContext(safe_email_id="id-2", body_dict=_make_body_dict(), attachments=[])
        self.parser._add_body_content("text/html", "<b>hi</b>", ctx)
        body_dict = ctx.body_dict
        self.assertEqual(body_dict["html_parts"], ["<b>hi</b>"])
        self.assertEqual(body_dict["html_len"], 9)
        self.assertEqual(body_dict["text_parts"], [])
        self.assertEqual(body_dict["text_len"], 0)

    def test_at_or_over_max_body_size_skips_append(self):
        \"\"\"
        When current_len >= max_body_size, _append_body_part must NOT be called.

        This validates the early-exit guard that protects the size limit from
        being exceeded via repeated small appends after the limit is reached.
        \"\"\"
        ctx = ParseContext(safe_email_id="id-3", body_dict=_make_body_dict(), attachments=[])
        ctx.body_dict["text_len"] = _SMALL_MAX  # already at limit
        body_dict = ctx.body_dict

        with patch.object(self.parser, "_append_body_part") as mock_append:
            self.parser._add_body_content(
                "text/plain", "overflow data", ctx
            )
            mock_append.assert_not_called()

    def test_non_html_content_type_defaults_to_text_key(self):
        \"\"\"
        Any content_type other than 'text/html' must route to the text bucket.

        Ensures that unknown MIME subtypes (e.g. text/enriched, text/calendar)
        fall back to text rather than HTML.
        \"\"\"
        ctx = ParseContext(safe_email_id="id-4", body_dict=_make_body_dict(), attachments=[])
        self.parser._add_body_content(
            "text/calendar", "BEGIN:VCALENDAR", ctx
        )
        body_dict = ctx.body_dict
        self.assertGreater(body_dict["text_len"], 0)
        self.assertEqual(body_dict["html_len"], 0)


"""

content = content.replace(
    "# ---------------------------------------------------------------------------",
    test_add_body_content + "# ---------------------------------------------------------------------------"
)

# Fix missing patch import
content = content.replace("from unittest.mock import MagicMock", "from unittest.mock import MagicMock, patch")


with open("tests/test_email_parser_body_size.py", "w") as f:
    f.write(content)
