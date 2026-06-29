🎯 **What:**
The format method in `src/utils/structured_logging.py` was technically at 100% test coverage, but it missed explicit edge cases regarding empty messages and non-string keys in `extra_fields`.

📊 **Coverage:**
Two new test scenarios were added to `tests/test_structured_logging.py`:
- `test_empty_message_and_args`: Validates formatting when an empty message is logged without args, asserting that `"message"` is cleanly empty.
- `test_malformed_extra_fields`: Tests behavior when integers and `None` are used as keys in `extra_fields`, ensuring that dictionary keys are properly coerced to strings to prevent `KeyError`s.

✨ **Result:**
The `JSONFormatter.format` method is now more robust against malformed `extra_fields` (by updating a bug in the code where it assumed all keys had a `.lower()` method). Test suite covers these missing scenarios, bringing robustness to formatting.
