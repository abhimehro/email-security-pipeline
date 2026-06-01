1. **Fix path traversal vulnerability in `_inspect_tar_contents` and `_handle_nested_tar_member`.**
   - The method iterates through `tf.getmembers()` (via `for member in tf`) and checks `member.name`.
   - Before doing anything with `member`, we need to check if `member.name` is suspicious (e.g. `member.name.startswith("/")` or `".." in member.name`). If it is, we should log a warning, add to the `score` and `warnings`, and skip or return. 
   - We will also apply `tarfile.data_filter` to `tf.extraction_filter` if it exists.
   - We will use `run_in_bash_session` to perform the changes using a patch file or `sed`/`awk`.
2. **Run tests.**
   - We will execute `python3 -m pytest tests/test_media_tar_security.py` to ensure that tar security tests continue passing, and run the full test suite `python3 -m pytest`.
3. **Complete pre-commit steps to ensure proper testing, verification, review, and reflection are done.**
4. **Submit PR.**
   - I will construct a JSON payload with `title`, `body`, `head`, and `base` fields.
   - I will execute `curl -X POST .../pulls` with `$GH_TOKEN` to create the pull request.
   - I will clean up the JSON file.
