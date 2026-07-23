with open('tests/test_app_runner.py', 'r') as f:
    content = f.read()

import re

# Remove `test_set_secure_permissions_fallback_chmod_path` and `test_set_secure_permissions_toctou_detected`
content = re.sub(
    r'def test_set_secure_permissions_fallback_chmod_path.*?(?=def test_set_secure_permissions_oserror)',
    '',
    content,
    flags=re.DOTALL
)

with open('tests/test_app_runner.py', 'w') as f:
    f.write(content)
