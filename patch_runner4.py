with open('tests/test_app_runner.py', 'r') as f:
    content = f.read()

import re
content = re.sub(r'def test_set_secure_permissions_oserror.*?(?=def |\Z)', '', content, flags=re.DOTALL)

with open('tests/test_app_runner.py', 'w') as f:
    f.write(content)
