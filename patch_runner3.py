with open('src/app_runner.py', 'r') as f:
    content = f.read()

import re

old_code = """        # Fallback: chmod with file descriptor
        try:
            os.chmod(fd, SECURE_MODE)
            return
        except (AttributeError, TypeError, OSError):
            print(
                "✖ " + Colors.colorize("CRITICAL: Platform does not support secure file descriptor permissions.", Colors.RED)
            )
            self._print_fallback_instructions()
            sys.exit(1)"""

new_code = """        # Fallback: chmod with file descriptor
        try:
            os.chmod(fd, SECURE_MODE)
            return
        except (AttributeError, TypeError):
            print(
                "✖ " + Colors.colorize("CRITICAL: Platform does not support secure file descriptor permissions.", Colors.RED)
            )
            self._print_fallback_instructions()
            sys.exit(1)
        except OSError as e:
            print(
                "✖ " + Colors.colorize(f"CRITICAL: Failed to set secure permissions: {e}", Colors.RED)
            )
            self._print_fallback_instructions()
            sys.exit(1)"""

content = content.replace(old_code, new_code)
with open('src/app_runner.py', 'w') as f:
    f.write(content)
