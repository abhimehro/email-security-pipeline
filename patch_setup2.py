with open('src/utils/setup_wizard.py', 'r') as f:
    content = f.read()

import re

old_code = """    except (AttributeError, OSError, NotImplementedError):
        try:
            # Some platforms support os.chmod(fd, mode)
            os.chmod(fd, 0o600)
        except (AttributeError, OSError, NotImplementedError, TypeError):
            print(
                "\\n✖ "
                + Colors.colorize(
                    "CRITICAL: Platform does not support secure file descriptor permissions.", Colors.RED
                )
            )
            import sys
            sys.exit(1)"""

new_code = """    except (AttributeError, OSError, NotImplementedError) as e_primary:
        try:
            # Some platforms support os.chmod(fd, mode)
            os.chmod(fd, 0o600)
        except (AttributeError, NotImplementedError, TypeError):
            print(
                "\\n✖ "
                + Colors.colorize(
                    "CRITICAL: Platform does not support secure file descriptor permissions.", Colors.RED
                )
            )
            import sys
            sys.exit(1)
        except OSError as exc:
            print(
                "\\n✖ "
                + Colors.colorize(
                    "Error setting permissions: " + str(exc), Colors.RED
                )
            )
            import sys
            sys.exit(1)"""

content = content.replace(old_code, new_code)
with open('src/utils/setup_wizard.py', 'w') as f:
    f.write(content)
