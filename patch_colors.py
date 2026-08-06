with open('src/utils/colors.py', 'r') as f:
    content = f.read()

target = '''    @staticmethod
    def get_risk_symbol(risk_level: str) -> str:
        """Get emoji symbol for a risk level."""
        # Emojis are Unicode characters, not ANSI codes, so they are generally safe
        # unless specifically requested to be ASCII-only.
        # However, some non-TTY environments (like simple log files) might not handle emojis well.
        # For now, we keep emojis as they add significant value even in some non-color terminals.
        level = risk_level.lower()
        symbols = {
            "high": "🔴",
            "medium": "🟡",
            "low": "🟢",
        }
        return symbols.get(level, "⚪")'''
replacement = '''    _SYMBOLS = {
        "high": "🔴",
        "medium": "🟡",
        "low": "🟢",
    }

    @classmethod
    def get_risk_symbol(cls, risk_level: str) -> str:
        """Get emoji symbol for a risk level."""
        # Emojis are Unicode characters, not ANSI codes, so they are generally safe
        # unless specifically requested to be ASCII-only.
        # However, some non-TTY environments (like simple log files) might not handle emojis well.
        # For now, we keep emojis as they add significant value even in some non-color terminals.
        return cls._SYMBOLS.get(risk_level.lower(), "⚪")'''

new_content = content.replace(target, replacement, 1)

with open('src/utils/colors.py', 'w') as f:
    f.write(new_content)
