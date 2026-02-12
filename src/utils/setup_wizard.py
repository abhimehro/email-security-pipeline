"""
Interactive setup wizard for initial configuration.
Simplifies the onboarding process by guiding users through key settings.
"""

import sys
import getpass
from pathlib import Path
from dotenv import set_key
from .colors import Colors

def run_setup_wizard(config_file: str):
    """Run interactive setup wizard for .env configuration"""
    print(f"\n{Colors.CYAN}🔧 Configuration Wizard{Colors.RESET}")
    print(f"{Colors.GREY}Let's get your email accounts set up.{Colors.RESET}\n")

    # Gmail Setup
    if _confirm("Configure Gmail account?"):
        email = input(f"  {Colors.BOLD}Gmail Address:{Colors.RESET} ").strip()
        print(f"  {Colors.GREY}(Use an App Password, not your login password){Colors.RESET}")
        password = getpass.getpass(f"  {Colors.BOLD}App Password:{Colors.RESET} ").strip()

        if email and password:
            try:
                _update_env(config_file, "GMAIL_ENABLED", "true")
                _update_env(config_file, "GMAIL_EMAIL", email)
                _update_env(config_file, "GMAIL_APP_PASSWORD", password)
                print(f"  {Colors.GREEN}✔ Gmail configured{Colors.RESET}\n")
            except Exception as e:
                print(f"  {Colors.RED}❌ Error saving configuration: {e}{Colors.RESET}\n")

    print(f"{Colors.GREEN}Configuration saved to {config_file}{Colors.RESET}")
    print(f"{Colors.GREY}You can edit other settings manually in the file.{Colors.RESET}\n")

def _confirm(question: str) -> bool:
    """Ask a yes/no question"""
    try:
        response = input(f"{question} [Y/n] ").strip().lower()
        return response in ('', 'y', 'yes')
    except EOFError:
        return False

def _update_env(file: str, key: str, value: str):
    """Update a key in the .env file"""
    # quote_mode="auto" handles values with spaces or special chars correctly
    set_key(file, key, value, quote_mode="auto")
