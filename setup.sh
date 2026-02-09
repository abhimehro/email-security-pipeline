#!/bin/bash
# Email Security Pipeline - Setup Script
# Automated setup for quick deployment

set -e  # Exit on error

echo "===================================="
echo "Email Security Pipeline Setup"
echo "===================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if .env exists
if [ -f .env ]; then
    echo -e "${YELLOW}Warning: .env file already exists${NC}"
    read -p "Do you want to overwrite it? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Keeping existing .env file"
    else
        cp .env.example .env
        echo -e "${GREEN}Created new .env from template${NC}"
    fi
else
    cp .env.example .env
    echo -e "${GREEN}Created .env from template${NC}"
fi

echo ""
echo "===================================="
echo "Configuration"
echo "===================================="
echo ""
echo "You need to configure your email credentials in the .env file."
echo ""
read -p "Would you like to configure Gmail credentials now? (y/N): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    read -p "Enter your Gmail address: " gmail_email
    read -sp "Enter your Gmail app password (hidden): " gmail_password
    echo ""

    # Require python3 for safe .env updates
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}Error: python3 is required to update .env safely${NC}"
        exit 1
    fi

    # Update .env file using Python to avoid credential leakage via ps aux.
    # Secrets are passed as one-off environment variables, never exported.
    GMAIL_EMAIL="$gmail_email" GMAIL_APP_PASSWORD="$gmail_password" python3 -c '
import os

email = os.environ.get("GMAIL_EMAIL", "")
password = os.environ.get("GMAIL_APP_PASSWORD", "")

lines = []
email_found = False
password_found = False

with open(".env", "r") as f:
    for line in f:
        if line.startswith("GMAIL_EMAIL="):
            lines.append(f"GMAIL_EMAIL={email}\n")
            email_found = True
        elif line.startswith("GMAIL_APP_PASSWORD="):
            lines.append(f"GMAIL_APP_PASSWORD={password}\n")
            password_found = True
        else:
            lines.append(line)

if not email_found:
    lines.append(f"GMAIL_EMAIL={email}\n")
if not password_found:
    lines.append(f"GMAIL_APP_PASSWORD={password}\n")

with open(".env", "w") as f:
    f.writelines(lines)
'

    # Clear password from shell variable
    gmail_password=""

    echo -e "${GREEN}Gmail credentials configured!${NC}"
fi

echo ""
echo "===================================="
echo "Deployment Method"
echo "===================================="
echo ""
echo "Choose your deployment method:"
echo "1) Docker (recommended)"
echo "2) Local Python"
echo ""
read -p "Enter choice (1 or 2): " -n 1 -r
echo
echo ""

if [[ $REPLY == "1" ]]; then
    echo "Building Docker image..."

    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Error: Docker is not installed${NC}"
        echo "Please install Docker and try again"
        exit 1
    fi

    docker-compose build

    echo ""
    echo -e "${GREEN}Docker image built successfully!${NC}"
    echo ""
    echo "To start the pipeline:"
    echo "  docker-compose up -d"
    echo ""
    echo "To view logs:"
    echo "  docker-compose logs -f"
    echo ""
    echo "To stop the pipeline:"
    echo "  docker-compose down"

elif [[ $REPLY == "2" ]]; then
    echo "Setting up local Python environment..."

    # Check Python version
    python_version=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
    required_version="3.11"

    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}Error: Python 3 is not installed${NC}"
        exit 1
    fi

    echo "Installing Python dependencies..."
    python3 -m pip install -r requirements.txt

    echo ""
    echo -e "${GREEN}Setup complete!${NC}"
    echo ""
    echo "To start the pipeline:"
    echo "  python3 src/main.py"
    echo ""
    echo "To view logs (in another terminal):"
    echo "  tail -f logs/email_security.log"

else
    echo -e "${RED}Invalid choice${NC}"
    exit 1
fi

echo ""
echo "===================================="
echo "Next Steps"
echo "===================================="
echo ""
echo "1. Review and update .env with your credentials"
echo "2. Read QUICKSTART.md for detailed instructions"
echo "3. Test the system by sending a suspicious email to yourself"
echo ""
echo -e "${GREEN}Setup complete!${NC}"
