#!/bin/bash
# Email Security Pipeline - Setup Script
# Automated setup for quick deployment

set -e  # Exit on error

# Check if running on macOS or Linux
if [[ "$OSTYPE" == "darwin"* ]]; then
    SED_CMD="sed -i ''"
else
    SED_CMD="sed -i"
fi

echo "===================================="
echo "Email Security Pipeline Setup"
echo "===================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

# Check if .env exists
if [ -f .env ]; then
    echo -e "${YELLOW}Warning: .env file already exists${NC}"
    read -p "Do you want to overwrite it? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Keeping existing .env file"
    else
        cp .env.example .env
        print_success "Created new .env from template"
    fi
else
    cp .env.example .env
    print_success "Created .env from template"
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

GMAIL_CONFIGURED=false

if [[ $REPLY =~ ^[Yy]$ ]]; then
    read -p "Enter your Gmail address: " gmail_email
    read -sp "Enter your Gmail app password (hidden): " gmail_password
    echo ""

    # Update .env file (using OS-appropriate sed command)
    $SED_CMD "s|GMAIL_EMAIL=.*|GMAIL_EMAIL=$gmail_email|" .env
    $SED_CMD "s|GMAIL_APP_PASSWORD=.*|GMAIL_APP_PASSWORD=$gmail_password|" .env
    $SED_CMD "s|GMAIL_ENABLED=.*|GMAIL_ENABLED=true|" .env

    # Clear password from memory (basic security measure)
    gmail_password=""

    print_success "Gmail credentials configured!"
    GMAIL_CONFIGURED=true
fi

echo ""
echo "===================================="
echo "Deployment Method"
echo "===================================="
echo ""
echo "Choose your deployment method:"
echo "1) Docker (recommended)"
echo "2) Local Python (Virtual Environment)"
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
    print_success "Docker image built successfully!"
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

    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}Error: Python 3 is not installed${NC}"
        exit 1
    fi

    # Create Virtual Environment
    if [ ! -d "venv" ]; then
        print_info "Creating virtual environment (venv)..."
        if ! python3 -m venv venv; then
            echo -e "${RED}Error: Failed to create venv.${NC}"
            if [[ "$OSTYPE" == "linux-gnu"* ]]; then
                echo "You might need to install python3-venv: sudo apt install python3-venv"
            fi
            exit 1
        fi
        print_success "Virtual environment created"
    else
        print_info "Using existing virtual environment"
    fi

    # Upgrade pip and install dependencies
    print_info "Installing dependencies..."

    if ./venv/bin/pip install --upgrade pip && \
       ./venv/bin/pip install -r requirements.txt; then
        print_success "Dependencies installed successfully"
    else
        echo -e "${RED}Error installing dependencies${NC}"
        exit 1
    fi

    echo ""
    print_success "Setup complete!"
    echo ""

    # Run connectivity check if configured
    if [ -f .env ]; then
        echo "===================================="
        echo "Connectivity Check"
        echo "===================================="
        echo ""
        read -p "Run connection test now? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            ./venv/bin/python scripts/check_mail_connectivity.py
        fi
    fi

    echo ""
    echo "To start the pipeline:"
    echo "  ./venv/bin/python src/main.py"
    echo ""
    echo "Or activate the virtual environment manually:"
    echo "  source venv/bin/activate"
    echo "  python src/main.py"
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
print_success "Ready to go!"
