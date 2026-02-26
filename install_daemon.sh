#!/bin/bash
#
# Email Security Pipeline - Launchd Daemon Installer
# Installs and configures the email security pipeline as a background service
#

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Directories
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PIPELINE_DIR="${SCRIPT_DIR}"
LAUNCHD_DIR="${PIPELINE_DIR}/launchd"
PLIST_NAME="com.abhimehrotra.email-security-pipeline.plist"
PLIST_SOURCE="${LAUNCHD_DIR}/${PLIST_NAME}"
PLIST_DEST="${HOME}/Library/LaunchAgents/${PLIST_NAME}"
LOG_DIR="${HOME}/Library/Logs/email-security-pipeline"

# Print functions
print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Check prerequisites
print_header "Checking Prerequisites"

# Check if .env exists
if [ ! -f "${PIPELINE_DIR}/.env" ]; then
    print_error ".env file not found!"
    print_info "Run 'python3 test_config.py' first to validate your configuration"
    exit 1
fi
print_success ".env file found"

# Check Python3
if ! command -v python3 &> /dev/null; then
    print_error "python3 not found in PATH"
    exit 1
fi
print_success "Python3 found: $(which python3)"

# Check if pipeline runs
print_info "Testing pipeline configuration..."
if ! ./venv/bin/python3 src/main.py --help > /dev/null 2>&1; then
    print_warning "Configuration test failed. Continue anyway? (y/n)"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        print_error "Installation cancelled"
        exit 1
    fi
else
    print_success "Configuration test passed"
fi

# Create log directory
print_header "Setting Up Directories"
mkdir -p "${LOG_DIR}"
print_success "Created log directory: ${LOG_DIR}"

# Install plist
print_header "Installing Launch Agent"

if [ -f "${PLIST_DEST}" ]; then
    print_warning "Launch agent already exists. Unloading..."
    launchctl unload "${PLIST_DEST}" 2>/dev/null || true
    rm "${PLIST_DEST}"
fi

cp "${PLIST_SOURCE}" "${PLIST_DEST}"
print_success "Copied plist to: ${PLIST_DEST}"

# Load the launch agent
print_header "Starting Email Security Pipeline"
launchctl load "${PLIST_DEST}"
print_success "Launch agent loaded"

# Give it a moment to start
sleep 2

# Check if it's running
if launchctl list | grep -q "com.abhimehrotra.email-security-pipeline"; then
    print_success "Pipeline is running!"

    # Show status
    print_header "Status"
    launchctl list | grep email-security-pipeline

    print_header "Quick Reference"
    echo "View logs:"
    echo "  tail -f ${LOG_DIR}/pipeline.out"
    echo "  tail -f ${LOG_DIR}/pipeline.err"
    echo "  tail -f ${PIPELINE_DIR}/logs/email_security.log"
    echo ""
    echo "Control the service:"
    echo "  launchctl stop com.abhimehrotra.email-security-pipeline"
    echo "  launchctl start com.abhimehrotra.email-security-pipeline"
    echo "  launchctl unload ${PLIST_DEST}  # Disable"
    echo "  launchctl load ${PLIST_DEST}    # Re-enable"
    echo ""
    echo "Check status:"
    echo "  launchctl list | grep email-security-pipeline"

else
    print_error "Failed to start pipeline!"
    print_info "Check logs for errors:"
    echo "  cat ${LOG_DIR}/pipeline.err"
    exit 1
fi

print_header "Installation Complete!"
print_success "Email Security Pipeline is now running as a background service"
print_info "It will automatically start on login and restart if it crashes"
