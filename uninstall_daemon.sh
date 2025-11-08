#!/bin/bash
#
# Email Security Pipeline - Launchd Daemon Uninstaller
# Stops and removes the email security pipeline background service
#

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PLIST_NAME="com.abhimehrotra.email-security-pipeline.plist"
PLIST_DEST="${HOME}/Library/LaunchAgents/${PLIST_NAME}"

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

print_header "Uninstalling Email Security Pipeline Service"

# Check if launch agent exists
if [ ! -f "${PLIST_DEST}" ]; then
    print_warning "Launch agent not found. Nothing to uninstall."
    exit 0
fi

# Unload the launch agent
print_header "Stopping Service"
if launchctl list | grep -q "com.abhimehrotra.email-security-pipeline"; then
    launchctl unload "${PLIST_DEST}"
    print_success "Service stopped"
else
    print_warning "Service was not running"
fi

# Remove the plist
rm "${PLIST_DEST}"
print_success "Launch agent removed"

# Verify it's gone
if launchctl list | grep -q "com.abhimehrotra.email-security-pipeline"; then
    print_error "Service still appears to be running!"
    print_info "Try: launchctl remove com.abhimehrotra.email-security-pipeline"
else
    print_success "Service completely removed"
fi

print_header "Cleanup Complete"
print_info "Logs are preserved at: ${HOME}/Library/Logs/email-security-pipeline/"
print_info "To remove logs: rm -rf ${HOME}/Library/Logs/email-security-pipeline/"
print_success "Email Security Pipeline service has been uninstalled"
