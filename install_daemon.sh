#!/bin/bash
#
# Email Security Pipeline - Launchd Daemon Installer
# Installs and configures the email security pipeline as a background service
# backed by Docker Compose using the Colima Docker context.
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE_DIR="${SCRIPT_DIR}"
LAUNCHD_DIR="${PIPELINE_DIR}/launchd"
PLIST_NAME="com.abhimehrotra.email-security-pipeline.plist"
PLIST_SOURCE="${LAUNCHD_DIR}/${PLIST_NAME}"
PLIST_DEST="${HOME}/Library/LaunchAgents/${PLIST_NAME}"
WRAPPER_SOURCE="${LAUNCHD_DIR}/start-email-security-pipeline.sh"
LOG_DIR="${HOME}/Library/Logs/email-security-pipeline"

print_header() { echo -e "\n${BLUE}=== $1 ===${NC}\n"; }
print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }
print_info() { echo -e "${BLUE}ℹ${NC} $1"; }

print_header "Checking Prerequisites"

if [[ ! -f "${PIPELINE_DIR}/.env" ]]; then
	print_error ".env file not found"
	print_info "Copy .env.example to .env and update credentials first"
	exit 1
fi
print_success ".env file found"

if ! command -v docker >/dev/null 2>&1; then
	print_error "docker not found in PATH"
	exit 1
fi
print_success "Docker found: $(command -v docker)"

if ! docker compose version >/dev/null 2>&1; then
	print_error "docker compose plugin not available"
	print_info "Install with: brew install docker-compose"
	exit 1
fi
print_success "docker compose plugin available"

if command -v colima >/dev/null 2>&1; then
	print_info "Ensuring Colima is running..."
	colima start >/dev/null 2>&1 || true
	print_success "Colima is available"
else
	print_warning "colima not found; LaunchAgent will still work if another Docker backend provides the 'colima' context"
fi

print_header "Setting Up Directories"
mkdir -p "${LOG_DIR}"
chmod +x "${WRAPPER_SOURCE}"
print_success "Prepared log directory and wrapper script"

print_header "Installing Launch Agent"
cp "${PLIST_SOURCE}" "${PLIST_DEST}"
python3 - <<PY
from pathlib import Path
import plistlib
plist_path = Path(r"${PLIST_DEST}")
repo = Path(r"${PIPELINE_DIR}")
wrapper = repo / 'launchd/start-email-security-pipeline.sh'
with plist_path.open('rb') as f:
    data = plistlib.load(f)
data['ProgramArguments'] = ['/bin/zsh', str(wrapper)]
data['WorkingDirectory'] = str(repo)
data['StandardOutPath'] = str(Path.home() / 'Library/Logs/email-security-pipeline/pipeline.out')
data['StandardErrorPath'] = str(Path.home() / 'Library/Logs/email-security-pipeline/pipeline.err')
data.setdefault('EnvironmentVariables', {})['HOME'] = str(Path.home())
data['EnvironmentVariables']['PATH'] = '/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'
with plist_path.open('wb') as f:
    plistlib.dump(data, f)
PY
print_success "Installed plist to ${PLIST_DEST}"

print_header "Loading Launch Agent"
launchctl bootout gui/$(id -u) "${PLIST_DEST}" 2>/dev/null || true
launchctl bootstrap gui/$(id -u) "${PLIST_DEST}"
launchctl enable gui/$(id -u)/com.abhimehrotra.email-security-pipeline
launchctl kickstart -k gui/$(id -u)/com.abhimehrotra.email-security-pipeline
print_success "Launch agent loaded"

print_header "Quick Reference"
echo "View LaunchAgent logs:"
echo "  tail -f ${LOG_DIR}/pipeline.out"
echo "  tail -f ${LOG_DIR}/pipeline.err"
echo
echo "View container logs:"
echo "  cd ${PIPELINE_DIR} && docker --context colima compose logs -f"
echo
echo "Restart service:"
echo "  launchctl kickstart -k gui/$(id -u)/com.abhimehrotra.email-security-pipeline"
echo
echo "Disable service:"
echo "  launchctl bootout gui/$(id -u) ${PLIST_DEST}"
echo
echo "Re-enable service:"
echo "  launchctl bootstrap gui/$(id -u) ${PLIST_DEST}"

echo
print_success "Installation complete"
print_info "The service now starts Docker Compose in detached mode using the Colima context"
