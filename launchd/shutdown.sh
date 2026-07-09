#!/bin/bash
# Graceful shutdown script for email-security-pipeline
# Called by LaunchAgent when stopping the service

set -euo pipefail

cd /Users/speedybee/dev/email-security-pipeline
/opt/homebrew/bin/docker --context colima compose down
