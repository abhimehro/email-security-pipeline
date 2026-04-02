#!/bin/bash
# Graceful shutdown script for email-security-pipeline
# Called by LaunchAgent when stopping the service

set -e

cd /Users/speedybee/dev/email-security-pipeline
/opt/homebrew/bin/docker compose down
