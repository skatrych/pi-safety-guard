#!/bin/bash

# Simple deployment script for the Safety Guard extension
# This script ensures the extension is deployed to the correct Pi agent directory
# without nested folder issues.

# Configurable deployment via environment variable
# Default deployment location: $HOME/.pi/agent/extensions/safety-guard
DEPLOY_DIR="${DEPLOY_DIR:-$HOME/.pi/agent/extensions/safety-guard}"

# Configure source via environment variable or use default
# Source location: $HOME/prj/pi-talks/safety-guard/safety-guard
SOURCE_DIR="${SOURCE_DIR:-$HOME/prj/pi-talks/safety-guard/safety-guard}"

BACKUP_PATH="$DEPLOY_DIR/safety-guard-backup-$(date +%Y%m%d_%H%M%S).ts"

echo "🚀 Starting Safety Guard deployment..."
echo "   Source: $SOURCE_DIR"
echo "   Destination: $DEPLOY_DIR"

# 1. Backup existing single-file version if it exists
if [ -f "$HOME/.pi/agent/extensions/safety-guard.ts" ]; then
    echo "📦 Backing up old single-file extension to $BACKUP_PATH"
    cp "$HOME/.pi/agent/extensions/safety-guard.ts" "$BACKUP_PATH"
    rm "$HOME/.pi/agent/extensions/safety-guard.ts"
fi

# 2. Prepare deployment directory
if [ -d "$DEPLOY_DIR" ]; then
    echo "🗑️  Removing old deployment directory"
    rm -rf "$DEPLOY_DIR"
fi

echo "📁 Creating deployment directory at $DEPLOY_DIR"
mkdir -p "$DEPLOY_DIR"

# 3. Copy files directly into the deployment directory
echo "🚚 Copying extension modules..."
cp "$SOURCE_DIR"/*.ts "$DEPLOY_DIR/"

# 4. Verify deployment
if [ -f "$DEPLOY_DIR/index.ts" ]; then
    echo "✅ Success! Extension deployed to $DEPLOY_DIR"
    echo "✨ Restart Pi agent to apply changes."
else
    echo "❌ Error: Deployment failed. index.ts not found in $DEPLOY_DIR"
    exit 1
fi
