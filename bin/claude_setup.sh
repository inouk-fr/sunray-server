#!/bin/bash

# Install Node.js LTS 20 + npm from NodeSource
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Check install
echo "Node.js version : $(node -v)"
echo "npm version     : $(npm -v)"

# To uninstall
#sudo apt remove --purge nodejs
#sudo rm /etc/apt/sources.list.d/nodesource.list

#
# Install Claude code
#
sudo npm install -g @anthropic-ai/claude-code
#
# Install playwright
# Ref: https://community.nodebb.org/topic/e118d50c-ab30-47a9-b444-7779569e48c4/i-figured-out-how-to-add-the-official-playwright-browser-automation-mcp-to-claude-code.
sudo apt install -y chromium
claude mcp add playwright npx '@playwright/mcp@latest'

#
# Use playwright
# Ref: https://til.simonwillison.net/claude-code/playwright-mcp-claude-code
# in claude code prompt:
#  Use playwright mcp to open a browser at https://www.muppy.io