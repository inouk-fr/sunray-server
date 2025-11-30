#!/usr/bin/env bash
set -euo pipefail

# SCRIPT: mpy_install_510_ikb.sh
# LAYER: 5 - Application-Specific (ikb installation)
# PURPOSE: Install ikb (inouk buildit) WITHOUT sudo privileges
# USAGE: ./mpy_install_510_ikb.sh (NO SUDO)
# ENV VARS:
#   - MPY_APP_BASE_DIR: Base directory (default: /opt/muppy)
#   - IKB_PYTHON_VERSION: Python version (default: cpython@3.12.8)
#   - IKB_DEV_MODE: Install ikb in dev mode (default: False)
# EXIT CODES:
#   0 - Success
#   1 - Installation failed or run with sudo

echo "[INFO] ikb (inouk buildit) installation"

# Check NOT running with sudo
if [[ $EUID -eq 0 ]]; then
  echo "[ERROR] This script should NOT be run with sudo"
  echo "[INFO] Run as regular user: ./mpy_install_510_ikb.sh"
  exit 1
fi

# Configuration
MPY_APP_BASE_DIR="${MPY_APP_BASE_DIR:-/opt/muppy}"
TOOLS_DIR="$MPY_APP_BASE_DIR/tools"
SRC_DIR="$MPY_APP_BASE_DIR/src"
IKB_PYTHON_VERSION="${IKB_PYTHON_VERSION:-cpython@3.12.8}"
IKB_DEV_MODE="${IKB_DEV_MODE:-False}"

# Check uv is available
if ! command -v uv &> /dev/null; then
  echo "[ERROR] uv not found. Please run mpy_install_500_odoo18_deps.sh first"
  exit 1
fi

echo "[INFO] Installing ikb (inouk buildit)..."

# Clean up previous installation
echo "[INFO] Removing previous ikb installation if exists..."
uv tool uninstall inouk-buildit 2>/dev/null || true

# Fresh installation
if [ "$IKB_DEV_MODE" = "True" ]; then
  echo "[INFO] Installing ikb in development mode..."
  if [ ! -d "$SRC_DIR/buildit" ]; then
    mkdir -p "$SRC_DIR"
    git clone https://gitlab.com/inouk/buildit.git "$SRC_DIR/buildit"
  fi
  UV_TOOL_BIN_DIR=$TOOLS_DIR uv tool install --editable "$SRC_DIR/buildit"
else
  echo "[INFO] Installing ikb from git..."
  UV_TOOL_BIN_DIR=$TOOLS_DIR uv tool install \
    --python=${IKB_PYTHON_VERSION} git+https://gitlab.com/inouk/buildit.git
fi

# Create symlink for system-wide access (requires sudo)
if [ -f "${TOOLS_DIR}/ikb" ] || [ -L "${TOOLS_DIR}/ikb" ]; then
  echo "[INFO] Creating system-wide symlink for ikb..."
  sudo ln -sf ${TOOLS_DIR}/ikb /usr/local/bin/ikb
  echo "[SUCCESS] ikb installed and available system-wide"
else
  echo "[ERROR] ikb binary not found at ${TOOLS_DIR}/ikb"
  exit 1
fi

# Verification
if command -v ikb &> /dev/null; then
  echo "[SUCCESS] ikb is accessible system-wide"
  ikb 2>&1 | head -3
else
  echo "[ERROR] ikb installation failed"
  exit 1
fi

echo "[INFO] ikb installation complete!"
exit 0
