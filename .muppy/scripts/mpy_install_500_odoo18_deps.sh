#!/usr/bin/env bash
set -euo pipefail

# SCRIPT: mpy_install_500_odoo18_deps.sh
# LAYER: 5 - Application-Specific (Odoo 18 Dependencies)
# PURPOSE: Install Odoo 18 development dependencies (Python libs, wkhtmltopdf, uv, Python, ikb)
# USAGE: [sudo] ./mpy_install_500_odoo18_deps.sh
# ENV VARS:
#   - MPY_USERNAME: System username (default: $USER)
#   - MPY_APP_BASE_DIR: Base directory (default: /opt/muppy)
#   - IKB_PYTHON_VERSION: Python version (default: cpython@3.12.8)
#   - IKB_ODOO_VERSION: Odoo major version (default: 18)
#   - IKB_DEV_MODE: Install ikb in dev mode (default: False)
# REQUIREMENTS: Ubuntu 24.04 LTS or later
# EXIT CODES:
#   0 - Success (installed or already present)
#   1 - Missing dependencies or installation failed

# Detect execution context (Docker vs LXC vs bare metal)
detect_context() {
  if [ -f /.dockerenv ]; then
    echo "docker"
  elif [ -d /dev/lxd ]; then
    echo "lxc"
  else
    echo "bare_metal"
  fi
}

CONTEXT=$(detect_context)
echo "[INFO] Running in ${CONTEXT} context..."
echo "[INFO] Odoo 18 dependencies installation"

# Configuration
# Use SUDO_USER if available (when run with sudo), otherwise fall back to USER
MPY_USERNAME="${MPY_USERNAME:-${SUDO_USER:-$USER}}"
MPY_APP_BASE_DIR="${MPY_APP_BASE_DIR:-/opt/muppy}"
TOOLS_DIR="$MPY_APP_BASE_DIR/tools"
SRC_DIR="$MPY_APP_BASE_DIR/src"
IKB_PYTHON_VERSION="${IKB_PYTHON_VERSION:-cpython@3.12.8}"
IKB_ODOO_VERSION="${IKB_ODOO_VERSION:-18}"
IKB_DEV_MODE="${IKB_DEV_MODE:-False}"

# Check if core components already installed (idempotency)
# Note: ikb is always reinstalled for clean idempotency
if command -v uv &> /dev/null && command -v wkhtmltopdf &> /dev/null; then
  UV_VERSION=$(uv --version 2>/dev/null || echo "unknown")
  WKHTMLTOPDF_VERSION=$(wkhtmltopdf --version 2>/dev/null | head -n1 || echo "unknown")
  echo "[INFO] Core dependencies already installed (uv and wkhtmltopdf)"
  echo "  - uv: ${UV_VERSION}"
  echo "  - wkhtmltopdf: ${WKHTMLTOPDF_VERSION}"
  echo "[INFO] Skipping uv and wkhtmltopdf installation (ikb will be reinstalled)..."
  # Don't exit - continue to reinstall ikb
fi

# Check root/sudo privileges
if [[ $EUID -ne 0 ]]; then
  echo "[ERROR] This script requires sudo/root privileges"
  exit 1
fi

echo "[INFO] Installing Odoo 18 dependencies..."

#
# 1. Install Python development libraries
#
echo "[INFO] Installing Python development libraries..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
  python-dev-is-python3 python3-dev python3-venv \
  libffi-dev liblzma-dev zlib1g-dev libbz2-dev \
  libncurses5-dev libncursesw5-dev xz-utils tk-dev \
  libsasl2-dev libldap2 libldap2-dev libz-dev \
  libreadline-dev \
  libjpeg-dev libfreetype-dev liblcms2-dev \
  libopenjp2-7 libopenjp2-7-dev \
  libwebp7 libwebp-dev libtiff-dev

#
# 2. Install font packages
#
echo "[INFO] Installing font packages..."
apt-get install -y --no-install-recommends \
  fontconfig fontconfig-config fonts-dejavu-core \
  libfontconfig1 libfontenc1 libxrender1 \
  x11-common xfonts-75dpi xfonts-base \
  xfonts-encodings xfonts-utils

#
# 3. Install wkhtmltopdf
#
WKHTMLTOPDF_VERSION="0.12.6.1-3"
WKHTMLTOPDF_DEB="wkhtmltox_${WKHTMLTOPDF_VERSION}.jammy_amd64.deb"
WKHTMLTOPDF_URL="https://github.com/wkhtmltopdf/packaging/releases/download/${WKHTMLTOPDF_VERSION}/${WKHTMLTOPDF_DEB}"

if ! command -v wkhtmltopdf &> /dev/null; then
  echo "[INFO] Installing wkhtmltopdf ${WKHTMLTOPDF_VERSION}..."
  wget -q $WKHTMLTOPDF_URL
  dpkg -i $WKHTMLTOPDF_DEB 2>/dev/null || true
  rm $WKHTMLTOPDF_DEB
else
  echo "[INFO] wkhtmltopdf already installed, skipping..."
fi

#
# 4. Create directory structure
#
echo "[INFO] Creating /opt/muppy directory structure..."
mkdir -p "$MPY_APP_BASE_DIR" "$TOOLS_DIR" "$SRC_DIR"

# Set ownership if running as root but installing for specific user
if [[ "$MPY_USERNAME" != "root" ]] && id -u "$MPY_USERNAME" &>/dev/null; then
  chown -R $MPY_USERNAME:$MPY_USERNAME "$MPY_APP_BASE_DIR"
fi
chmod 755 "$MPY_APP_BASE_DIR" "$TOOLS_DIR" "$SRC_DIR"

#
# 5. Install uv (in /opt/muppy/tools with system-wide symlink)
#
if ! command -v uv &> /dev/null; then
  if [ -f "${TOOLS_DIR}/uv" ]; then
    echo "[INFO] uv found in ${TOOLS_DIR}, creating symlink..."
  else
    echo "[INFO] Installing uv package manager..."
    curl -LsSf https://astral.sh/uv/install.sh | env UV_UNMANAGED_INSTALL="${TOOLS_DIR}" sh
  fi

  # Create symlink for system-wide access
  echo "[INFO] Creating system-wide symlink for uv..."
  ln -sf ${TOOLS_DIR}/uv /usr/local/bin/uv
else
  echo "[INFO] uv already installed and accessible system-wide, skipping..."
fi

#
# 6. Install Python via uv
#
echo "[INFO] Installing Python ${IKB_PYTHON_VERSION} via uv..."
uv python install $IKB_PYTHON_VERSION || {
  echo "[WARNING] Python installation may have failed or version already installed"
}

#
# 7. Install ikb (inouk buildit) - Always reinstall for clean idempotency
#
echo "[INFO] Installing ikb (inouk buildit)..."

# Clean up any previous installation
echo "[INFO] Removing previous ikb installation if exists..."
rm -f /usr/local/bin/ikb
rm -f ${TOOLS_DIR}/ikb
# Clean up uv tool installations for both root and user
uv tool uninstall inouk-buildit 2>/dev/null || true
if [[ "$MPY_USERNAME" != "root" ]] && id -u "$MPY_USERNAME" &>/dev/null; then
  sudo -u $MPY_USERNAME uv tool uninstall inouk-buildit 2>/dev/null || true
fi

# Fresh installation (install as non-root user for proper permissions)
if [ "$IKB_DEV_MODE" = "True" ]; then
  echo "[INFO] Installing ikb in development mode..."
  if [ ! -d "$SRC_DIR/buildit" ]; then
    git clone https://gitlab.com/inouk/buildit.git "$SRC_DIR/buildit"
  fi
  if [[ "$MPY_USERNAME" != "root" ]] && id -u "$MPY_USERNAME" &>/dev/null; then
    sudo -u $MPY_USERNAME UV_TOOL_BIN_DIR=$TOOLS_DIR uv tool install --editable "$SRC_DIR/buildit"
  else
    UV_TOOL_BIN_DIR=$TOOLS_DIR uv tool install --editable "$SRC_DIR/buildit"
  fi
else
  echo "[INFO] Installing ikb from git..."
  if [[ "$MPY_USERNAME" != "root" ]] && id -u "$MPY_USERNAME" &>/dev/null; then
    sudo -u $MPY_USERNAME UV_TOOL_BIN_DIR=$TOOLS_DIR uv tool install \
      --python=${IKB_PYTHON_VERSION} git+https://gitlab.com/inouk/buildit.git
  else
    UV_TOOL_BIN_DIR=$TOOLS_DIR uv tool install \
      --python=${IKB_PYTHON_VERSION} git+https://gitlab.com/inouk/buildit.git
  fi
fi

# Create symlink for system-wide access
echo "[INFO] Creating system-wide symlink for ikb..."
ln -sf ${TOOLS_DIR}/ikb /usr/local/bin/ikb

#
# 8. Verification
#
echo "[INFO] Verifying installations..."
VERIFICATION_FAILED=false

# Check wkhtmltopdf
if command -v wkhtmltopdf &> /dev/null; then
  WKHTMLTOPDF_VER=$(wkhtmltopdf --version 2>/dev/null | head -n1 || echo "installed")
  echo "[SUCCESS] wkhtmltopdf: ${WKHTMLTOPDF_VER}"
else
  echo "[ERROR] wkhtmltopdf installation failed"
  VERIFICATION_FAILED=true
fi

# Check uv
if command -v uv &> /dev/null; then
  UV_VER=$(uv --version 2>/dev/null || echo "installed")
  echo "[SUCCESS] uv: ${UV_VER}"
else
  echo "[ERROR] uv installation failed"
  VERIFICATION_FAILED=true
fi

# Check ikb
if command -v ikb &> /dev/null; then
  IKB_VER=$(ikb --version 2>/dev/null | head -n1 || echo "installed")
  echo "[SUCCESS] ikb: ${IKB_VER}"
else
  echo "[ERROR] ikb installation failed"
  VERIFICATION_FAILED=true
fi

# Check Python
PYTHON_PATH=$(uv python find $IKB_PYTHON_VERSION 2>/dev/null || echo "not found")
if [[ "$PYTHON_PATH" != "not found" ]]; then
  echo "[SUCCESS] Python: ${PYTHON_PATH}"
else
  echo "[WARNING] Python ${IKB_PYTHON_VERSION} may not be installed correctly"
fi

if $VERIFICATION_FAILED; then
  echo "[ERROR] Some components failed to install"
  exit 1
fi

#
# 9. Cleanup (Docker context only)
#
if [[ "${CONTEXT}" == "docker" ]]; then
  echo "[INFO] Cleaning up apt cache (Docker context)..."
  apt-get clean
  rm -rf /var/lib/apt/lists/*
fi

echo "[INFO] Odoo 18 dependencies installation complete!"
echo "[INFO] Directory structure:"
echo "  - Base: ${MPY_APP_BASE_DIR}"
echo "  - Tools: ${TOOLS_DIR}"
echo "  - Source: ${SRC_DIR}"
echo "[INFO] Tools installed in ${TOOLS_DIR} and symlinked to /usr/local/bin"
echo "[INFO] uv and ikb are now available system-wide"
exit 0
