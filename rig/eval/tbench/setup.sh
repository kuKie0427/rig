#!/bin/bash
# Setup script for rig inside a Terminal-Bench container.
# Installs rig into an isolated venv.
#
# Environment variables:
#   RIG_VERSION  Pin to a specific git ref (branch, tag, or commit SHA).
#                  Defaults to "master". Set to a tagged release or commit SHA
#                  for reproducible benchmark runs, e.g. RIG_VERSION=v0.22.0

set -euo pipefail

RIG_VERSION="${RIG_VERSION:-master}"

# Install system dependencies
apt-get update -q
apt-get install -y --no-install-recommends python3 python3-pip python3-venv git

# Create venv and install uv inside it (no system package changes required)
python3 -m venv /opt/rig-venv
/opt/rig-venv/bin/pip install --quiet uv

# Install rig via uv (fast, reproducible)
/opt/rig-venv/bin/uv pip install "rig @ git+https://github.com/rig/rig.git@${RIG_VERSION}"

# Make rig available globally
ln -sf /opt/rig-venv/bin/rig /usr/local/bin/rig

# Verify
rig --version
echo "rig setup complete."
