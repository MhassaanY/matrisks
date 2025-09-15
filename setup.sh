#!/usr/bin/env bash
set -euo pipefail

# Root-level setup: creates/uses backend venv and installs all deps from requirements-all.txt

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$PROJECT_ROOT/matrisks-backend"

python3 -m venv "$BACKEND_DIR/venv"
source "$BACKEND_DIR/venv/bin/activate"

pip install --upgrade pip
pip install -r "$PROJECT_ROOT/requirements-all.txt"

echo "All dependencies installed into $BACKEND_DIR/venv"
echo "Activate with: source $BACKEND_DIR/venv/bin/activate"

