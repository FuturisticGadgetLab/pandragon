#!/bin/bash
# Rebuild Cython modules for the Pandragon server

VENV_PATH="./venv"

echo "Activating virtual environment..."
source "$VENV_PATH/bin/activate"

echo "Rebuilding Cython modules..."
cd "$(dirname "$0")/protocol"
# Use cythonize -i to compile the module in-place
cythonize -i parser.pyx

echo "Build complete."
