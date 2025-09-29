#!/bin/bash

# Simple runner script for IAM Policy Analyzer
# This script activates the virtual environment and runs the analyzer

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Setting up virtual environment..."
    python -m venv venv
    echo "Installing dependencies..."
    source venv/bin/activate
    pip install -r requirements.txt
fi

# Activate virtual environment and run the analyzer
source venv/bin/activate
python simple_analyzer.py "$@"
