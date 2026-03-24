#!/bin/bash
# Run autonomous training with venv activated

# Activate venv first
source venv/bin/activate

# Check dependencies
python3 -c "import numpy; print('numpy OK')" 2>/dev/null || {
    echo "Installing numpy..."
    pip install numpy
}

# Run training
python3 autonomous_training.py "$@"