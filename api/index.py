import os
import sys

# Ensure project root directory is in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Import the configured Flask application instance
from app import app

# Vercel WSGI entry point (callable 'app')
if __name__ == "__main__":
    app.run(debug=True)
