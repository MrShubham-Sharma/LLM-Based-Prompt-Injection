import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG_DIR = os.path.join(BASE_DIR, "Vexora-LLM-Based-Prompt-Injection")
if PKG_DIR not in sys.path:
    sys.path.insert(0, PKG_DIR)

# Change directory so relative paths (like static/) work properly
os.chdir(PKG_DIR)

from app import app
