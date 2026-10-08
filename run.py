"""
SecureLLM AI — Root Launcher
Delegates execution to the main application inside LLM-Based-Prompt-Injection/
"""
import os
import sys

# Set current working directory and sys.path to the inner package directory
pkg_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Vexora-LLM-Based-Prompt-Injection")
os.chdir(pkg_dir)
sys.path.insert(0, pkg_dir)

if __name__ == "__main__":
    from app import app
    print("=" * 60)
    print("[SecureLLM AI] Server starting on http://127.0.0.1:5000")
    print("  3-Layer Background Defense Shield Active")
    print("=" * 60)
    app.run(debug=True, port=5000)
