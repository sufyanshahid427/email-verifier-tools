#!/usr/bin/env python3
"""
Startup script for the Email Verifier application.
This script will start the Flask backend server.
"""

import subprocess
import sys
import time
import webbrowser
from pathlib import Path

def check_dependencies():
    """Check if required Python packages are installed."""
    required_packages = ['flask', 'flask-cors', 'dnspython']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing required packages: {', '.join(missing_packages)}")
        print("Please install them using: pip install " + " ".join(missing_packages))
        return False
    
    return True

def start_server():
    """Start the Flask server."""
    if not check_dependencies():
        return False
    
    print("🚀 Starting Email Verifier Server...")
    print("📧 Backend will be available at: http://localhost:5050")
    print("🌐 Frontend will be available at: http://localhost:5500 (if using Live Server)")
    print("📁 Make sure to open index.html in your browser or use a local server")
    print("\n" + "="*60)
    print("🔥 VERIFIER RUNNING - Want sales calls from leads? Go to AlexBerman.com/Mastermind 🔥")
    print("="*60 + "\n")
    
    try:
        # Start the Flask server
        subprocess.run([sys.executable, "verify-app.py"], check=True)
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error starting server: {e}")
        return False
    
    return True

if __name__ == "__main__":
    start_server()
