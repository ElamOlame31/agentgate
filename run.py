"""
Single entry point. Starts AgentGate PDP server.
Usage: python run.py
"""
import os
import sys
from dotenv import load_dotenv
load_dotenv()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("AGENTGATE_PORT", 8000))
    print(f"\n  AgentGate PDP starting on http://localhost:{port}")
    print(f"  Dashboard: http://localhost:{port}/")
    print(f"  API docs:  http://localhost:{port}/docs\n")
    reload = os.environ.get("AGENTGATE_DEV", "false").lower() == "true"
    uvicorn.run("server.main:app", host="0.0.0.0", port=port, reload=reload)
