#!/usr/bin/env python3
"""HexStrike AI API Server - Backward Compatible Entrypoint."""
import argparse
from hexstrike.core.visual import BANNER, ModernVisualEngine
from hexstrike.core.config import API_PORT
from hexstrike.api.app import create_app

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Run the HexStrike AI API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    args = parser.parse_args()

    app = create_app(debug=args.debug)
    app.run(host="0.0.0.0", port=args.port, debug=args.debug)

if __name__ == "__main__":
    main()
