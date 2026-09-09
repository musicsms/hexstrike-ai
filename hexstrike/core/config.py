import os

API_PORT = int(os.environ.get("HEXSTRIKE_PORT", 8888))
DEFAULT_HOST = os.environ.get("HEXSTRIKE_HOST", "0.0.0.0")
COMMAND_TIMEOUT = int(os.environ.get("HEXSTRIKE_TIMEOUT", 300))
CACHE_SIZE = int(os.environ.get("HEXSTRIKE_CACHE_SIZE", 1000))
CACHE_TTL = int(os.environ.get("HEXSTRIKE_CACHE_TTL", 3600))
DEFAULT_HEXSTRIKE_SERVER = f"http://127.0.0.1:{API_PORT}"
