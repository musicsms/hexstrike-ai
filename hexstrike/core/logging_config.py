import logging
import sys

def configure_logging() -> None:
    """Idempotent: safe to call from every entrypoint without adding duplicate handlers."""
    if logging.getLogger().handlers:
        return

    handlers = [logging.StreamHandler(sys.stdout)]
    try:
        handlers.append(logging.FileHandler('hexstrike.log'))
    except OSError:
        pass

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers,
    )
