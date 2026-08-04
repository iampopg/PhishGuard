import logging
import sys


def configure_logging(level: str = "INFO", quiet: bool = False) -> logging.Logger:
    if quiet:
        level = "WARNING"
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    root = logging.getLogger("phishguard")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.propagate = False
    return root


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"phishguard.{name}")
