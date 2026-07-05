import logging
import sys

def setup_logger(name: str = "FIC", verbose: bool = False) -> logging.Logger:
    """
    Configure a standardized logger for the File Integrity Checker.
    
    Why it exists:
    In security tools, visibility is critical. We need to distinguish between
    INFO (routine scans), WARNING (missing/untracked files), and ERROR/CRITICAL
    (tampered files or permission denied). Standard print() doesn't scale.
    """
    logger = logging.getLogger(name)
    
    # Avoid duplicate handlers if setup_logger is called multiple times
    if logger.hasHandlers():
        logger.handlers.clear()

    # Set log level based on verbosity
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Format output cleanly
    formatter = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger
