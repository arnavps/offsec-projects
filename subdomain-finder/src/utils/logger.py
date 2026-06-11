import logging
import sys

class CustomFormatter(logging.Formatter):
    grey = "\x1b[38;20m"
    blue = "\x1b[34;20m"
    green = "\x1b[32;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    reset = "\x1b[0m"
    
    format_info = f"{blue}[*]{reset} %(message)s"
    format_success = f"{green}[+]{reset} %(message)s"
    format_warning = f"{yellow}[!]{reset} %(message)s"
    format_error = f"{red}[-]{reset} %(message)s"
    format_debug = f"{grey}[DEBUG]{reset} %(message)s"

    FORMATS = {
        logging.DEBUG: format_debug,
        logging.INFO: format_info,
        logging.WARNING: format_warning,
        logging.ERROR: format_error,
        logging.CRITICAL: format_error
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, self.format_info)
        
        # Hack to support custom SUCCESS level by checking message prefix
        # This allows us to use logger.info("[+] Message") internally if we don't want a custom log level
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            if record.msg.startswith("[SUCCESS]"):
                log_fmt = self.format_success
                record.msg = record.msg.replace("[SUCCESS] ", "")

        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

def setup_logger(debug=False):
    logger = logging.getLogger("SubdomainFinder")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    
    if not logger.handlers:
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.DEBUG if debug else logging.INFO)
        ch.setFormatter(CustomFormatter())
        logger.addHandler(ch)
        
    return logger

logger = setup_logger()
