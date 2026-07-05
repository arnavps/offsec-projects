import argparse
import getpass

def parse_args():
    """
    Parses command-line arguments.
    
    Security Relevance:
    Passwords passed via CLI arguments can be saved in shell history (.bash_history). 
    We allow a --password flag for automated scripts, but encourage interactive 
    prompting via getpass to prevent accidental history logging.
    """
    parser = argparse.ArgumentParser(
        description="Entropy-based Password Strength Analyzer",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        '-p', '--password',
        type=str,
        help="Password to analyze. If omitted, you will be prompted securely."
    )
    
    return parser.parse_args()

def get_password(args) -> str:
    """
    Retrieves the password securely if not provided via arguments.
    """
    if args.password is not None:
        return args.password
    
    try:
        # getpass prevents the password from echoing to the terminal
        return getpass.getpass("Enter password to analyze (input hidden): ")
    except Exception as e:
        print(f"Error reading password securely: {e}")
        return ""
