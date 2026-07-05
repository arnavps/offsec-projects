import sys
from pathlib import Path

from src.cli import setup_parser
from src.utils.logger import setup_logger
from src.core.baseline import BaselineManager
from src.core.verifier import compare_baselines

def main():
    parser = setup_parser()
    args = parser.parse_args()
    
    logger = setup_logger(verbose=args.verbose)
    
    target_dir: Path = args.target
    baseline_file: Path = args.baseline
    
    if not target_dir.exists():
        logger.error(f"Target directory does not exist: {target_dir}")
        sys.exit(1)
        
    if args.command == "generate":
        logger.info(f"Starting baseline generation for target: {target_dir}")
        logger.info(f"Using algorithm: {args.algorithm}")
        
        manager = BaselineManager(target_dir, algorithm=args.algorithm)
        try:
            state = manager.generate_baseline()
            logger.info(f"Hashed {len(state)} files successfully.")
            
            manager.save_to_file(baseline_file)
            logger.info(f"Baseline saved to {baseline_file}")
        except Exception as e:
            logger.error(f"Failed to generate baseline: {e}")
            sys.exit(1)
            
    elif args.command == "verify":
        logger.info(f"Loading trusted baseline from: {baseline_file}")
        if not baseline_file.exists():
            logger.error(f"Baseline file does not exist: {baseline_file}")
            sys.exit(1)
            
        trusted_manager = BaselineManager(target_dir) # Target dir is just a placeholder here, overridden by load
        try:
            trusted_manager.load_from_file(baseline_file)
        except Exception as e:
            logger.error(f"Failed to load baseline: {e}")
            sys.exit(1)
            
        logger.info(f"Baseline loaded. Contains {len(trusted_manager.state)} tracked files using {trusted_manager.algorithm}.")
        logger.info(f"Scanning current state of {target_dir}...")
        
        current_manager = BaselineManager(target_dir, algorithm=trusted_manager.algorithm)
        try:
            current_manager.generate_baseline()
        except Exception as e:
            logger.error(f"Failed to scan current directory: {e}")
            sys.exit(1)
            
        logger.info("Comparing states...")
        result = compare_baselines(trusted_manager, current_manager)
        
        # Output results
        if result.is_clean():
            logger.info("INTEGRITY VERIFIED: No unauthorized changes detected.")
        else:
            logger.warning("INTEGRITY COMPROMISED: Changes detected!")
            if result.modified:
                logger.warning(f"MODIFIED ({len(result.modified)}):")
                for f in result.modified:
                    logger.warning(f"  [~] {f}")
            if result.missing:
                logger.warning(f"MISSING ({len(result.missing)}):")
                for f in result.missing:
                    logger.warning(f"  [-] {f}")
            if result.untracked:
                logger.warning(f"UNTRACKED ({len(result.untracked)}):")
                for f in result.untracked:
                    logger.warning(f"  [+] {f}")
            sys.exit(2) # Non-zero exit code for CI/CD or scripts

if __name__ == "__main__":
    main()
