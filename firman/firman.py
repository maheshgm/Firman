from .gen_config import gen_config
import logging
import os
import argparse

logger = logging.getLogger("firman")

def main():
    parser = argparse.ArgumentParser(description="Generate configuration for binary analysis")
    parser.add_argument("filepath", type=str, help="Path to the binary file")
    args = parser.parse_args()

    if not os.path.exists(args.filepath):
        logger.error(f"File {args.filepath} does not exist.")
        exit(1)

    gen_config(args.filepath)

if __name__ == "__main__": 
    main()
