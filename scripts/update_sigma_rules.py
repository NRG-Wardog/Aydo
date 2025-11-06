import zipfile
import os
import requests
import argparse

SIGMA_RULES_URL = "https://github.com/SigmaHQ/sigma/archive/master.zip"
DOWNLOAD_CHUNK_SIZE = 8192
OUTPUT_DIR = "../data"
SIGMA_ZIP_FILE = f"{OUTPUT_DIR}/sigma_rules.zip"
SIGMA_EXTRACT_DIR = f"{OUTPUT_DIR}/sigma_rules"


def download_sigma_rules() -> bool:
    """Download Sigma rules from SigmaHQ GitHub repository."""
    try:
        print(f"Downloading Sigma rules from {SIGMA_RULES_URL}...")
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        response = requests.get(SIGMA_RULES_URL, stream=True)
        response.raise_for_status()
        
        with open(SIGMA_ZIP_FILE, "wb") as f:
            for chunk in response.iter_content(chunk_size=DOWNLOAD_CHUNK_SIZE):
                if chunk:
                    f.write(chunk)
        
        print(f"Successfully downloaded Sigma rules to {SIGMA_ZIP_FILE}")
        return True
    except Exception as e:
        print(f"Error downloading Sigma rules: {e}")
        return False


def extract_sigma_rules() -> bool:
    """Extract the downloaded Sigma rules zip file."""
    if not os.path.exists(SIGMA_ZIP_FILE):
        print(f"Zip file not found: {SIGMA_ZIP_FILE}")
        return False
    
    try:
        print(f"Extracting Sigma rules to {SIGMA_EXTRACT_DIR}...")
        os.makedirs(SIGMA_EXTRACT_DIR, exist_ok=True)
        
        with zipfile.ZipFile(SIGMA_ZIP_FILE, "r") as zip_ref:
            zip_ref.extractall(SIGMA_EXTRACT_DIR)
        
        print(f"Successfully extracted Sigma rules to {SIGMA_EXTRACT_DIR}")
        return True
    except Exception as e:
        print(f"Error extracting Sigma rules: {e}")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Download and extract Sigma rules from SigmaHQ")
    parser.add_argument(
        "-d", "--download", action="store_true", help="Download Sigma rules from GitHub"
    )
    parser.add_argument(
        "-e", "--extract", action="store_true", help="Extract the downloaded Sigma rules"
    )
    args = parser.parse_args()

    if args.download:
        download_sigma_rules()

    if args.extract:
        extract_sigma_rules()
    
    # If no arguments provided, show help
    if not args.download and not args.extract:
        parser.print_help()


if __name__ == "__main__":
    main()
