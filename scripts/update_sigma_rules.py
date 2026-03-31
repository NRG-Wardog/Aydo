import zipfile
import os
import json
import glob
import argparse

SIGMA_RULES_URL = "https://github.com/SigmaHQ/sigma/archive/master.zip"
DOWNLOAD_CHUNK_SIZE = 8192
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
OUTPUT_DIR = os.path.join(REPO_ROOT, "data")
SIGMA_ZIP_FILE = os.path.join(OUTPUT_DIR, "sigma_rules.zip")
SIGMA_EXTRACT_DIR = os.path.join(OUTPUT_DIR, "sigma_rules")
SIGMA_QUERIES_FILE = os.path.join(OUTPUT_DIR, "sigma_queries.json")
PROCESS_MONITOR_TABLE_NAME = "Events"  # server/VM/ProcessMonitor/SqlRequests.hpp
TABLE_NAME_PLACEHOLDERS = ("<TABLE_NAME>", "Events")


def download_sigma_rules() -> bool:
    """Download Sigma rules from SigmaHQ GitHub repository."""
    try:
        import requests

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


def convert_sigma_rules() -> bool:
    """Convert all Sigma rules to SQLite queries and save as JSON array."""
    if not os.path.exists(SIGMA_EXTRACT_DIR):
        print(f"Sigma rules directory not found: {SIGMA_EXTRACT_DIR}")
        print("Please run with --download and --extract first.")
        return False
    
    try:
        from sigma.collection import SigmaCollection
        from sigma.backends.sqlite import sqlite
        from sigma.pipelines.sysmon import sysmon_pipeline
        from sigma.pipelines.windows import windows_logsource_pipeline
        from sigma.processing.resolver import ProcessingPipelineResolver

        print("Setting up pySigma pipeline...")
        # Create the pipeline resolver
        piperesolver = ProcessingPipelineResolver()
        # Add pipelines
        piperesolver.add_pipeline_class(sysmon_pipeline())  # Sysmon
        piperesolver.add_pipeline_class(windows_logsource_pipeline())  # Windows
        # Create a combined pipeline
        combined_pipeline = piperesolver.resolve(piperesolver.pipelines)
        # Instantiate backend using the combined pipeline
        sqlite_backend = sqlite.sqliteBackend(combined_pipeline)
        
        # Find all YAML rule files
        rules_pattern = os.path.join(SIGMA_EXTRACT_DIR, "**", "*.yml")
        rule_files = glob.glob(rules_pattern, recursive=True)
        
        if not rule_files:
            print("No Sigma rule files found.")
            return False
        
        print(f"Found {len(rule_files)} Sigma rule files. Converting...")
        
        queries = []
        errors = 0
        
        for rule_file in rule_files:
            try:
                with open(rule_file, "r", encoding="utf-8") as f:
                    rule_content = f.read()
                
                collection = SigmaCollection.from_yaml(rule_content)
                for rule in collection.rules:
                    try:
                        converted = sqlite_backend.convert_rule(rule)
                        level = str(rule.level) if rule.level else "unknown"


                        for query in converted:
                            if not query:
                                continue  # Skip empty queries

                            normalized = query
                            for placeholder in TABLE_NAME_PLACEHOLDERS:
                                if placeholder in normalized:
                                    normalized = normalized.replace(
                                        placeholder, PROCESS_MONITOR_TABLE_NAME
                                    )
                            queries.append({"query": normalized, "level": level})
                    except Exception as e:
                        errors += 1

                        
            except Exception as e:
                errors += 1
                continue
        
        # Save queries to JSON file
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        with open(SIGMA_QUERIES_FILE, "w", encoding="utf-8") as f:
            json.dump(queries, f)
        
        print(f"Successfully converted {len(queries)} queries (skipped {errors} rules with errors)")
        print(f"Saved to {SIGMA_QUERIES_FILE}")
        return True
        
    except Exception as e:
        print(f"Error converting Sigma rules: {e}")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Download and extract Sigma rules from SigmaHQ")
    parser.add_argument(
        "-d", "--download", action="store_true", help="Download Sigma rules from GitHub"
    )
    parser.add_argument(
        "-e", "--extract", action="store_true", help="Extract the downloaded Sigma rules"
    )
    parser.add_argument(
        "-c", "--convert", action="store_true", help="Convert Sigma rules to SQLite queries and save as JSON"
    )
    args = parser.parse_args()

    if args.download:
        if not download_sigma_rules():
            print("Download failed. Aborting.")
            return

    if args.extract:
        if not extract_sigma_rules():
            print("Extraction failed. Aborting.")
            return
    
    if args.convert:
        if not convert_sigma_rules():
            print("Conversion failed.")
            return
    
    # If no arguments provided, show help
    if not args.download and not args.extract and not args.convert:
        parser.print_help()


if __name__ == "__main__":
    main()
