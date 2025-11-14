import requests
import os
import zipfile
import shutil
import argparse
import json
from tqdm import tqdm
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqlite
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline
from sigma.processing.resolver import ProcessingPipelineResolver

# A dict of URLs to download from, each has a list of directories to ignore
RULES_DOWNLOAD_URLS = {
    "https://github.com/mdecrevoisier/SIGMA-detection-rules/archive/refs/heads/main.zip": [
        "linux-defender",
        "cloud-azure",
    ],
    "https://github.com/SigmaHQ/sigma/tree/master/rules": [
        ".github",
        "deprecated",
        "rules/linux",
        "rules/cloud",
    ],
}
DOWNLOAD_CHUNK_SIZE = 1024 * 16  # 16 kb
DOWNLOAD_TO_FOLDER = "data"
# note about these: the script, by default will go to the folder OUTSIDE the folder where the script is
TEMP_DIR = "data/temp_sigma"
OUTPUT_FILE = "data/sigma_rules_sqlite.json"
VALID_SIGMA_RULES_EXTENSIONS = [".yml", ".yaml"]
EVENTS_TABLE = "Events"


def download_file_from_url(url: str, dest_path: str) -> bool:
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        with open(dest_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=DOWNLOAD_CHUNK_SIZE):
                if chunk:
                    f.write(chunk)

        return True
    except Exception as e:
        print(f"Error downloading {url}: {e}")

        return False


def extract_zip_file(zip_path: str, extract_to: str) -> bool:
    if not os.path.exists(zip_path):
        raise FileNotFoundError(f"Zip file not found: {zip_path}")

    try:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(extract_to)

        return True
    except Exception as e:
        print(f"Error extracting {zip_path}: {e}")


def download_sigma_rules():
    """Download Sigma rules zip files from configured URLs"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    temp_dir = os.path.join(script_dir, "..", TEMP_DIR)

    # Create temp directory
    os.makedirs(temp_dir, exist_ok=True)

    for i, (url, ignore_list) in enumerate(RULES_DOWNLOAD_URLS.items()):
        print(f"Downloading from: {url}")

        # Download zip file with unique name for each source
        zip_filename = os.path.join(temp_dir, f"sigma_rules_{i}.zip")
        if not download_file_from_url(url, zip_filename):
            print(f"Failed to download from {url}")
            continue

        print(f"Downloaded to {zip_filename}")

    print("Sigma rules download complete!")


def extract_sigma_rules():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    temp_dir = os.path.join(script_dir, "..", TEMP_DIR)
    rules_dir = os.path.join(script_dir, "..", DOWNLOAD_TO_FOLDER)

    # Create rules directory
    os.makedirs(rules_dir, exist_ok=True)

    for i, (url, ignore_list) in enumerate(RULES_DOWNLOAD_URLS.items()):
        zip_filename = os.path.join(temp_dir, f"sigma_rules_{i}.zip")

        if not os.path.exists(zip_filename):
            print(
                f"Zip file not found: {zip_filename}. Please download first using -d flag."
            )
            continue

        print(f"Extracting rules from {zip_filename}...")

        # Extract to temp directory
        extract_temp = os.path.join(temp_dir, f"extracted_{i}")
        os.makedirs(extract_temp, exist_ok=True)

        if not extract_zip_file(zip_filename, extract_temp):
            print(f"Failed to extract {zip_filename}")
            continue

        # Copy rules, excluding ignored directories
        for root, dirs, files in os.walk(extract_temp):
            # Filter out ignored directories
            dirs[:] = [d for d in dirs if d not in ignore_list]

            for file in files:
                if file.endswith(tuple(VALID_SIGMA_RULES_EXTENSIONS)):
                    src_file = os.path.join(root, file)
                    rel_path = os.path.relpath(root, extract_temp)
                    dest_dir = os.path.join(rules_dir, rel_path)
                    os.makedirs(dest_dir, exist_ok=True)

                    dest_file = os.path.join(dest_dir, file)
                    shutil.copy2(src_file, dest_file)

        print(f"Rules extracted to {rules_dir}")

    print("Sigma rules extraction complete!")


def parse_sigma_rules():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    rules_dir = os.path.join(script_dir, "..", DOWNLOAD_TO_FOLDER)
    output_file = os.path.join(script_dir, "..", OUTPUT_FILE)

    # Check if rules directory exists
    if not os.path.exists(rules_dir):
        print(f"Rules directory not found: {rules_dir}")
        print("Please download and extract rules first using -d and -e flags.")
        return

    # Set up the SQLite backend with combined pipeline
    print("Setting up SQLite backend with Sysmon and Windows pipelines...")
    piperesolver = ProcessingPipelineResolver()
    piperesolver.add_pipeline_class(sysmon_pipeline())
    piperesolver.add_pipeline_class(windows_logsource_pipeline())
    combined_pipeline = piperesolver.resolve(piperesolver.pipelines)
    sqlite_backend = sqlite.sqliteBackend(combined_pipeline)

    # Collect all Sigma rule files
    print("Collecting Sigma rule files...")
    rule_files = []
    for root, dirs, files in os.walk(rules_dir):
        for file in files:
            if file.endswith(tuple(VALID_SIGMA_RULES_EXTENSIONS)):
                rule_files.append(os.path.join(root, file))

    print(f"Found {len(rule_files)} Sigma rule files")

    # Convert rules to SQLite queries
    queries_set = set()
    failed_count = 0
    successful_count = 0

    for rule_file in tqdm(rule_files, desc="Converting rules to SQLite queries"):
        try:
            # Load the Sigma rule
            with open(rule_file, "r", encoding="utf-8") as f:
                rule_content = f.read()

            rule_collection = SigmaCollection.from_yaml(rule_content)

            # Convert to SQLite query
            sqlite_queries = sqlite_backend.convert(rule_collection)

            for sqlite_query in sqlite_queries:
                # Replace table name and add to set (automatically removes duplicates)
                query = sqlite_query.replace("<TABLE_NAME>", EVENTS_TABLE)
                queries_set.add(query)

            successful_count += 1

        except Exception:
            failed_count += 1

    queries_list = list(queries_set)

    print(f"Saving results to {output_file}...")

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(queries_list, f)

    print(f"Rules converted: {successful_count}")
    print(f"Failed to convert: {failed_count}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Update Sigma rules database")
    parser.add_argument(
        "-d", "--download", action="store_true", help="Download new database from URL"
    )
    parser.add_argument(
        "-e", "--extract", action="store_true", help="Extract the database file"
    )
    parser.add_argument(
        "-p", "--parse", action="store_true", help="Parse Sigma rules to usable format"
    )
    args = parser.parse_args()

    steps = [
        (args.download, lambda: download_sigma_rules(), "downloading sigma rules"),
        (args.extract, lambda: extract_sigma_rules(), "extracting sigma rules"),
        (args.parse, lambda: parse_sigma_rules(), "parsing sigma rules"),
    ]

    any_action = False
    for flag, func, label in steps:
        if flag:
            any_action = True
            try:
                func()
            except Exception as e:
                print(f"Error {label}: {e}")
                return

    if not any_action:
        parser.print_help()


if __name__ == "__main__":
    main()
