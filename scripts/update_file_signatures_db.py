import json
import argparse
import os
import subprocess

SEPERATOR = ':'
NAME_INDEX = 0
SIGNATURE_INDEX = 3
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
DATA_DIR = os.path.join(REPO_ROOT, "data")
DATABASE_FILE_URL = "https://database.clamav.net/main.cvd"
DATABASE_FILE_NAME = os.path.join(DATA_DIR, "main.cvd")
EXTRACT_DATABASE_FILE_TO = os.path.join(DATA_DIR, "file_signatures")
SIGTOOL_PATH = os.path.expandvars("%USERPROFILE%\\Downloads\\clamav-1.4.3.win.x64\\clamav-1.4.3.win.x64\\sigtool.exe")
DATABASE_FILE = "main.ndb"
OUTPUT_FILE = os.path.join(DATA_DIR, "file_signatures.json")
SIGNATURE_WILDCARDS = ["*", "?", "|", "(", ")", "{", "}", "/"]


def extract_database(database_file: str, output_path: str) -> None:
    """Extract the database file using sigtool"""
    
    print(f"Extracting database from {database_file} to {output_path}...")
    
    if not os.path.exists(database_file):
        print("Error: database file not found. Please download it first using -d flag.")
        raise Exception("Database file not found")

    if not os.path.exists(output_path):
        os.makedirs(output_path)

    subprocess.run([SIGTOOL_PATH, "--unpack", database_file], cwd=output_path, check=True)

    print(f"Database extracted successfully to {output_path}")


def does_signature_contain_wildcard(signature: str) -> bool:
    return any(wildcard in signature for wildcard in SIGNATURE_WILDCARDS)

def parse_database(database_file: str, output_file_path: str) -> None:
    """Parse the database file and extract the signatures"""
    
    print(f"Parsing database from {database_file}...")
    
    if not os.path.exists(database_file):
        print("Error: database file not found. Please extract it first using -e flag.")
        raise Exception("Database file not found")
    
    signature_name_map = {
        "simple": {},
        "complex": {}
    }

    with open(database_file, 'r') as f:
        lines = f.readlines()

        for line_number, line in enumerate(lines, start=1):
            try:
                name, signature = parse_line(line)
            except ValueError as e:
                print(f"Skipping malformed line {line_number}: {e}")
                continue

            signature = signature.strip() # Remove new line character from the end of the signature

            # Differentiate between simple and complex signatures
            if does_signature_contain_wildcard(signature):
                signature_name_map["complex"][signature] = name
            else:
                signature_name_map["simple"][signature] = name

    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
    with open(output_file_path, 'w') as f:
        json.dump(signature_name_map, f)

    print(f"Database parsed successfully to {output_file_path}")


def parse_line(line: str) -> tuple[str, str]:
    parts = line.split(SEPERATOR)
    if len(parts) <= SIGNATURE_INDEX:
        raise ValueError(
            f"expected at least {SIGNATURE_INDEX + 1} fields, got {len(parts)}"
        )

    name = parts[NAME_INDEX]
    signature = parts[SIGNATURE_INDEX]

    return name, signature


def main() -> None:
    parser = argparse.ArgumentParser(description='Update signatures database (signatures)')
    parser.add_argument('-d', '--download', action='store_true', help='Download new database from URL')
    parser.add_argument('-e', '--extract', action='store_true', help='Extract the database file')
    parser.add_argument('-p', '--parse', action='store_true', help='Parse CSV to SQLite database')
    parser.add_argument('-r', '--remove_files', action='store_true', help='Remove the leftover files (if exists) (zip, csv)')
    args = parser.parse_args()

    def download_step():
        print("\n\n=======================================")
        print("CAN NO LONGER DOWNLOAD THE DATABASE!")
        print("CalmAV has blocked the option to download")
        print("the database using a script. Please download")
        print("the database manually from the following URL:")
        print(DATABASE_FILE_URL)
        print("=======================================\n\n")

    steps = [
        (args.download, download_step, "downloading database"),
        (args.extract,  lambda: extract_database(DATABASE_FILE_NAME, EXTRACT_DATABASE_FILE_TO), "extracting database"),
        (args.parse,    lambda: parse_database(os.path.join(EXTRACT_DATABASE_FILE_TO, DATABASE_FILE), OUTPUT_FILE), "parsing database"),
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


if __name__ == '__main__':
  main()
