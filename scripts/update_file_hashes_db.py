import zipfile
import csv
import sqlite3
import argparse
import os

CSV_FILE_HASHES_URL = "https://bazaar.abuse.ch/export/csv/full/"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
DATA_DIR = os.path.join(REPO_ROOT, "data")
OUTPUT_FILE_NAME = os.path.join(DATA_DIR, "file_hashes")
CSV_HASH_INDEX = 1
CSV_SIGNATURE_INDEX = 8
RENAME_FILES = {
    "full.csv": f"{OUTPUT_FILE_NAME}.csv", # because malware bazaar exports the file as full.csv, we need to rename it
}
GENERIC_MALWARE_SIGNATURE = "GenericMalware"
CSV_COMMENT = '#'
INVALID_SIGNATURE = "n/a"


def remove_files(database_file: str, csv_file:str) -> None:
    """Remove the leftover files (if exists) (zip, csv)"""
    
    try:
        if os.path.exists(database_file):
            os.remove(database_file)
            print(f"Database zip file {database_file} removed successfully")
        else:
            print(f"Database zip file {database_file} does not exist")
            
        if os.path.exists(csv_file):
            os.remove(csv_file)
            print(f"CSV file {csv_file} removed successfully")
        else:
            print(f"CSV file {csv_file} does not exist")
    except Exception as e:
        print(f"Error removing files: {e}")
        return


def download_database_from_url(url: str, output_file: str) -> None:
    """Download the CSV database from the specified URL"""
    import requests

    print(f"Downloading database from {url}...")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    response = requests.get(url)
    response.raise_for_status()
    
    with open(output_file, 'wb') as f:
        f.write(response.content)

    print(f"Database downloaded successfully as {output_file}")


def extract_database(database_file: str, output_path: str, renames: dict[str, str]) -> None:
    """Extract the database file (assuming it might be a zip file)"""

    if not os.path.exists(database_file):
        print("Error: database zip file not found. Please download it first using -d flag.")
        raise Exception("Database zip file not found")
    
    with zipfile.ZipFile(database_file, 'r') as zip_ref:
        zip_ref.extractall(output_path)

    for file_name in renames:
        os.rename(os.path.join(output_path, file_name), os.path.join(output_path, renames[file_name]))
    
    print("Database extracted successfully")


def parse_csv_to_sqlite(csv_file: str, db_file: str) -> None:
    """Parse CSV file and extract sha256_hash and signature fields to SQLite database"""

    if not os.path.exists(csv_file):
        print("Error: csv file not found. Please download it first using -d flag.")
        raise Exception("CSV file not found")
    
    print("Parsing CSV and creating SQLite database...")
    
    # Create SQLite database and table
    os.makedirs(os.path.dirname(db_file), exist_ok=True)
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    # Drop table if it exists and create new one
    cursor.execute('''DROP TABLE IF EXISTS file_hashes''')
    cursor.execute('''CREATE TABLE file_hashes
                      (hash TEXT PRIMARY KEY, name TEXT)''')
    
    try:
        try:
            import tqdm
            progress_iter = tqdm.tqdm
        except ImportError:
            progress_iter = lambda rows: rows

        with open(csv_file, 'r', encoding='utf-8') as csvfile:
            csv_reader = csv.reader(csvfile)
            
            for row in progress_iter(csv_reader):
                # If the first value is a comment, skip it
                if row[0].startswith(CSV_COMMENT):
                    continue
                
                # The CSV is formatted in such way that we always have a " " around the values, so we wanna remove them
                sha256_hash = row[CSV_HASH_INDEX].strip().replace('"', "")
                signature = row[CSV_SIGNATURE_INDEX].strip().replace('"', "")

                if signature == INVALID_SIGNATURE:
                    signature = GENERIC_MALWARE_SIGNATURE # Some file_hashes don't have a name, but have exerted malicous behaviour
                    
                if sha256_hash and signature:
                    try:
                        cursor.execute("INSERT INTO file_hashes (hash, name) VALUES (?, ?)", 
                                         (sha256_hash, signature))
                    except sqlite3.IntegrityError:
                        print(f"Duplicate hash: {sha256_hash}")
                        continue
    except Exception as e:
        conn.rollback()
        conn.close()
        raise e
    
    conn.commit()
    conn.close()
    print("SQLite database created successfully")


def main() -> None:
    parser = argparse.ArgumentParser(description='Update hashes database (hashes)')
    parser.add_argument('-d', '--download', action='store_true', help='Download new database from URL')
    parser.add_argument('-e', '--extract', action='store_true', help='Extract the database file')
    parser.add_argument('-p', '--parse', action='store_true', help='Parse CSV to SQLite database')
    parser.add_argument('-r', '--remove_files', action='store_true', help='Remove the leftover files (if exists) (zip, csv)')
    parser.add_argument('--csv', type=str, default=f"{OUTPUT_FILE_NAME}.csv", help='Custom CSV file name (default: %(default)s)')
    parser.add_argument('--zip', type=str, default=f"{OUTPUT_FILE_NAME}.zip", help='Custom ZIP file name (default: %(default)s)')
    parser.add_argument('--db', type=str, default=f"{OUTPUT_FILE_NAME}.db", help='Custom SQLite database file name (default: %(default)s)')
    args = parser.parse_args()

    database_zip_file = args.zip
    csv_file = args.csv
    db_file = args.db

    steps = [
        (args.download, lambda: download_database_from_url(CSV_FILE_HASHES_URL, database_zip_file), "downloading database"),
        (args.extract,  lambda: extract_database(database_zip_file, os.path.dirname(database_zip_file) or ".", RENAME_FILES), "extracting database"),
        (args.parse,    lambda: parse_csv_to_sqlite(csv_file, db_file), "parsing CSV"),
        (args.remove_files, lambda: remove_files(database_zip_file, csv_file), "removing leftover files"),
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
