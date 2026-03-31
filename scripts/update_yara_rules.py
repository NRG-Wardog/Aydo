import zipfile
import os
import argparse
import subprocess
import shutil

# A list of sources (zip files), and in each source, a list of folders to ignore
# ** garbage in garbage out: if you put a bad list, you get a bad result (maybe not even compile) **
YARA_RULES_SOURCES_AND_FOLDERS_TO_IGNORE = {
    "https://github.com/Yara-Rules/rules/archive/master.zip": ["deprecated"] # it's a decent list, that wasn't updated to yara-x, so a modification is needed before compilation (looka t the errors)
}
DOWNLOAD_CHUNK_SIZE = 8192
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
OUTPUT_DIR = os.path.join(REPO_ROOT, "data")
COMPILED_YARA_RULES_FILE = os.path.join(OUTPUT_DIR, "compiled_yara_rules.yrc")


def download_file_from_url(url: str, dest_path: str) -> bool:
    try:
        import requests

        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
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
        os.makedirs(extract_to, exist_ok=True)
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(extract_to)

        return True
    except Exception as e:
        print(f"Error extracting {zip_path}: {e}")
        return False


def download_yara_rules() -> bool:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    all_succeeded = True

    for i, (url, folders_to_ignore) in enumerate(
        YARA_RULES_SOURCES_AND_FOLDERS_TO_IGNORE.items()
    ):
        print(f"Downloading YARA rules from {url}...")

        file_path = os.path.join(OUTPUT_DIR, f"yara_rules_{i}.zip")
        if not download_file_from_url(url, file_path):
            print(f"Skipping {url} due to download failure")
            all_succeeded = False
            continue

        output_dir = os.path.join(OUTPUT_DIR, f"yara_rules_{i}")
        if not extract_yara_rules(file_path, output_dir, folders_to_ignore):
            print(f"Skipping extraction for {file_path}")
            all_succeeded = False

    return all_succeeded


def extract_yara_rules(
    file_path: str, output_dir: str, folders_to_ignore: list
) -> bool:
    if not extract_zip_file(file_path, output_dir):
        return False

    for folder in folders_to_ignore:
        folder_path = os.path.join(output_dir, folder)

        if os.path.exists(folder_path):
            print(f"Removing {folder_path}...")
            if os.path.isdir(folder_path):
                shutil.rmtree(folder_path)
            else:
                os.remove(folder_path)

    return True


def extract_yara_rules_batch() -> bool:
    all_succeeded = True

    for i, (url, folders_to_ignore) in enumerate(
        YARA_RULES_SOURCES_AND_FOLDERS_TO_IGNORE.items()
    ):
        file_path = os.path.join(OUTPUT_DIR, f"yara_rules_{i}.zip")
        output_dir = os.path.join(OUTPUT_DIR, f"yara_rules_{i}")
        if not extract_yara_rules(file_path, output_dir, folders_to_ignore):
            print(f"Skipping extraction for {file_path}")
            all_succeeded = False

    return all_succeeded


def compile_yara_rules() -> None:
    """Compile YARA rules using the yr CLI tool (yara-x)."""
    print("Compiling YARA rules...")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    compiled_count = 0
    for i in range(len(YARA_RULES_SOURCES_AND_FOLDERS_TO_IGNORE)):
        extract_dir = os.path.join(OUTPUT_DIR, f"yara_rules_{i}")

        if not os.path.exists(extract_dir):
            print(f"Skipping {extract_dir} (does not exist)")
            continue

        # Search for index.yar file
        index_yar_path = None
        for root, dirs, files in os.walk(extract_dir):
            if "index.yar" in files:
                index_yar_path = os.path.join(root, "index.yar")
                break

        if not index_yar_path:
            print(f"No index.yar found in {extract_dir}")
            continue

        compiled_output = os.path.join(
            OUTPUT_DIR, f"compiled_yara_rules_file_{compiled_count}.yrc"
        )
        index_yar_dir = os.path.dirname(index_yar_path)

        try:
            cmd = [
                "yr",
                "compile",
                "--relaxed-re-syntax",
                "index.yar",
                "-o",
                compiled_output,
            ]
            print(f"Running command: {' '.join(cmd)} (cwd: {index_yar_dir})")

            subprocess.run(
                cmd, cwd=index_yar_dir, capture_output=True, text=True, check=True
            )
            print(f"Successfully compiled YARA rules to {compiled_output}")
            compiled_count += 1

        except Exception as e:
            print(f"Error compiling YARA rules from {index_yar_path}: {e}")

    print(f"Compiled {compiled_count} YARA rule file(s)")


def remove_downloaded_zip_files() -> None:
    for i in range(len(YARA_RULES_SOURCES_AND_FOLDERS_TO_IGNORE)):
        zip_file_path = os.path.join(OUTPUT_DIR, f"yara_rules_{i}.zip")
        if os.path.exists(zip_file_path):
            print(f"Removing {zip_file_path}...")
            os.remove(zip_file_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Update YARA rules database")
    parser.add_argument(
        "-d", "--download", action="store_true", help="Download new database from URL"
    )
    parser.add_argument(
        "-e", "--extract", action="store_true", help="Extract the database file"
    )
    parser.add_argument(
        "-c", "--compile", action="store_true", help="compile YARA rules"
    )
    parser.add_argument(
        "-r",
        "--remove_files",
        action="store_true",
        help="Remove the leftover files (if exists) (zip, csv)",
    )
    args = parser.parse_args()

    if args.download:
        print("Downloading YARA rules...")
        try:
            if not download_yara_rules():
                print("One or more YARA downloads or extractions failed.")
        except Exception as e:
            print(f"Failed to download YARA rules: {e}")

    if args.extract:
        print("Extracting YARA rules...")
        try:
            if not extract_yara_rules_batch():
                print("One or more YARA extractions failed.")
        except Exception as e:
            print(f"Failed to extract YARA rules: {e}")

    if args.compile:
        print("Compiling YARA rules...")
        try:
            compile_yara_rules()
        except Exception as e:
            print(f"Failed to compile YARA rules: {e}")

    if args.remove_files:
        print("Removing leftover files...")
        try:
            remove_downloaded_zip_files()
        except Exception as e:
            print(f"Failed to remove leftover files: {e}")


if __name__ == "__main__":
    main()
