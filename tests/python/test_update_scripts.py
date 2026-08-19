import importlib.util
import json
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_script(name: str):
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


hashes = load_script("update_file_hashes_db")
signatures = load_script("update_file_signatures_db")
yara = load_script("update_yara_rules")
sigma = load_script("update_sigma_rules")


class HashDatabaseTests(unittest.TestCase):
    def test_csv_is_normalized_and_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv_path = root / "hashes.csv"
            db_path = root / "hashes.db"
            csv_path.write_text(
                "# comment\n"
                'x,"abc",x,x,x,x,x,x,"n/a"\n'
                'x,"abc",x,x,x,x,x,x,"Duplicate"\n'
                'x,"def",x,x,x,x,x,x,"NamedThreat"\n',
                encoding="utf-8",
            )

            hashes.parse_csv_to_sqlite(str(csv_path), str(db_path))

            with sqlite3.connect(db_path) as connection:
                rows = connection.execute(
                    "SELECT hash, name FROM file_hashes ORDER BY hash"
                ).fetchall()
            self.assertEqual(
                rows,
                [("abc", "GenericMalware"), ("def", "NamedThreat")],
            )


class SignatureDatabaseTests(unittest.TestCase):
    def test_parser_separates_simple_and_complex_signatures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "main.ndb"
            output = root / "signatures.json"
            source.write_text(
                "Simple:0:*:AABBCC\n"
                "Complex:0:*:AA??CC\n"
                "malformed\n",
                encoding="utf-8",
            )

            signatures.parse_database(str(source), str(output))

            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8")),
                {
                    "simple": {"AABBCC": "Simple"},
                    "complex": {"AA??CC": "Complex"},
                },
            )

    def test_parse_line_rejects_missing_fields(self):
        with self.assertRaises(ValueError):
            signatures.parse_line("invalid")


class ArchiveTests(unittest.TestCase):
    def test_yara_archive_extracts_and_removes_ignored_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "rules.zip"
            output = root / "rules"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("active/index.yar", "rule active { condition: true }")
                handle.writestr("deprecated/old.yar", "rule old { condition: true }")

            self.assertTrue(
                yara.extract_yara_rules(str(archive), str(output), ["deprecated"])
            )
            self.assertTrue((output / "active" / "index.yar").exists())
            self.assertFalse((output / "deprecated").exists())

    def test_sigma_extract_requires_an_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            old_zip = sigma.SIGMA_ZIP_FILE
            try:
                sigma.SIGMA_ZIP_FILE = str(Path(directory) / "missing.zip")
                self.assertFalse(sigma.extract_sigma_rules())
            finally:
                sigma.SIGMA_ZIP_FILE = old_zip


if __name__ == "__main__":
    unittest.main()
