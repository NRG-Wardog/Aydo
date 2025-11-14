import argparse
import json
import os
import re
from typing import Iterable


SQL_KEYWORDS = {
    "select",
    "from",
    "where",
    "and",
    "or",
    "join",
    "inner",
    "left",
    "right",
    "full",
    "outer",
    "cross",
    "on",
    "group",
    "by",
    "order",
    "having",
    "union",
    "all",
    "distinct",
    "into",
    "update",
    "insert",
    "delete",
    "values",
    "set",
    "as",
    "not",
    "null",
    "like",
    "in",
    "is",
    "between",
    "exists",
    "case",
    "when",
    "then",
    "end",
}


IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")


def _clean_identifier(token: str) -> str:
    parts = []
    for part in token.split("."):
        trimmed = part.strip('`"[]')
        if trimmed:
            parts.append(trimmed)
    return ".".join(parts)


def _filter_identifiers(tokens: Iterable[str]) -> list[str]:
    cleaned: list[str] = []
    for token in tokens:
        identifier = _clean_identifier(token)
        if (
            not identifier
            or identifier.isdigit()
            or identifier.lower() in SQL_KEYWORDS
            or not IDENTIFIER_RE.match(identifier)
        ):
            continue
        cleaned.append(identifier)
    return cleaned


def extract_table_names(query: str) -> list[str]:
    # Match table names after FROM, JOIN, UPDATE, INSERT INTO
    pattern = re.compile(
        r"\b(?:FROM|JOIN|UPDATE|INTO)\s+([^\s;,)]+)",
        re.IGNORECASE,
    )

    raw_tables = [match.group(1) for match in pattern.finditer(query)]
    return _filter_identifiers(raw_tables)


def extract_column_names(query: str) -> list[str]:
    segment = r"(?:`[^`]+`|\[[^\]]+\]|\"[^\"]+\"|[A-Za-z_][A-Za-z0-9_]*)"
    column_pattern = re.compile(
        rf"(?P<token>{segment}(?:\.{segment})*)\s*(?="
        r"=|!=|<>|<=|>=|<|>|\b(?:NOT\s+)?LIKE\b|\b(?:NOT\s+)?IN\b|"
        r"\bIS(?:\s+NOT)?\b|\b(?:NOT\s+)?BETWEEN\b|\bGLOB\b|\bREGEXP\b)",
        re.IGNORECASE,
    )

    raw_columns = [match.group("token") for match in column_pattern.finditer(query)]
    return _filter_identifiers(raw_columns)


def main() -> None:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_input = os.path.join(script_dir, "..", "data", "sigma_rules_sqlite.json")

    parser = argparse.ArgumentParser(
        description="Show all tables used in Sigma SQLite queries JSON."
    )
    parser.add_argument(
        "-i",
        "--input",
        default=default_input,
        help=f"Path to sigma_rules_sqlite.json (default: {default_input})",
    )
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Input file not found: {args.input}")
        print("Run update_sigma_rules.py with -p to generate it first.")
        return

    with open(args.input, "r", encoding="utf-8") as f:
        queries = json.load(f)

    if not isinstance(queries, list):
        print("Expected a JSON array of query strings.")
        return

    table_set: set[str] = set()
    column_set: set[str] = set()
    for q in queries:
        if not isinstance(q, str):
            continue
        table_set.update(extract_table_names(q))
        column_set.update(extract_column_names(q))

    if table_set:
        print("Tables used in queries:")
        for t in sorted(table_set):
            print(f"- {t}")
    else:
        print("No table names detected in queries.")

    print()
    if column_set:
        print("Columns used in queries:")
        for c in sorted(column_set):
            print(f"- {c}")
    else:
        print("No column names detected in queries.")


if __name__ == "__main__":
    main()
