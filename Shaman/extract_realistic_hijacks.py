#!/usr/bin/env python3
"""
find_category.py

Usage:
  python find_category.py input.json
  python find_category.py input.json --category "Potential Stealthy Hijacking"
  python find_category.py input.json --out matches.json
"""

import argparse
import json
import sys
from typing import Any, Dict, List, Tuple


def load_json(path: str) -> Any:
    try:

        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON in {path}: {e}", file=sys.stderr)
        sys.exit(1)


def find_matches(data: Any, category: str) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Supports JSON shaped like:
      {
        "88": { ... "category": "Potential Stealthy Hijacking", ... },
        "89": { ... }
      }

    Returns list of (top_level_key, incident_dict).
    """
    if not isinstance(data, dict):
        print("Error: expected top-level JSON object (a dict).", file=sys.stderr)
        sys.exit(1)

    matches: List[Tuple[str, Dict[str, Any]]] = []
    for key, value in data.items():
        if isinstance(value, dict) and value.get("category") == category:
            matches.append((str(key), value))
    return matches


def main() -> None:
    parser = argparse.ArgumentParser(description="Find incidents by category in a JSON file.")
    parser.add_argument("input", help="Path to input JSON file")
    parser.add_argument(
        "--category",
        default="Potential Stealthy Hijacking",
        help='Category to match (default: "Potential Stealthy Hijacking")',
    )
    parser.add_argument("--out", help="Optional output JSON path to save matches")
    args = parser.parse_args()

    data = load_json(args.input)
    matches = find_matches(data, args.category)

    print(f'Matching category: "{args.category}"')
    print(f"Found {len(matches)} match(es).\n")

    for key, incident in matches:
        inc_id = incident.get("id", key)
        time = incident.get("time", "N/A")
        prefixes = incident.get("prefixes", [])
        print(f"- key={key} id={inc_id} time={time} prefixes={prefixes}")

    if args.out:
        out_obj = {key: incident for key, incident in matches}
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(out_obj, f, indent=2, ensure_ascii=False)
        print(f"\nSaved {len(matches)} match(es) to: {args.out}")


if __name__ == "__main__":
    main()
