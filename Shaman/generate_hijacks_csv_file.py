#!/usr/bin/env python3

import json
import csv
import sys
import re


def extract_asn(asn_string):
    """
    Extract number from strings like:
    'AS5713 (Telkom SA Ltd., ZA)'
    Returns: '5713'
    """
    match = re.search(r"AS(\d+)", asn_string)
    return match.group(1) if match else None


def main(input_file, output_file):
    # Load JSON
    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        print(len(data))
    unique_pairs = set()
    rows = []
    m = 0
    n = 0

    for key, incident in data.items():
        if incident.get("category") != "Potential Stealthy Hijacking":
            continue
        m = m + 1 
        unexpected_origins = incident.get("unexpected_origins", [])
        prefixes = incident.get("prefixes", [])

        # Skip if multiple unexpected origins
        if len(prefixes) > 1 and len(unexpected_origins) > 1:
            
            n = n + 1
            continue

        asn_number = extract_asn(unexpected_origins[0])
        if not asn_number:
            continue

        time = incident.get("time", "")
        

        for prefix in prefixes:
            pair = (prefix, asn_number)

            # Deduplicate (prefix, ASN)
            if pair not in unique_pairs:
                unique_pairs.add(pair)
                rows.append({
                    "time": time,
                    "prefix": prefix,
                    "unexpected_origin_asn": asn_number
                })

    # Write CSV
    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["time", "prefix", "unexpected_origin_asn"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(rows)

    print(f"CSV file created: {output_file}")
    print(f"Total unique rows written: {len(rows)}")
    print(f"Confused incidents: {n}")
    print(m)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py input.json output.csv")
        sys.exit(1)

    input_json = sys.argv[1]
    output_csv = sys.argv[2]

    main(input_json, output_csv)
