import csv


def _unique_fields(headers):
    # QRadar AQL exports can contain repeated/non-semantic header values such as
    # N/A, false, 0, etc. Keep every physical column instead of letting
    # csv.DictReader overwrite duplicate keys.
    fields = []
    seen = {}
    for idx, header in enumerate(headers or []):
        label = str(header or "").strip()
        base = f"column_{idx:03d}"
        if label:
            seen[label] = seen.get(label, 0) + 1
        fields.append(base)
    return fields


def parse_csv(filepath):
    """Parse every physical QRadar CSV column without losing duplicate headers."""
    with open(filepath, newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        headers = next(reader, [])
        fields = _unique_fields(headers)
        records = []
        for row in reader:
            # Preserve every cell, including empty cells.
            padded = list(row) + [""] * max(0, len(fields) - len(row))
            record = {field: padded[i] for i, field in enumerate(fields)}
            # Preserve the original physical headers and also expose a header-based
            # view for rule evaluation. Duplicate headers are kept as lists rather
            # than silently overwriting one another.
            record["__source_headers__"] = headers
            by_header = {}
            for i, header in enumerate(headers):
                label = str(header or "").strip() or fields[i]
                value = padded[i]
                if label in by_header:
                    if not isinstance(by_header[label], list):
                        by_header[label] = [by_header[label]]
                    by_header[label].append(value)
                else:
                    by_header[label] = value
            record["__source_by_header__"] = by_header
            records.append(record)
    return records, fields
