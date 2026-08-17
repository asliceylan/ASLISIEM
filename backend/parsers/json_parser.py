import json


def parse_json(filepath):
    """Parse a JSON file (AQL export) into a list of dict records and field names.
    Accepts: a top-level list of objects, or a top-level object containing a
    list under a common key (events/results/data/records)."""
    with open(filepath, encoding="utf-8-sig") as f:
        data = json.load(f)

    records = []
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        list_key = None
        for key in ("events", "results", "data", "records", "rows"):
            if key in data and isinstance(data[key], list):
                list_key = key
                break
        if list_key:
            records = data[list_key]
        else:
            # a single record object
            records = [data]

    # normalize: keep only dict records
    records = [r for r in records if isinstance(r, dict)]

    fieldnames = []
    seen = set()
    for r in records:
        for k in r.keys():
            if k not in seen:
                seen.add(k)
                fieldnames.append(k)

    # flatten non-primitive values to strings for storage safety, keep raw separately
    return records, fieldnames
