from backend.engine.condition_evaluator import evaluate_condition


def evaluate_group(event, group):
    """group: {"logic": "AND"|"OR", "conditions": [condition, ...]}"""
    conditions = group.get("conditions", [])
    logic = (group.get("logic") or "AND").upper()
    if not conditions:
        return False
    results = [evaluate_condition(event, c) for c in conditions]
    return all(results) if logic == "AND" else any(results)


def evaluate_condition_groups(event, structure):
    """structure: {"logic": "AND"|"OR", "groups": [group, ...]}
    Groups are combined using the top-level logic (defaults to OR of ANDs,
    matching QRadar-style rule test expressions)."""
    groups = structure.get("groups", [])
    logic = (structure.get("logic") or "OR").upper()
    if not groups:
        return False
    results = [evaluate_group(event, g) for g in groups]
    return all(results) if logic == "AND" else any(results)
