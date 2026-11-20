import os
import yaml

# used to sort matched attack paths from highest to lowest severity
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def load_path_rules(folder):
    file_path = os.path.join(folder, "paths.yaml")
    if not os.path.exists(file_path):
        return []
    with open(file_path) as f:
        # return empty list if the yaml file is blank
        return yaml.safe_load(f) or []


def link_paths(findings, path_rules):
    triggered = {}
    for finding in findings:
        if finding["status"] == "fail" or (finding["status"] == "info" and finding["paths"]):
            triggered[finding["id"]] = finding

    results = []
    for rule in path_rules:
        needed = rule["requires"]

        # skip unless every required check was triggered
        if not all(rule_id in triggered for rule_id in needed):
            continue

        files = []
        if rule.get("same_path"):
            shared = set(triggered[needed[0]]["paths"])
            for rule_id in needed[1:]:
                shared = shared & set(triggered[rule_id]["paths"])
            if not shared:
                continue
            files = sorted(shared)

        results.append({
            "id": rule["id"],
            "name": rule["name"],
            "severity": rule["severity"],
            "requires": needed,
            "files": files,
            "explanation": rule["explanation"],
            "mitre": rule.get("mitre", ""),
        })

    results.sort(key=lambda p: SEVERITY_ORDER.get(p["severity"], 9))
    return results
