import glob
import os
import yaml

from checks import check_file_perm

CHECK_FUNCTIONS = {
    "file_perm": check_file_perm,
}


def load_rules(folder):
    """Read every checks*.yaml file in the rules folder."""
    rules = []
    for file_path in sorted(glob.glob(os.path.join(folder, "checks*.yaml"))):
        with open(file_path) as f:
            rules += yaml.safe_load(f)
    return rules


def run_rules(rules):
    """Run each rule and collect the results."""
    findings = []
    for rule in rules:
        check_function = CHECK_FUNCTIONS.get(rule["type"])
        if check_function is None:
            result = {"status": "skip", "evidence": "unknown check type", "paths": []}
        else:
            result = check_function(rule)

        findings.append({
            "id": rule["id"],
            "title": rule["title"],
            "cis_ref": rule.get("cis_ref", ""),
            "severity": rule["severity"],
            "fix": rule.get("fix", ""),
            "status": result["status"],
            "evidence": result["evidence"],
            "paths": result["paths"],
        })
    return findings
