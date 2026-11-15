import os
import stat
import re
import glob

def check_file_perm(rule):
    """Check that a file is not too open and is owned by the right user."""
    path = rule["target"]

    if not os.path.exists(path):
        return {"status": "skip", "evidence": f"{path} not found", "paths": []}

    try:
        info = os.stat(path)
    except PermissionError:
        return {"status": "skip", "evidence": f"cannot read {path}", "paths": []}

    actual_mode = stat.S_IMODE(info.st_mode)
    allowed_mode = int(rule["max_mode"], 8)
    expected_owner = rule.get("owner_uid", 0)

    extra_bits = actual_mode & ~allowed_mode

    problems = []
    if extra_bits:
        problems.append(f"mode is {oct(actual_mode)}, allowed {rule['max_mode']}")
    if info.st_uid != expected_owner:
        problems.append(f"owner uid is {info.st_uid}, expected {expected_owner}")

    if problems:
        return {"status": "fail", "evidence": f"{path}: " + ", ".join(problems),
                "paths": [path]}
    return {"status": "pass", "evidence": f"{path} is OK", "paths": []}

def check_file_contains(rule):
    """Look for a risky line (or a missing line) in config files."""
    pattern = re.compile(rule["pattern"], re.IGNORECASE)
    fail_if = rule.get("fail_if", "found")

    files = []
    for target in rule["targets"]:
        files += glob.glob(target)

    if not files:
        return {"status": "skip", "evidence": "config file not found", "paths": []}

    matches = []
    unreadable = []

    for path in files:
        try:
            with open(path) as f:
                for line_number, line in enumerate(f, start=1):
                    text = line.strip()
                    if text.startswith("#"):
                        continue
                    if pattern.search(text):
                        matches.append(f"{path} line {line_number}")
        except PermissionError:
            unreadable.append(path)

    if unreadable and not matches:
        return {"status": "skip", "evidence": "permission denied (run as root)", "paths": []}

    found = len(matches) > 0
    if (fail_if == "found" and found) or (fail_if == "missing" and not found):
        if found:
            evidence = "pattern found at " + ", ".join(matches)
        else:
            evidence = "required setting not found"
        paths = sorted({m.split(" line ")[0] for m in matches})
        return {"status": "fail", "evidence": evidence, "paths": paths}

    return {"status": "pass", "evidence": "no problem found", "paths": []}
