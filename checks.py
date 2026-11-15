import os
import stat

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
