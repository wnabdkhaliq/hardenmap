import os
import stat
import re
import glob

def check_file_perm(rule):
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


def check_cron_scripts(rule):
    scripts = {}  

    cron_files = []
    for target in rule["targets"]:
        cron_files += glob.glob(target)

    for cron_file in cron_files:
        try:
            with open(cron_file) as f:
                for line in f:
                    text = line.strip()
                    if not text or text.startswith("#"):
                        continue
                    parts = text.split()
                    if len(parts) < 7:
                        continue
                    user = parts[5]
                    if user != "root":
                        continue
                    for word in parts[6:]:
                        if word.startswith("/") and os.path.isfile(word):
                            scripts[word] = cron_file
        except PermissionError:
            continue

    for folder in rule.get("script_dirs", []):
        try:
            names = os.listdir(folder)
        except (FileNotFoundError, PermissionError):
            continue
        for name in names:
            full_path = os.path.join(folder, name)
            if os.path.isfile(full_path):
                scripts[full_path] = folder

    if not scripts:
        return {"status": "pass", "evidence": "no scripts run by root from cron", "paths": []}

    evidence = f"{len(scripts)} script(s) run by root from cron"
    return {"status": "info", "evidence": evidence, "paths": sorted(scripts)}


def check_find_files(rule):
    condition = rule["condition"]
    status_if_found = rule.get("status_if_found", "fail")

    found = []

    for folder in rule["search_dirs"]:
        for root, subfolders, files in os.walk(folder):
            for name in files:
                full_path = os.path.join(root, name)

                if os.path.islink(full_path):
                    continue

                try:
                    info = os.lstat(full_path)
                except OSError:
                    continue

                if not stat.S_ISREG(info.st_mode):
                    continue

                if condition == "world_writable" and info.st_mode & stat.S_IWOTH:
                    found.append(full_path)
                elif condition == "suid" and info.st_mode & stat.S_ISUID:
                    found.append(full_path)

    if not found:
        return {"status": "pass", "evidence": "no matching files found", "paths": []}

    examples = ", ".join(found[:3])
    evidence = f"{len(found)} file(s) found, for example: {examples}"
    return {"status": status_if_found, "evidence": evidence, "paths": sorted(found)}
