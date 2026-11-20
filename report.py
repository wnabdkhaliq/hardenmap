import csv
import html
import io
import json
import os
import socket
from datetime import datetime

BENCHMARK = "CIS Ubuntu Linux 24.04 LTS Benchmark v2.0.0 Level 1 Server (selected controls)"

POINTS = {"critical": 10, "high": 7, "medium": 4, "low": 1}

STATUS_ORDER = {"fail": 0, "info": 1, "skip": 2, "pass": 3}

CSS = """
body { font-family: Arial, sans-serif; margin: 30px; background: #f4f4f4; color: #222; }
.box { display: inline-block; padding: 12px 20px; margin: 4px; border-radius: 6px;
       background: #fff; border: 1px solid #ccc; text-align: center; }
.box b { display: block; font-size: 22px; }
table { border-collapse: collapse; width: 100%; background: #fff; }
th, td { border: 1px solid #ccc; padding: 6px 8px; text-align: left;
         vertical-align: top; font-size: 14px; }
th { background: #333; color: #fff; }
tr:hover { background-color: #f7f9fa; }
.path { background: #fff; border-left: 6px solid #999; padding: 10px; margin: 8px 0; }
.critical { border-left-color: #c0392b; }
.high { border-left-color: #e67e22; }
.medium { border-left-color: #f1c40f; }
.low { border-left-color: #3498db; }
.s-fail { background: #f8d7da; }
.s-pass { background: #d4edda; }
.s-info { background: #d6e9f8; }
.s-skip { background: #eeeeee; }
.level-critical, .level-high { color: #c0392b; }
.level-medium { color: #d68910; }
.level-low { color: #1e8449; }
"""


def calculate_score(findings, attack_paths):
    score = 0
    for f in findings:
        if f["status"] == "fail":
            score += POINTS.get(f["severity"], 0)
    for p in attack_paths:
        score += POINTS.get(p["severity"], 0)

    if score >= 35:
        level = "CRITICAL"
    elif score >= 20:
        level = "HIGH"
    elif score >= 10:
        level = "MEDIUM"
    else:
        level = "LOW"
    return score, level


def build_report_data(findings, attack_paths, version):
    score, level = calculate_score(findings, attack_paths)

    count = {"pass": 0, "fail": 0, "info": 0, "skip": 0}
    for f in findings:
        count[f["status"]] = count.get(f["status"], 0) + 1

    try:
        host_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        host_ip = "127.0.0.1"

    return {
        "tool": "HardenMap",
        "version": version,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "host": socket.gethostname(),
        "host_ip": host_ip,
        "benchmark": BENCHMARK,
        "summary": {
            "total": len(findings),
            "pass": count["pass"],
            "fail": count["fail"],
            "info": count["info"],
            "skip": count["skip"],
            "attack_paths": len(attack_paths),
            "risk_score": score,
            "risk_level": level,
        },
        "findings": findings,
        "attack_paths": attack_paths,
    }


def esc(text):
    return html.escape(str(text))


def build_html(data):
    s = data["summary"]
    out = []
    out.append("<!DOCTYPE html><html><head><meta charset='utf-8'>")
    out.append("<title>HardenMap Report</title><style>" + CSS + "</style></head><body>")
    out.append("<h1>HardenMap Report</h1>")
    host_display = esc(data["host"])
    if data.get("host_ip"):
        host_display += f" ({esc(data['host_ip'])})"
    out.append("<p>" + esc(data["benchmark"]) + "<br>Host: " + host_display
               + " | Scan time: " + esc(data["scan_time"]) + "</p>")

    level_class = "level-" + s["risk_level"].lower()
    out.append("<div>")
    out.append(f"<div class='box'>Risk score<b class='{level_class}'>"
               f"{s['risk_score']} ({s['risk_level']})</b></div>")
    for name in ("pass", "fail", "info", "skip"):
        out.append(f"<div class='box'>{name.capitalize()}<b>{s[name]}</b></div>")
    out.append(f"<div class='box'>Attack paths<b>{s['attack_paths']}</b></div>")
    out.append("</div>")

    out.append("<h2>Attack paths</h2>")
    if not data["attack_paths"]:
        out.append("<p>No attack paths found.</p>")
    for p in data["attack_paths"]:
        out.append(f"<div class='path {esc(p['severity'])}'>")
        out.append(f"<b>[{esc(p['severity'].upper())}] {esc(p['id'])} - {esc(p['name'])}</b><br>")
        out.append("Linked checks: " + esc(" + ".join(p["requires"])) + "<br>")
        if p["files"]:
            out.append("Files: " + esc(", ".join(p["files"])) + "<br>")
        out.append("Why: " + esc(p["explanation"]))
        if p["mitre"]:
            out.append("<br>MITRE ATT&CK: " + esc(p["mitre"]))
        out.append("</div>")

    out.append("<h2>Findings</h2>")
    out.append("<table><tr><th>ID</th><th>CIS ref</th><th>Title</th><th>Status</th>"
               "<th>Severity</th><th>Evidence</th><th>Fix</th></tr>")
    ordered = sorted(data["findings"], key=lambda f: STATUS_ORDER.get(f["status"], 9))
    for f in ordered:
        fix = f["fix"] if f["status"] == "fail" else ""
        out.append(f"<tr class='s-{esc(f['status'])}'>"
                   f"<td>{esc(f['id'])}</td><td>{esc(f['cis_ref'])}</td>"
                   f"<td>{esc(f['title'])}</td><td>{esc(f['status'].upper())}</td>"
                   f"<td>{esc(f['severity'])}</td><td>{esc(f['evidence'])}</td>"
                   f"<td>{esc(fix)}</td></tr>")
    out.append("</table>")

    out.append("<p><i>HardenMap is read-only. No file contents are stored in this report. "
               "Fix suggestions are text only.</i></p>")
    out.append("</body></html>")
    return "\n".join(out)


def build_csv(data):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "CIS_Ref", "Title", "Status", "Severity", "Evidence", "Fix"])
    for f in data.get("findings", []):
        writer.writerow([
            f.get("id", ""),
            f.get("cis_ref", ""),
            f.get("title", ""),
            f.get("status", "").upper(),
            f.get("severity", ""),
            f.get("evidence", ""),
            f.get("fix", "") if f.get("status") == "fail" else "",
        ])
    return output.getvalue()


def give_back_to_user(path):
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if not (uid and gid):
        return
    try:
        os.chown(path, int(uid), int(gid))
    except OSError:
        pass


def save_reports(findings, attack_paths, folder, fmt, version):
    os.makedirs(folder, exist_ok=True)
    data = build_report_data(findings, attack_paths, version)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    saved = []

    if fmt in ("json", "both", "all"):
        path = os.path.join(folder, f"hardenmap_report_{stamp}.json")
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        saved.append(path)

    if fmt in ("html", "both", "all"):
        path = os.path.join(folder, f"hardenmap_report_{stamp}.html")
        with open(path, "w") as f:
            f.write(build_html(data))
        saved.append(path)

    if fmt in ("csv", "all"):
        path = os.path.join(folder, f"hardenmap_report_{stamp}.csv")
        with open(path, "w", newline="", encoding="utf-8") as f:
            f.write(build_csv(data))
        saved.append(path)

    give_back_to_user(folder)
    for path in saved:
        give_back_to_user(path)
    return data, saved
