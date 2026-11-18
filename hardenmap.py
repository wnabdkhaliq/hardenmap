import argparse
import sys
import socket

from engine import load_rules, run_rules
from linker import load_path_rules, link_paths
from report import save_reports

VERSION = "1.0.0"

DISCLAIMER = """
==============================================================
 HardenMap - LEGAL NOTICE
==============================================================
This tool is for AUTHORIZED security auditing only.
Use it only on systems you own or have written permission to audit.
Unauthorized access to computer systems is an offence under the
Computer Crimes Act 1997 (Malaysia).
You are responsible for how you use this tool.
This tool is read-only. It does not change any system setting.
==============================================================
"""


LOCAL_TARGETS = ("localhost", "127.0.0.1")


def check_scope(target):
    allowed = LOCAL_TARGETS + (socket.gethostname(),)
    if target not in allowed:
        print(f"Target '{target}' is out of scope. HardenMap only audits the local machine.")
        sys.exit(1)


def show_disclaimer_and_confirm():
    print(DISCLAIMER)
    answer = input("Do you have authorization to audit this machine? (yes/no): ")
    if answer.strip().lower() != "yes":
        print("Authorization not confirmed. Exiting.")
        sys.exit(1)


def run_scan(args):
    rules = load_rules(args.rules)
    print(f"Loaded {len(rules)} rules from {args.rules}")
    print(f"Target scope: {args.target} (local machine only)")

    if args.dry_run:
        print("Dry run: these rules would run, but no checks are run.")
        for rule in rules:
            print(f"  {rule['id']}  {rule['title']}")
        return

    findings = run_rules(rules)

    for f in findings:
        print(f"[{f['status'].upper():4}] {f['id']}  {f['title']}  ({f['severity']})")
        print(f"       Evidence: {f['evidence']}")
        if f["status"] == "fail":
            print(f"       Fix     : {f['fix']}")

    path_rules = load_path_rules(args.rules)
    attack_paths = link_paths(findings, path_rules)

    print(f"\nATTACK PATHS FOUND: {len(attack_paths)}")
    for p in attack_paths:
        print(f"[{p['severity'].upper()}] {p['id']}  {p['name']}")
        print(f"       Linked : {' + '.join(p['requires'])}")
        if p["files"]:
            print(f"       Files  : {', '.join(p['files'])}")
        print(f"       Why    : {p['explanation']}")
        if p["mitre"]:
            print(f"       MITRE  : {p['mitre']}")

    total_fail = sum(1 for f in findings if f["status"] == "fail")
    print(f"\nTotal: {len(findings)} | Failed: {total_fail} | Attack paths: {len(attack_paths)}")

    data, saved = save_reports(findings, attack_paths, args.output, args.format, VERSION)
    print(f"Risk score: {data['summary']['risk_score']}  ->  {data['summary']['risk_level']}")
    print("Reports saved:")
    for path in saved:
        print(f"  {path}")


def list_rules(args):
    rules = load_rules(args.rules)
    for rule in rules:
        print(f"{rule['id']:10} {rule['severity']:8} {rule['title']}")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="hardenmap",
        description="HardenMap - read-only audit tool for Ubuntu 24.04 (CIS Benchmark)",
        epilog=(
            "Examples:\n"
            "  python3 hardenmap.py scan\n"
            "  python3 hardenmap.py scan --dry-run\n"
            "  python3 hardenmap.py list-rules"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"HardenMap {VERSION}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_cmd = subparsers.add_parser("scan", help="audit this machine")
    scan_cmd.add_argument("--rules", default="rules/",
                          help="folder with the rule files (default: rules/)")
    scan_cmd.add_argument("--output", default="output/",
                          help="folder to save reports (default: output/)")
    scan_cmd.add_argument("--dry-run", action="store_true",
                          help="show what would run, but do not run any checks")
    scan_cmd.add_argument("-y", "--yes", action="store_true",
                          help="confirm authorization automatically without interactive prompt")
    scan_cmd.add_argument("--format", choices=["json", "html", "both"], default="both",
                          help="report format to save (default: both)")
    scan_cmd.add_argument("--target", default="localhost",
                          help="target to audit, local machine only (default: localhost)")
    scan_cmd.set_defaults(func=run_scan)

    list_cmd = subparsers.add_parser("list-rules", help="show all loaded rules")
    list_cmd.add_argument("--rules", default="rules/",
                          help="folder with the rule files (default: rules/)")
    list_cmd.set_defaults(func=list_rules)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "scan":
            check_scope(args.target)
            if not getattr(args, "yes", False):
                show_disclaimer_and_confirm()
            else:
                print(DISCLAIMER)
                print("Authorization auto-confirmed via --yes flag.")
        args.func(args)
    except KeyboardInterrupt:
        print("\nStopped by user (Ctrl+C). No changes were made.")
        sys.exit(130)


if __name__ == "__main__":
    main()
