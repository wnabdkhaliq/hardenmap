HardenMap runs on **Ubuntu 24.04 LTS**.

Open a terminal and run these commands in order:

```bash
# 1. Install the tools (first time only)
sudo apt update
sudo apt install git python3 python3-venv python3-pip -y

# 2. Download the project
git clone https://github.com/wnabdkhaliq/hardenmap.git
cd hardenmap

# 3. Make a virtual environment and install the library
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 4. Run the tool
python3 hardenmap.py scan
```

When the legal notice appears, type `yes` to confirm that you are allowed to audit this machine. The scan takes about a second. The results are printed on the screen and the reports are saved in the `output/` folder.

## Installation

| Step | Command | What it does |
|---|---|---|
| 1 | `sudo apt install git python3 python3-venv python3-pip -y` | Installs Git and Python |
| 2 | `git clone https://github.com/wnabdkhaliq/hardenmap.git` | Downloads the project |
| 3 | `cd hardenmap` | Goes into the project folder |
| 4 | `python3 -m venv venv` | Makes a private Python environment |
| 5 | `source venv/bin/activate` | Turns it on. The prompt starts with `(venv)` |
| 6 | `pip install -r requirements.txt` | Installs PyYAML (needs internet) |

Run the project from your **home folder**, not from a VirtualBox shared folder. Shared folders break virtual environments and show wrong file owners which gives wrong scan results.

Each time you open a new terminal, turn the environment on again before you run the tool:

```bash
cd ~/hardenmap
source venv/bin/activate
```

## Usage

Try the commands in this order the first time:

```bash
python3 hardenmap.py --help          # see all options
python3 hardenmap.py list-rules      # show the 20 rules
python3 hardenmap.py scan --dry-run  # show what would run, without running it
python3 hardenmap.py scan            # run the audit
```

Other examples:

```bash
python3 hardenmap.py scan --format json       # save only the JSON report
python3 hardenmap.py scan --format html       # save only the HTML report
python3 hardenmap.py scan --output my_reports/   # save reports in another folder
```

| Option | Meaning |
|---|---|
| `--rules` | Folder with the rule files (default: `rules/`) |
| `--output` | Folder for the reports (default: `output/`) |
| `--format` | `json`, `html` or `both` (default: `both`) |
| `--dry-run` | Show which rules would run, without running them |
| `--target` | Local machine only (default: `localhost`). Other targets are refused |

Run the tool as a **normal user** without `sudo`. If you press **Ctrl+C**, the tool stops cleanly.

### Reading the results

Every rule shows one of four states: `PASS`, `FAIL`, `INFO` or `SKIP`. A failed rule shows the evidence and a fix suggestion. If related failed rules make an attack path, it is listed under `ATTACK PATHS FOUND` with its severity, the files involved and the MITRE ATT&CK reference. At the end you get the risk score and the names of the report files.

Example of the last lines of a scan:

```
ATTACK PATHS FOUND: 1
[CRITICAL] PATH-001  Writable script executed by root
       Linked : PERM-007 + CRON-001
       Files  : /opt/test/backup.sh
       MITRE  : T1053.003 Scheduled Task/Job: Cron

Total: 20 | Failed: 5 | Attack paths: 1
Risk score: 24  ->  HIGH
Reports saved:
  output/hardenmap_report_20261116_015626.json
  output/hardenmap_report_20261116_015626.html
```

Example of HTML version:

<img width="1210" height="662" alt="HardenMap Report AttackPath (HTML)" src="https://github.com/user-attachments/assets/e043c9da-f794-49bb-9c45-4267dd8441d8" />

### Opening the reports

Reports are saved in the `output/` folder with the date and time in the name so a new scan never overwrites an old one. Run these commands from the project folder to open the newest report.

Open the HTML report in your browser:

```bash
xdg-open $(ls -t output/*.html | head -1)
```

View the JSON report in the terminal:

```bash
less $(ls -t output/*.json | head -1)
```

## Troubleshooting

| Problem | Fix |
|---|---|
| `No module named 'yaml'` | Run `source venv/bin/activate`, then `pip install -r requirements.txt` |
| `No module named 'engine'` | Go into the project folder first: `cd ~/hardenmap` |
| `venv/bin/activate: No such file` | Make the environment: `python3 -m venv venv` |
| `Loaded 0 rules` | The `rules/` folder or its YAML files are missing |
| `out of scope` message | Only `localhost` and this machine's own hostname are allowed |
| Many `SKIP` results | A file is missing or not readable by a normal user |
