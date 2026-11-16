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

When the legal notice appears, type `yes` to confirm that you are allowed to audit this machine. The scan usually takes about a second. It is fast because HardenMap does not use the internet or any network connection. It only reads files on the local machine (file permissions, config files, cron jobs and SUID files) and checks the 20 rules in `rules/`. The results are printed on the screen and the reports are saved in the `output/` folder.

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

Example of **HTML** version:

<img width="1210" height="662" alt="HardenMap Report AttackPath (HTML)" src="https://github.com/user-attachments/assets/e043c9da-f794-49bb-9c45-4267dd8441d8" />

Example of **JSON** version:

<img width="618" height="450" alt="HardenMap Report AttackPath (JSON)" src="https://github.com/user-attachments/assets/0ae492af-e5d8-4f4e-9f1e-9cce0d284a21" />

<img width="846" height="202" alt="HardenMap Report AttackPath2 (JSON)" src="https://github.com/user-attachments/assets/3bddd1c8-97cd-4c4c-be39-f97e5d471386" />

## Default Ubuntu vs hardened Ubuntu

On a default Ubuntu 24.04 install, the first scan shows **4 FAIL** results. This is expected and is not a bug in the tool. Ubuntu's default permissions are more open than CIS Level 1 asks for:

| Rule | File | Ubuntu default | CIS Level 1 asks for |
|---|---|---|---|
| PERM-011 | /etc/crontab | 0644 | 0600 |
| PERM-012 | /etc/cron.d | 0755 | 0700 |
| PERM-013 | /etc/cron.daily | 0755 | 0700 |
| SSH-003 | /etc/ssh/sshd_config | 0644 | 0600 |

Other users cannot write to these files so the risk is information exposure: any user on the machine can read the cron schedule and the SSH settings.

**Before (default Ubuntu):** 4 FAIL, risk score 10 (MEDIUM)

<img width="1225" height="610" alt="HardenMap Report (HTML)" src="https://github.com/user-attachments/assets/fef33661-14d8-4214-b837-54254091eb27" />

**After hardening:** 0 FAIL, risk score 0 (LOW). This scan was run with `sudo` because a hardened system hides these files from normal users.

<img width="1210" height="609" alt="HardenMap Scan (0 fail) - HTML" src="https://github.com/user-attachments/assets/2b68ce7c-13f3-4312-a235-605f9abf5612" />

HardenMap never changes permissions. These commands are only an example of applying the fix suggestions:

```bash
sudo chmod 600 /etc/crontab
sudo chmod 700 /etc/cron.d /etc/cron.daily
sudo chmod 600 /etc/ssh/sshd_config
sudo venv/bin/python hardenmap.py scan
```

To go back to the Ubuntu defaults:

```bash
sudo chmod 644 /etc/crontab /etc/ssh/sshd_config
sudo chmod 755 /etc/cron.d /etc/cron.daily
```

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
Press `q` to exit from the JSON report in the terminal.

## Troubleshooting

| Problem | Fix |
|---|---|
| `No module named 'yaml'` | Run `source venv/bin/activate`, then `pip install -r requirements.txt` |
| `No module named 'engine'` | Go into the project folder first: `cd ~/hardenmap` |
| `venv/bin/activate: No such file` | Make the environment: `python3 -m venv venv` |
| `Loaded 0 rules` | The `rules/` folder or its YAML files are missing |
| `out of scope` message | Only `localhost` and this machine's own hostname are allowed |
| Many `SKIP` results | A file is missing or not readable by a normal user |
