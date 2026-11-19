# HardenMap CIS Hardening Notes

## Overview
HardenMap audits Ubuntu 24.04 LTS against selected CIS Level 1 Server controls and links related findings into attack paths without modifying system files.

## Key Audit Areas
- **SSH Configuration:** Disabling root login, empty passwords, and host-based authentication in `/etc/ssh/sshd_config`.
- **Scheduled Tasks (Cron):** Ensuring cron scripts executed by `root` are owned by `root` and not world/group writable.
- **SUID Binaries:** Reviewing SUID binaries under `/usr/bin`, `/usr/sbin`, and `/usr/local` and removing unnecessary SUID bits (`chmod u-s <file>`).

## Manual Remediation Reminder
Always back up configuration files (such as `/etc/ssh/sshd_config`) and test changes in a non-production VM before applying hardening fixes.
