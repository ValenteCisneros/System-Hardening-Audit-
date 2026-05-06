# System Hardening & Audit Tool

> **Automated security auditing for Linux servers — aligned with ISO/IEC 27001 and the Principle of Least Privilege.**

[![Shell Script](https://img.shields.io/badge/Shell-Bash-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![ISO 27001](https://img.shields.io/badge/Aligned-ISO%2027001-blue?style=flat-square)](https://www.iso.org/isoiec-27001-information-security.html)
[![CIS Benchmark](https://img.shields.io/badge/Reference-CIS%20Benchmark-orange?style=flat-square)](https://www.cisecurity.org/)

---

## Overview

`audit.sh` is a Bash script that performs a structured security audit on a freshly deployed Linux server. It checks six critical control domains, generates a color-coded terminal report, and saves a timestamped report file for documentation and compliance evidence.

This project was built to reinforce hands-on knowledge of:

- **Bash scripting** — control flow, file parsing, process substitution, `stat`, `awk`, `find`, `ss`
- **Linux system administration** — users, groups, permissions, SSH, firewalls, logging daemons
- **Security governance** — ISO/IEC 27001 controls, CIS Linux Benchmark, Least Privilege principle

---

## What It Audits

| # | Domain | ISO 27001 Control | Description |
|---|--------|-------------------|-------------|
| 1 | Users & Privileges | A.9.2 — User access management | Empty passwords, UID 0 accounts, sudo members, password aging |
| 2 | Firewall | A.13.1 — Network security | UFW/IPTables state, high-risk exposed ports |
| 3 | File Permissions | A.9.4.1 — Access restriction | `/etc/shadow`, `/etc/sudoers`, SUID/SGID binaries, world-writable files |
| 4 | SSH Hardening | A.9.4.2 — Secure log-on | Root login, password auth, empty passwords, MaxAuthTries |
| 5 | Patch Management | A.12.6 — Vulnerability management | Pending updates, pending security patches |
| 6 | Audit Logging | A.12.4 — Logging & monitoring | `auditd`, `rsyslog`, log file existence |

---

## Usage

### Requirements
- Linux (Debian/Ubuntu, RHEL/CentOS, or compatible)
- Bash 4.0+
- Root / sudo privileges

### Run

```bash
# Clone the repo
git clone https://github.com/<your-username>/system-hardening-audit.git
cd system-hardening-audit

# Make executable
chmod +x audit.sh

# Run as root
sudo ./audit.sh
```

### Output

```
╔═══════════════════════════════════════════════════════╗
║       System Hardening & Audit Tool  v1.0.0           ║
║   ISO 27001 · CIS Benchmark · Least Privilege         ║
╚═══════════════════════════════════════════════════════╝

  Host   : my-linux-server
  Kernel : 6.5.0-28-generic
  Date   : Wed May 06 12:00:00 UTC 2026

══════════════════════════════════════════════════════
  CHECK 1 · USER & PRIVILEGE AUDIT (ISO 27001 A.9.2)
══════════════════════════════════════════════════════
  [INFO] Searching for empty-password accounts...
  [PASS] No empty-password accounts found
  [PASS] root is the only UID 0 account
  [WARN] Users with sudo access: johndoe — Review necessity
  ...

══════════════════════════════════════════════════════
  AUDIT REPORT RESUMED
══════════════════════════════════════════════════════
  [PASS]  18 checks passed
  [WARN]   3 warnings (review)
  [FAIL]   1 checks failed (action required)

  Compliance Score : 82%
  Risk Level       : MEDIUM
```

Reports are saved automatically to `./audit_reports/audit_YYYYMMDD_HHMMSS.txt`.

---

## Project Structure

```
system-hardening-audit/
├── audit.sh              # Main audit script
├── audit_reports/        # Auto-generated timestamped reports (git-ignored)
├── docs/
│   └── controls_map.md   # Mapping of checks → ISO 27001 controls
└── README.md
```

---

## Key Checks in Detail

### 1 — Empty Passwords & UID 0 (Least Privilege)
Parses `/etc/shadow` for accounts with no password hash and `/etc/passwd` for any non-root account with UID 0 — a direct violation of the Least Privilege principle.

```bash
# Find empty-password accounts
awk -F: '($2 == "" || $2 == "!!") && $1 != "root" { print $1 }' /etc/shadow
```

### 2 — Firewall & Exposed Ports
Detects active UFW/IPTables and checks for high-risk ports (21/FTP, 23/Telnet, 3389/RDP, 5900/VNC, etc.) exposed on public interfaces.

### 3 — Critical File Permissions
Verifies that sensitive files follow strict permission standards:

| File | Expected Max Permissions |
|------|--------------------------|
| `/etc/shadow` | `640` |
| `/etc/sudoers` | `440` |
| `/etc/ssh/sshd_config` | `600` |
| `/etc/passwd` | `644` |

Also scans for **world-writable files** in `/etc` and `/usr`, and unexpected **SUID/SGID binaries** system-wide.

### 4 — SSH Hardening
Parses `sshd_config` for insecure directives. Best practice baseline:

```
PermitRootLogin         no
PasswordAuthentication  no
PermitEmptyPasswords    no
MaxAuthTries            3
Protocol                2
```

---

## 🧠 Concepts Applied

| Concept | How It Appears |
|---------|---------------|
| **Least Privilege** | Checks UID 0, sudo membership, SUID binaries, file permissions |
| **ISO 27001 A.9** | Access control for users, SSH, file system |
| **ISO 27001 A.12** | Logging (auditd), patch management |
| **ISO 27001 A.13** | Network security via firewall checks |
| **CIS Benchmark** | Permission baselines for critical Linux files |
| **Defense in Depth** | Six independent control layers audited |

---

## 🛠️ Planned Improvements

- [ ] `--fix` flag for auto-remediation of common findings
- [ ] JSON output format for SIEM integration
- [ ] Support for checking `fail2ban` configuration
- [ ] Docker container mode (run without root via namespace tricks)
- [ ] HTML report generation

---

## ⚠️ Disclaimer

This tool is for **authorized auditing purposes only**. Run it exclusively on systems you own or have explicit permission to audit. The author assumes no responsibility for misuse.

---

## 📚 References

- [ISO/IEC 27001:2022 — Information Security Controls](https://www.iso.org/standard/75652.html)
- [CIS Benchmarks — Linux](https://www.cisecurity.org/cis-benchmarks)
- [NIST SP 800-123 — Guide to General Server Security](https://csrc.nist.gov/publications/detail/sp/800-123/final)
- [Linux `chmod` and `stat` reference](https://man7.org/linux/man-pages/man1/chmod.1.html)

---

## 👤 Author

**[Tu Nombre]**  
Cloud & Security Operations | ISO 27001 | Linux Administration  
[LinkedIn](https://linkedin.com/in/tu-perfil) · [GitHub](https://github.com/tu-usuario)

---

*Built as a practical reinforcement of security governance principles — translating policy knowledge into working automation.*
