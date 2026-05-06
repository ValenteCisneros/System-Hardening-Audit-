# Controls Map — ISO 27001 Alignment

This document maps each `audit.sh` check to its corresponding ISO/IEC 27001:2022 control.

## Check 1 — Users & Privileges

| Check | ISO 27001 Control | Rationale |
|-------|-------------------|-----------|
| Empty password accounts | A.9.2.1 User registration | Accounts without passwords bypass authentication entirely |
| UID 0 non-root accounts | A.9.2.3 Privileged access management | Only root should have UID 0; others violate Least Privilege |
| Sudo group membership | A.9.2.3 | Elevated privileges must be justified and minimized |
| System accounts with login shell | A.9.2.1 | Service accounts should not have interactive access |
| Password aging (PASS_MAX_DAYS) | A.9.4.3 Password management | Enforces credential rotation policy |

## Check 2 — Firewall

| Check | ISO 27001 Control | Rationale |
|-------|-------------------|-----------|
| UFW/IPTables active | A.13.1.1 Network controls | All servers must have active perimeter controls |
| High-risk ports exposed | A.13.1.2 Network services | Ports 21/23/3389/5900 are high-risk if publicly exposed |

## Check 3 — File Permissions

| Check | ISO 27001 Control | Rationale |
|-------|-------------------|-----------|
| `/etc/shadow` permissions | A.9.4.1 Information access restriction | Readable only by root/shadow group |
| `/etc/sudoers` permissions | A.9.4.1 | World-readable sudoers is a privilege escalation risk |
| `/etc/ssh/sshd_config` | A.9.4.2 Secure log-on | Config must not be world-readable |
| World-writable files in /etc /usr | A.9.4.1 | Any user modifying system files = integrity violation |
| Unexpected SUID/SGID binaries | A.9.2.3 | SUID bits can be exploited for privilege escalation |

## Check 4 — SSH Hardening

| Check | ISO 27001 Control | Rationale |
|-------|-------------------|-----------|
| PermitRootLogin | A.9.4.2 Secure log-on | Direct root login disables accountability/traceability |
| PasswordAuthentication | A.9.4.2 | Key-based auth is significantly stronger than passwords |
| PermitEmptyPasswords | A.9.2.1 | Empty passwords on SSH is a critical vulnerability |
| MaxAuthTries | A.9.4.2 | Limits brute-force attempts |

## Check 5 — Patch Management

| Check | ISO 27001 Control | Rationale |
|-------|-------------------|-----------|
| Pending system updates | A.12.6.1 Technical vulnerability management | Unpatched systems are directly exploitable |
| Pending security patches | A.12.6.1 | Security patches must be applied as a priority |

## Check 6 — Audit Logging

| Check | ISO 27001 Control | Rationale |
|-------|-------------------|-----------|
| auditd active | A.12.4.1 Event logging | Kernel-level audit trail required for forensics |
| rsyslog active | A.12.4.1 | System log aggregation must be running |
| Log files present | A.12.4.3 Log protection | Logs must exist and be retained |

---

## Risk Scoring

| Score | Risk Level | Meaning |
|-------|-----------|---------|
| ≥ 85% | 🟢 LOW | Baseline security posture met |
| 60–84% | 🟡 MEDIUM | Notable gaps; remediation plan required |
| < 60% | 🔴 HIGH | Significant exposure; immediate action required |
