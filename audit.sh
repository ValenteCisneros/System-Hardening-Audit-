#!/usr/bin/env bash
# =============================================================================
#  System Hardening & Audit Tool
#  Aligns with: ISO/IEC 27001 — A.9 (Access Control), A.12 (Operations Security)
#               CIS Benchmark — Linux Security Guidelines
#               Principle of Least Privilege
#
#  Author : Valente Cisneros
#  Version: 1.0.0
#  License: MIT
# =============================================================================

set -euo pipefail

# Ensure we have a proper PATH for system commands
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"

# ─── Colors & Formatting ─────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

remediate() { log "${BLUE}  [REMEDIATION]${RESET} $*"; }

# ─── Report Setup ─────────────────────────────────────────────────────────────
REPORT_DIR="./audit_reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="${REPORT_DIR}/audit_${TIMESTAMP}.txt"
PASS=0
WARN=0
FAIL=0

mkdir -p "$REPORT_DIR"

# ─── Helpers ──────────────────────────────────────────────────────────────────
log()  { echo -e "$*" | tee -a "$REPORT_FILE"; }
pass() { PASS=$((PASS + 1)); log "${GREEN}  [PASS]${RESET} $*"; }
warn() { WARN=$((WARN + 1)); log "${YELLOW}  [WARN]${RESET} $*"; }
fail() { FAIL=$((FAIL + 1)); log "${RED}  [FAIL]${RESET} $*"; }
info() { log "${CYAN}  [INFO]${RESET} $*"; }
section() {
  log ""
  log "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"
  log "${BOLD}  $*${RESET}"
  log "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"
}
require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${RESET} This script requires root privileges."
    echo -e "        Run: ${BOLD}sudo ./audit.sh${RESET}"
    exit 1
  fi
}

# ─── BANNER ───────────────────────────────────────────────────────────────────
print_banner() {
  clear
  echo -e "${CYAN}${BOLD}"
  echo "  ╔═══════════════════════════════════════════════════════╗"
  echo "  ║       System Hardening & Audit Tool  v1.0.0           ║"
  echo "  ║   ISO 27001 · CIS Benchmark · Least Privilege         ║"
  echo "  ╚═══════════════════════════════════════════════════════╝"
  echo -e "${RESET}"
  echo -e "  ${DIM}Host   : $(hostname)${RESET}"
  echo -e "  ${DIM}Kernel : $(uname -r)${RESET}"
  echo -e "  ${DIM}Date   : $(date)${RESET}"
  echo -e "  ${DIM}Report : ${REPORT_FILE}${RESET}"
  echo ""
}

# ═════════════════════════════════════════════════════════════════════════════
# CHECK 1 — USER & PRIVILEGE AUDIT
# ISO 27001 Control: A.9.2 — User access management
# ═════════════════════════════════════════════════════════════════════════════
check_users() {
  section "CHECK 1 · USER & PRIVILEGE AUDIT (ISO 27001 A.9.2)"

  # 1.1 — Empty-password accounts
  info "Scanning for empty-password accounts..."
  local empty_pass
  empty_pass=$(awk -F: '($2 == "" || $2 == "!!" ) && $1 != "root" { print $1 }' /etc/shadow 2>/dev/null || true)

  if [[ -z "$empty_pass" ]]; then
    pass "No accounts with empty passwords found"
  else
    while IFS= read -r user; do
      fail "Account with no password detected: ${BOLD}$user${RESET}"
      remediate "Lock account: passwd -l $user"
    done <<< "$empty_pass"
  fi

  # 1.2 — UID 0 accounts (should ONLY be root)
  info "Checking for accounts with UID 0 (root privilege)..."
  local uid0_users
  uid0_users=$(awk -F: '$3 == 0 { print $1 }' /etc/passwd)

  while IFS= read -r user; do
    if [[ "$user" == "root" ]]; then
      pass "root is the only account with UID 0"
    else
      fail "Non-root account with UID 0: ${BOLD}$user${RESET} — Violates Least Privilege"
      remediate "Remove or modify user $user: deluser $user or usermod -u <non-zero-uid> $user"
    fi
  done <<< "$uid0_users"

  # 1.3 — Sudo group members
  info "Listing sudo/wheel group members..."
  local sudo_members=""
  if getent group sudo &>/dev/null; then
    sudo_members=$(getent group sudo | cut -d: -f4)
  elif getent group wheel &>/dev/null; then
    sudo_members=$(getent group wheel | cut -d: -f4)
  fi

  if [[ -z "$sudo_members" ]]; then
    pass "No additional users in sudo/wheel group"
  else
    warn "Users with sudo access: ${BOLD}${sudo_members}${RESET} — Review necessity"
    remediate "Review sudoers file: visudo and remove unnecessary sudo access"
  fi

  # 1.4 — Accounts with login shell that shouldn't have one
  info "Scanning for system accounts with an active login shell..."
  local sys_shell_users
  sys_shell_users=$(awk -F: '$3 < 1000 && $3 != 0 && $7 !~ /(nologin|false|sync)/ { print $1 "  →  shell: " $7 }' /etc/passwd)

  if [[ -z "$sys_shell_users" ]]; then
    pass "All system accounts have a restricted shell"
  else
    while IFS= read -r entry; do
      warn "System account with login shell: ${BOLD}$entry${RESET}"
      local user=$(echo "$entry" | awk '{print $1}')
      remediate "Set nologin shell: usermod -s /usr/sbin/nologin $user"
    done <<< "$sys_shell_users"
  fi

  # 1.5 — Password aging policy
  info "Checking password expiration policy..."
  local max_days
  max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
  if [[ -n "$max_days" && "$max_days" -le 90 ]]; then
    pass "PASS_MAX_DAYS = ${max_days} days (≤ 90) — Policy compliant"
  else
    warn "PASS_MAX_DAYS = ${max_days:-not set} — Recommended ≤ 90 days (ISO 27001 A.9.4)"
    remediate "Set PASS_MAX_DAYS to 90 or less: echo 'PASS_MAX_DAYS 90' >> /etc/login.defs"
  fi
}

# ═════════════════════════════════════════════════════════════════════════════
# CHECK 2 — FIREWALL AUDIT
# ISO 27001 Control: A.13.1 — Network security management
# ═════════════════════════════════════════════════════════════════════════════
check_firewall() {
  section "CHECK 2 · FIREWALL AUDIT (ISO 27001 A.13.1)"

  # 2.1 — UFW status
  if command -v ufw &>/dev/null; then
    info "UFW detected — Checking status..."
    local ufw_status
    ufw_status=$(ufw status | head -1)
    if echo "$ufw_status" | grep -qi "active"; then
      pass "UFW is ACTIVE"
      local rules_count
      rules_count=$(ufw status numbered 2>/dev/null | grep -c "^\[" || echo "0")
      info "  Active rules: ${rules_count}"
    else
      fail "UFW is INACTIVE — Server has no active firewall"
      remediate "Enable UFW: ufw enable"
    fi
  fi

  # 2.2 — IPTables fallback
  if ! command -v ufw &>/dev/null || ! ufw status | grep -qi "active"; then
    if command -v iptables &>/dev/null; then
      info "Checking IPTables..."
      local ipt_rules
      ipt_rules=$(iptables -L INPUT --line-numbers 2>/dev/null | grep -c "^[0-9]" || echo "0")
      if [[ "$ipt_rules" -gt 0 ]]; then
        pass "IPTables has ${ipt_rules} active rule(s) in INPUT chain"
      else
        fail "IPTables has no rules — Open network policy"
        remediate "Add basic iptables rules: iptables -A INPUT -i lo -j ACCEPT && iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"
      fi
    else
      fail "Neither UFW nor IPTables found — No firewall control detected"
      remediate "Install UFW: apt install ufw && ufw enable"
    fi
  fi

  # 2.3 — Open ports check (requires ss or netstat)
  info "Scanning listening ports..."
  local listening_ports=""
  if command -v ss &>/dev/null; then
    listening_ports=$(ss -tlnp 2>/dev/null | awk 'NR>1 {print $4, $6}' | grep -v "127.0.0.1\|::1" || true)
  elif command -v netstat &>/dev/null; then
    listening_ports=$(netstat -tlnp 2>/dev/null | awk 'NR>2 {print $4, $7}' | grep -v "127.0.0.1\|::1" || true)
  fi

  # High-risk ports
  local risky_ports=(21 23 25 110 143 445 3389 5900)
  local risky_found=false

  if [[ -n "$listening_ports" ]]; then
    while IFS= read -r port_line; do
      local port_num
      port_num=$(echo "$port_line" | grep -oP ':\K[0-9]+' | head -1 || echo "")
      if [[ -n "$port_num" ]]; then
        local risky=false
        for rp in "${risky_ports[@]}"; do
          if [[ "$port_num" == "$rp" ]]; then
            risky=true; risky_found=true
          fi
        done
        if $risky; then
          fail "HIGH-RISK port listening publicly: :${port_num}"
          remediate "Investigate and close unnecessary port $port_num: Check what service is running (ss -tlnp | grep :$port_num) and disable/firewall it"
        else
          info "Port listening: :${port_num}"
        fi
      fi
    done <<< "$listening_ports"
  fi

  if ! $risky_found; then
    pass "No high-risk ports detected on public interfaces"
  fi
}

# ═════════════════════════════════════════════════════════════════════════════
# CHECK 3 — FILE PERMISSIONS AUDIT (Least Privilege)
# ISO 27001 Control: A.9.4.1 — Information access restriction
# ═════════════════════════════════════════════════════════════════════════════
check_file_permissions() {
  section "CHECK 3 · FILE PERMISSIONS — LEAST PRIVILEGE (ISO 27001 A.9.4)"

  # Critical files: expected permissions
  declare -A CRITICAL_FILES=(
    ["/etc/shadow"]="000 or 640"
    ["/etc/passwd"]="644"
    ["/etc/sudoers"]="440"
    ["/etc/ssh/sshd_config"]="600"
    ["/etc/crontab"]="644"
    ["/boot/grub/grub.cfg"]="400 or 600"
  )

  # Max allowed octal permissions per file
  declare -A MAX_PERMS=(
    ["/etc/shadow"]="640"
    ["/etc/passwd"]="644"
    ["/etc/sudoers"]="440"
    ["/etc/ssh/sshd_config"]="600"
    ["/etc/crontab"]="644"
    ["/boot/grub/grub.cfg"]="600"
  )

  for file in "${!CRITICAL_FILES[@]}"; do
    if [[ ! -e "$file" ]]; then
      info "File not found (may not apply): $file"
      continue
    fi

    local actual_perm
    actual_perm=$(stat -c "%a" "$file")
    local expected_perm="${MAX_PERMS[$file]}"
    local actual_owner
    actual_owner=$(stat -c "%U:%G" "$file")

    # Compare: actual should be <= expected (numerically)
    if [[ "$actual_perm" -le "$expected_perm" ]]; then
      pass "${file}  →  perms: ${BOLD}${actual_perm}${RESET}  owner: ${actual_owner}"
    else
      fail "${file}  →  perms: ${BOLD}${actual_perm}${RESET} (expected ≤ ${expected_perm})  owner: ${actual_owner}"
      case "$file" in
        "/etc/shadow") remediate "Restrict shadow file permissions: chmod 640 /etc/shadow" ;;
        "/etc/passwd") remediate "Set passwd file permissions: chmod 644 /etc/passwd" ;;
        "/etc/sudoers") remediate "Set sudoers file permissions: chmod 440 /etc/sudoers" ;;
        "/etc/ssh/sshd_config") remediate "Restrict sshd_config permissions: chmod 600 /etc/ssh/sshd_config" ;;
        "/etc/crontab") remediate "Set crontab file permissions: chmod 644 /etc/crontab" ;;
        "/boot/grub/grub.cfg") remediate "Restrict grub.cfg permissions: chmod 600 /boot/grub/grub.cfg" ;;
        *) remediate "Fix permissions: chmod $expected_perm $file" ;;
      esac
    fi
  done

  # 3.2 — World-writable files (critical directories)
  info "Scanning for world-writable files in /etc and /usr ..."
  local ww_files
  ww_files=$(find /etc /usr -xdev -type f -perm -0002 2>/dev/null | head -20 || true)

  if [[ -z "$ww_files" ]]; then
    pass "No world-writable files found in /etc and /usr"
  else
    while IFS= read -r f; do
      fail "World-writable file: ${BOLD}$f${RESET}"
      remediate "Remove world-writable permission: chmod o-w $f"
    done <<< "$ww_files"
  fi

  # 3.3 — SUID/SGID binaries (unexpected)
  info "Scanning for unexpected SUID/SGID binaries..."
  local suid_files
  suid_files=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | grep -vE "(sudo|su|passwd|newgrp|gpasswd|chsh|chfn|mount|umount|ping|ping6|pkexec|polkit|at|crontab|ssh-agent|Xorg|screen|wall|write|chage|expiry|login|pt_chown|unix_chkpwd)" || true)

  if [[ -z "$suid_files" ]]; then
    pass "No unexpected SUID/SGID binaries found"
  else
    local count
    count=$(echo "$suid_files" | wc -l)
    warn "${count} additional SUID/SGID binary(s) found — Review:"
    while IFS= read -r f; do
      warn "  → ${BOLD}$f${RESET}"
      remediate "Investigate SUID/SGID binary $f: Consider removing the bit with chmod a-s $f if not absolutely necessary"
    done <<< "$suid_files"
  fi
}

# ═════════════════════════════════════════════════════════════════════════════
# CHECK 4 — SSH HARDENING AUDIT
# ISO 27001 Control: A.9.4.2 — Secure log-on procedures
# ═════════════════════════════════════════════════════════════════════════════
check_ssh() {
  section "CHECK 4 · SSH HARDENING (ISO 27001 A.9.4.2)"

  local sshd_config="/etc/ssh/sshd_config"

  if [[ ! -f "$sshd_config" ]]; then
    info "sshd_config not found — SSH may not be installed"
    return
  fi

  # Helper to read effective sshd option via sshd -T
  get_ssh_opt() {
    sshd -T 2>/dev/null | grep -i "^${1}" | awk '{print $2}' | head -1 || true
  }

  # 4.1 Root login
  local root_login
  root_login=$(get_ssh_opt "PermitRootLogin")
  if [[ "${root_login,,}" == "no" || "${root_login,,}" == "prohibit-password" ]]; then
    pass "PermitRootLogin = ${root_login} — Root SSH login blocked"
  else
    fail "PermitRootLogin = ${root_login:-not set} — Recommended: 'no' or 'prohibit-password'"
    remediate "Set PermitRootLogin to 'no' or 'prohibit-password': echo 'PermitRootLogin no' >> /etc/ssh/sshd_config && systemctl restart sshd"
  fi

  # 4.2 Password authentication
  local passwd_auth
  passwd_auth=$(get_ssh_opt "PasswordAuthentication")
  if [[ "${passwd_auth,,}" == "no" ]]; then
    pass "PasswordAuthentication = no — Only public key auth allowed"
  else
    warn "PasswordAuthentication = ${passwd_auth:-yes (default)} — Consider disabling (use keys only)"
    remediate "Disable password authentication: echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config && systemctl restart sshd"
  fi

  # 4.3 Empty passwords
  local empty_pw
  empty_pw=$(get_ssh_opt "PermitEmptyPasswords")
  if [[ "${empty_pw,,}" == "no" || -z "$empty_pw" ]]; then
    pass "PermitEmptyPasswords = no (default) — Empty passwords blocked"
  else
    fail "PermitEmptyPasswords = ${empty_pw} — CRITICAL RISK"
    remediate "Disable empty passwords: echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config && systemctl restart sshd"
  fi

  # 4.4 Protocol version (legacy check)
  local protocol
  protocol=$(get_ssh_opt "Protocol")
  if [[ -z "$protocol" || "$protocol" == "2" ]]; then
    pass "SSH Protocol 2 in use (default in modern OpenSSH)"
  else
    fail "SSH Protocol = ${protocol} — Only protocol 2 is permitted"
    remediate "Set Protocol to 2: echo 'Protocol 2' >> /etc/ssh/sshd_config && systemctl restart sshd"
  fi

  # 4.5 Max auth tries
  local max_tries
  max_tries=$(get_ssh_opt "MaxAuthTries")
  if [[ -n "$max_tries" && "$max_tries" -le 4 ]]; then
    pass "MaxAuthTries = ${max_tries} (≤ 4) — Brute-force protection enabled"
  else
    warn "MaxAuthTries = ${max_tries:-6 (default)} — Recommended: ≤ 4"
    remediate "Set MaxAuthTries to 4 or less: echo 'MaxAuthTries 4' >> /etc/ssh/sshd_config && systemctl restart sshd"
  fi
}

# ═════════════════════════════════════════════════════════════════════════════
# CHECK 5 — SYSTEM UPDATES & PATCHES
# ISO 27001 Control: A.12.6 — Technical vulnerability management
# ═════════════════════════════════════════════════════════════════════════════
check_updates() {
  section "CHECK 5 · PATCH MANAGEMENT (ISO 27001 A.12.6)"

  if command -v apt &>/dev/null; then
    info "Checking for pending package updates (apt)..."
    local pending
    pending=$(apt list --upgradable 2>/dev/null | tail -n +2 | wc -l)
    pending=$(echo "$pending" | tr -d '[:space:]')
    # Validate that the value is numeric
    if ! [[ "$pending" =~ ^[0-9]+$ ]]; then
      warn "Could not determine pending package count"
    elif [[ "$pending" -eq 0 ]]; then
      pass "System is up to date — No pending packages"
    elif [[ "$pending" -le 10 ]]; then
      warn "${pending} package(s) pending update"
      remediate "Apply updates: apt update && apt upgrade -y"
    else
      fail "${pending} packages pending — System is out of date (potential vulnerabilities)"
      remediate "Apply updates immediately: apt update && apt upgrade -y"
    fi

    # Check for security-only updates
    local sec_updates
    sec_updates=$(apt list --upgradable 2>/dev/null | grep -i "security" | wc -l)
    if [[ "$sec_updates" -gt 0 ]]; then
      fail "${sec_updates} SECURITY update(s) pending — Apply IMMEDIATELY"
      remediate "Apply security updates now: apt update && apt upgrade -y"
    fi

  elif command -v yum &>/dev/null || command -v dnf &>/dev/null; then
    info "Checking for pending packages (yum/dnf)..."
    local pkg_mgr="yum"
    command -v dnf &>/dev/null && pkg_mgr="dnf"
    local pending
    pending=$($pkg_mgr check-update --quiet 2>/dev/null | grep -c "^[a-zA-Z]" || echo "0")
    if [[ "$pending" -eq 0 ]]; then
      pass "System is up to date — No pending packages"
    else
      warn "${pending} package(s) pending update"
    fi
  else
    info "Package manager not recognized — Manual verification required"
  fi

  # Kernel version check (informational)
  info "Running kernel: $(uname -r)"
}

# ═════════════════════════════════════════════════════════════════════════════
# CHECK 6 — AUDIT LOGGING
# ISO 27001 Control: A.12.4 — Logging and monitoring
# ═════════════════════════════════════════════════════════════════════════════
check_logging() {
  section "CHECK 6 · AUDIT LOGGING (ISO 27001 A.12.4)"

  # auditd
  if systemctl is-active --quiet auditd 2>/dev/null; then
    pass "auditd is ACTIVE — Kernel event logging enabled"
  else
    warn "auditd is not active — Recommended for kernel-level event auditing"
    remediate "Install and enable auditd: apt install auditd && systemctl enable --now auditd"
  fi

  # rsyslog / syslog
  if systemctl is-active --quiet rsyslog 2>/dev/null || systemctl is-active --quiet syslog 2>/dev/null; then
    pass "rsyslog/syslog is active — System logging enabled"
  else
    warn "rsyslog not detected as active"
    remediate "Install and enable rsyslog: apt install rsyslog && systemctl enable --now rsyslog"
  fi

  # Log files exist
  for logfile in /var/log/auth.log /var/log/syslog /var/log/secure; do
    if [[ -f "$logfile" ]]; then
      local log_size
      log_size=$(du -sh "$logfile" 2>/dev/null | cut -f1)
      pass "Log file found: ${logfile} (${log_size})"
      break
    fi
  done

  # If no log files were found
  if [[ ! -f "/var/log/auth.log" && ! -f "/var/log/syslog" && ! -f "/var/log/secure" ]]; then
    warn "No standard log files found — Check logging configuration"
    remediate "Ensure rsyslog or syslog is running: systemctl start rsyslog || systemctl start syslog"
  fi
}

# ═════════════════════════════════════════════════════════════════════════════
# FINAL REPORT SUMMARY
# ═════════════════════════════════════════════════════════════════════════════
print_summary() {
  local total=$((PASS + WARN + FAIL))
  local score=0
  if [[ $total -gt 0 ]]; then score=$(( (PASS * 100) / total )); fi

  # Risk level
  local risk_level risk_color
  if   [[ $score -ge 85 ]]; then risk_level="LOW";    risk_color=$GREEN
  elif [[ $score -ge 60 ]]; then risk_level="MEDIUM"; risk_color=$YELLOW
  else                            risk_level="HIGH";   risk_color=$RED
  fi

  log ""
  log "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"
  log "${BOLD}  AUDIT SUMMARY${RESET}"
  log "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"
  log "  ${GREEN}[PASS]${RESET}  ${BOLD}${PASS}${RESET} controls passed"
  log "  ${YELLOW}[WARN]${RESET}  ${BOLD}${WARN}${RESET} warnings (review recommended)"
  log "  ${RED}[FAIL]${RESET}  ${BOLD}${FAIL}${RESET} controls failed (action required)"
  log ""
  log "  Compliance Score : ${BOLD}${score}%${RESET}"
  log "  Risk Level       : ${risk_color}${BOLD}${risk_level}${RESET}"
  log ""
  log "  Full report saved to: ${BOLD}${REPORT_FILE}${RESET}"
  log "${BOLD}${CYAN}══════════════════════════════════════════════════════${RESET}"
  log ""

  if [[ $FAIL -gt 0 ]]; then
    log "${RED}${BOLD}  ⚠  ${FAIL} critical failure(s) found. Review the report and apply remediations.${RESET}"
    log ""
  fi
}

# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════
main() {
  require_root
  print_banner

  # Write header to report
  {
    echo "====================================================="
    echo " System Hardening & Audit Report"
    echo " Host   : $(hostname)"
    echo " Kernel : $(uname -r)"
    echo " Date   : $(date)"
    echo "====================================================="
  } >> "$REPORT_FILE"

  check_users
  check_firewall
  check_file_permissions
  check_ssh
  check_updates
  check_logging
  print_summary
}

main "$@"