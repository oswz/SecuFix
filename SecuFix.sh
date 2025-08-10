#!/bin/bash

# Set text format variables
BOLD=$(tput bold)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
NORMAL=$(tput sgr0)

# Start with banner
clear
echo "${BOLD}${BLUE}|==============================================|${NORMAL}"
echo "${BOLD}${BLUE}|       Linux System Hardening Scan     |${NORMAL}"
echo "${BOLD}${BLUE}|              Version 2.0                     |${NORMAL}"
echo "${BOLD}${BLUE}|                made by AA                    |${NORMAL}"
echo "${BOLD}${BLUE}|==============================================|${NORMAL}"

# Function to log results and count issues
WARNINGS=0
PASSED=0
SKIPPED=0

function log_result {
    local check_type="$1"
    local status="$2"
    local message="$3"
    
    if [ "$status" = "PASS" ]; then
        echo -e "[${GREEN}${BOLD}PASS${NORMAL}] ($check_type) $message"
        ((PASSED++))
    elif [ "$status" = "WARN" ]; then
        echo -e "[${RED}${BOLD}WARN${NORMAL}] ($check_type) $message"
        ((WARNINGS++))
    elif [ "$status" = "INFO" ]; then
        echo -e "[${BLUE}${BOLD}INFO${NORMAL}] $message"
    elif [ "$status" = "SKIP" ]; then
        echo -e "[${YELLOW}${BOLD}SKIP${NORMAL}] ($check_type) $message"
        ((SKIPPED++))
    fi
}

# Function to check and display the results
function check {
    local check_type="$1"
    local command="$2"
    local fail_message="$3"
    local pass_message="$4"
    
    log_result "INFO" "" "Checking: $check_type"
    
    if eval "$command" > /dev/null 2>&1; then
        log_result "$check_type" "PASS" "$pass_message"
        return 0
    else
        log_result "$check_type" "WARN" "$fail_message"
        return 1
    fi
}

# Function to determine the Linux distribution
function get_distro {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif [ -f /etc/redhat-release ]; then
        echo "redhat"
    else
        echo "unknown"
    fi
}

# Create temporary directory for findings
TMPDIR=$(mktemp -d)
REPORT_FILE="$TMPDIR/hardening_report.txt"
touch "$REPORT_FILE"

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    log_result "INFO" "" "This script is not running as root. Some checks may fail due to insufficient permissions."
    log_result "INFO" "" "For comprehensive results, run with sudo: sudo $0"
    echo ""
fi

# Get system information
distro=$(get_distro)
hostname=$(hostname)
kernel=$(uname -r)
date=$(date)

# Write header to report file
cat > "$REPORT_FILE" << EOF
# Linux System Hardening Report
- Hostname: $hostname
- Distribution: $distro
- Kernel: $kernel
- Scan Date: $date

## Security Findings Summary

EOF

log_result "INFO" "" "Detected Distribution: $distro"
log_result "INFO" "" "Kernel Version: $kernel"
echo ""
# 0. INSTALL DEPENDENCIES (first thing first)

# List of required dependencies
REQUIRED_TOOLS=("rkhunter" "chkrootkit" "aide" "auditd" "sysstat" "curl" "openssl" "mokutil")

# Function to check if a tool is installed
is_installed() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install missing tools
install_missing_tools() {
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! is_installed "$tool"; then
            echo "[WARN] $tool is not installed. Installing..."
            if [[ -f /etc/fedora-release ]]; then
                # Fedora package manager (dnf)
                sudo dnf install -y "$tool"
            elif [[ -f /etc/debian_version ]]; then
                # Debian/Ubuntu package manager (apt)
                sudo apt update && sudo apt install -y "$tool"
            elif [[ -f /etc/centos-release ]]; then
                # CentOS/RHEL package manager (yum)
                sudo yum install -y "$tool"
            else
                echo "[ERROR] Unsupported OS. Please install $tool manually."
            fi
        else
            echo "[INFO] $tool is already installed."
        fi
    done
}

# Install missing dependencies
install_missing_tools

# Confirm installation
echo ""
echo "[INFO] All required dependencies are installed or already present."


# 1. SECURITY FRAMEWORKS
echo "${BOLD}${BLUE}[+] SECURITY FRAMEWORKS${NORMAL}"

# Check for SELinux status
if command -v sestatus >/dev/null 2>&1; then
    SELINUX_STATUS=$(sestatus | grep "SELinux status:" | awk '{print $3}')
    if [ "$SELINUX_STATUS" = "enabled" ]; then
        log_result "SELinux" "PASS" "SELinux is enabled and enforcing"
        SELINUX_MODE=$(sestatus | grep "Current mode:" | awk '{print $3}')
        if [ "$SELINUX_MODE" != "enforcing" ]; then
            log_result "SELinux" "WARN" "SELinux is not in enforcing mode (current: $SELINUX_MODE)"
        fi
    else
        log_result "SELinux" "WARN" "SELinux is not enabled"
    fi
# Check for AppArmor status
elif command -v apparmor_status >/dev/null 2>&1; then
    if apparmor_status | grep -q "apparmor module is loaded"; then
        log_result "AppArmor" "PASS" "AppArmor is enabled"
        PROFILES=$(apparmor_status | grep -A1 "profiles are loaded" | grep -oE '[0-9]+')
        COMPLAIN=$(apparmor_status | grep -A1 "profiles are in complain mode" | grep -oE '[0-9]+')
        if [ "$COMPLAIN" -gt 0 ]; then
            log_result "AppArmor" "WARN" "$COMPLAIN AppArmor profiles are in complain mode"
        fi
    else
        log_result "AppArmor" "WARN" "AppArmor is not enabled"
    fi
else
    log_result "Security Framework" "WARN" "Neither SELinux nor AppArmor is installed"
fi

# 2. FIREWALL CONFIGURATION
echo ""
echo "${BOLD}${BLUE}[+] FIREWALL CONFIGURATION${NORMAL}"

# Check for firewall status based on distro
FIREWALL_ACTIVE=false
if [ "$distro" = "ubuntu" ] || [ "$distro" = "debian" ]; then
    if command -v ufw >/dev/null 2>&1; then
        UFW_STATUS=$(ufw status | grep "Status:" | awk '{print $2}')
        if [ "$UFW_STATUS" = "active" ]; then
            log_result "Firewall" "PASS" "UFW firewall is active"
            ufw status numbered | tail -n +5 > "$TMPDIR/firewall_rules.txt"
            log_result "INFO" "" "$(wc -l < "$TMPDIR/firewall_rules.txt") UFW rules configured"
            FIREWALL_ACTIVE=true
        else
            log_result "Firewall" "WARN" "UFW is installed but not active"
        fi
    else
        log_result "Firewall" "WARN" "UFW is not installed"
    fi
elif [ "$distro" = "fedora" ] || [ "$distro" = "centos" ] || [ "$distro" = "rhel" ]; then
    if command -v firewall-cmd >/dev/null 2>&1; then
        if systemctl is-active --quiet firewalld; then
            log_result "Firewall" "PASS" "Firewalld is active"
            firewall-cmd --list-all > "$TMPDIR/firewall_rules.txt"
            FIREWALL_ACTIVE=true
        else
            log_result "Firewall" "WARN" "Firewalld is installed but not active"
        fi
    else
        log_result "Firewall" "WARN" "Firewalld is not installed"
    fi
fi

# Check iptables as fallback
if [ "$FIREWALL_ACTIVE" = false ]; then
    if command -v iptables >/dev/null 2>&1; then
        IPT_RULES=$(iptables -L | grep -v "Chain" | grep -v "target" | grep -v "^$" | wc -l)
        if [ "$IPT_RULES" -gt 0 ]; then
            log_result "Firewall" "PASS" "Iptables has $IPT_RULES active rules"
            iptables -L > "$TMPDIR/firewall_rules.txt"
        else
            log_result "Firewall" "WARN" "No active iptables rules found"
        fi
    else
        log_result "Firewall" "WARN" "No firewall solution detected"
    fi
fi

# 3. SSH CONFIGURATION
echo ""
echo "${BOLD}${BLUE}[+] SSH CONFIGURATION${NORMAL}"

if [ -f /etc/ssh/sshd_config ]; then
    # Check for SSH root login
    if grep -q "^PermitRootLogin " /etc/ssh/sshd_config; then
        ROOT_LOGIN=$(grep "^PermitRootLogin " /etc/ssh/sshd_config | awk '{print $2}')
        if [ "$ROOT_LOGIN" = "no" ] || [ "$ROOT_LOGIN" = "prohibit-password" ]; then
            log_result "SSH" "PASS" "Root login via SSH is disabled or key-only"
        else
            log_result "SSH" "WARN" "Root login via SSH is allowed with password"
        fi
    else
        log_result "SSH" "WARN" "PermitRootLogin not explicitly set in sshd_config"
    fi

    # Check for password authentication
    if grep -q "^PasswordAuthentication " /etc/ssh/sshd_config; then
        PASS_AUTH=$(grep "^PasswordAuthentication " /etc/ssh/sshd_config | awk '{print $2}')
        if [ "$PASS_AUTH" = "no" ]; then
            log_result "SSH" "PASS" "Password authentication in SSH is disabled"
        else
            log_result "SSH" "WARN" "Password authentication in SSH is enabled"
        fi
    else
        log_result "SSH" "WARN" "PasswordAuthentication not explicitly set in sshd_config"
    fi
    
    # Check for protocol version
    if grep -q "^Protocol " /etc/ssh/sshd_config; then
        PROTO_VER=$(grep "^Protocol " /etc/ssh/sshd_config | awk '{print $2}')
        if [ "$PROTO_VER" = "2" ]; then
            log_result "SSH" "PASS" "SSH uses secure protocol version 2"
        else
            log_result "SSH" "WARN" "SSH is not explicitly set to use protocol version 2"
        fi
    fi
    
    # Check for idle timeout
    if grep -q "^ClientAliveInterval " /etc/ssh/sshd_config; then
        TIMEOUT=$(grep "^ClientAliveInterval " /etc/ssh/sshd_config | awk '{print $2}')
        if [ "$TIMEOUT" -gt 0 ] && [ "$TIMEOUT" -le 300 ]; then
            log_result "SSH" "PASS" "SSH idle timeout is properly configured ($TIMEOUT seconds)"
        else
            log_result "SSH" "WARN" "SSH idle timeout may be too long ($TIMEOUT seconds)"
        fi
    else
        log_result "SSH" "WARN" "SSH idle timeout not configured"
    fi
    
    # Check allowed authentication methods
    if grep -q "^AuthenticationMethods " /etc/ssh/sshd_config; then
        AUTH_METHODS=$(grep "^AuthenticationMethods " /etc/ssh/sshd_config | awk '{$1=""; print $0}' | tr -d ' ')
        if echo "$AUTH_METHODS" | grep -q "publickey"; then
            log_result "SSH" "PASS" "SSH requires public key authentication"
        else
            log_result "SSH" "WARN" "SSH doesn't explicitly require public key authentication"
        fi
    fi
else
    log_result "SSH" "SKIP" "SSH server is not installed"
fi

# 4. SYSTEM UPDATES
echo ""
echo "${BOLD}${BLUE}[+] SYSTEM UPDATES${NORMAL}"

UPDATE_CHECK=false
if [ "$distro" = "fedora" ] || [ "$distro" = "centos" ] || [ "$distro" = "rhel" ]; then
    if command -v dnf >/dev/null 2>&1; then
        UPDATES=$(dnf check-update -q | grep -v "^$" | wc -l)
        if [ "$UPDATES" -gt 0 ]; then
            log_result "Updates" "WARN" "$UPDATES packages need updating. Run 'sudo dnf update'"
        else
            log_result "Updates" "PASS" "System is up-to-date"
        fi
        UPDATE_CHECK=true
    elif command -v yum >/dev/null 2>&1; then
        UPDATES=$(yum check-update -q | grep -v "^$" | wc -l)
        if [ "$UPDATES" -gt 0 ]; then
            log_result "Updates" "WARN" "$UPDATES packages need updating. Run 'sudo yum update'"
        else
            log_result "Updates" "PASS" "System is up-to-date"
        fi
        UPDATE_CHECK=true
    fi
elif [ "$distro" = "ubuntu" ] || [ "$distro" = "debian" ]; then
    if command -v apt >/dev/null 2>&1; then
        apt update -qq >/dev/null 2>&1
        UPDATES=$(apt list --upgradable 2>/dev/null | grep -v "Listing..." | wc -l)
        if [ "$UPDATES" -gt 0 ]; then
            log_result "Updates" "WARN" "$UPDATES packages need updating. Run 'sudo apt upgrade'"
        else
            log_result "Updates" "PASS" "System is up-to-date"
        fi
        UPDATE_CHECK=true
    fi
elif [ "$distro" = "arch" ]; then
    if command -v pacman >/dev/null 2>&1; then
        pacman -Sy > /dev/null 2>&1
        UPDATES=$(pacman -Qu | wc -l)
        if [ "$UPDATES" -gt 0 ]; then
            log_result "Updates" "WARN" "$UPDATES packages need updating. Run 'sudo pacman -Syu'"
        else
            log_result "Updates" "PASS" "System is up-to-date"
        fi
        UPDATE_CHECK=true
    fi
fi

if [ "$UPDATE_CHECK" = false ]; then
    log_result "Updates" "SKIP" "Unknown distribution, cannot check for updates"
fi

# 5. FILE PERMISSIONS
echo ""
echo "${BOLD}${BLUE}[+] FILE PERMISSIONS${NORMAL}"

# Check for world-writable files (limit to key directories for efficiency)
log_result "INFO" "" "Checking for world-writable files in key directories..."
WORLD_WRITABLE=$(find /bin /sbin /usr/bin /usr/sbin /etc /var -xdev -type f -perm -002 2>/dev/null | head -n 20)
WORLD_WRITABLE_COUNT=$(echo "$WORLD_WRITABLE" | grep -v "^$" | wc -l)
if [ "$WORLD_WRITABLE_COUNT" -gt 0 ]; then
    log_result "Permissions" "WARN" "Found $WORLD_WRITABLE_COUNT world-writable files. First 20 saved to report."
    echo "$WORLD_WRITABLE" > "$TMPDIR/world_writable.txt"
else
    log_result "Permissions" "PASS" "No world-writable files found in key directories"
fi

# Check critical file permissions
if [ -f /etc/passwd ]; then
    PASSWD_PERM=$(stat -c '%a' /etc/passwd)
    if [ "$PASSWD_PERM" -le 644 ]; then
        log_result "Permissions" "PASS" "/etc/passwd has secure permissions ($PASSWD_PERM)"
    else
        log_result "Permissions" "WARN" "/etc/passwd has insecure permissions ($PASSWD_PERM)"
    fi
fi

if [ -f /etc/shadow ]; then
    SHADOW_PERM=$(stat -c '%a' /etc/shadow)
    if [ "$SHADOW_PERM" -le 400 ]; then
        log_result "Permissions" "PASS" "/etc/shadow has secure permissions ($SHADOW_PERM)"
    else
        log_result "Permissions" "WARN" "/etc/shadow has insecure permissions ($SHADOW_PERM)"
    fi
fi

if [ -f /etc/group ]; then
    GROUP_PERM=$(stat -c '%a' /etc/group)
    if [ "$GROUP_PERM" -le 644 ]; then
        log_result "Permissions" "PASS" "/etc/group has secure permissions ($GROUP_PERM)"
    else
        log_result "Permissions" "WARN" "/etc/group has insecure permissions ($GROUP_PERM)"
    fi
fi

# Check for SUID/SGID files
log_result "INFO" "" "Checking for SUID/SGID files..."
SUID_FILES=$(find / -path /proc -prune -o -type f -perm -4000 -o -perm -2000 2>/dev/null)
SUID_COUNT=$(echo "$SUID_FILES" | grep -v "^$" | wc -l)
if [ "$SUID_COUNT" -gt 0 ]; then
    echo "$SUID_FILES" > "$TMPDIR/suid_files.txt"
    log_result "Permissions" "INFO" "Found $SUID_COUNT SUID/SGID files. Review for any unusual entries."
fi

# 6. NETWORK SECURITY
echo ""
echo "${BOLD}${BLUE}[+] NETWORK SECURITY${NORMAL}"

# Check for listening ports
log_result "INFO" "" "Checking for listening services..."
LISTENING_SERVICES=$(ss -tuln | grep LISTEN)
echo "$LISTENING_SERVICES" > "$TMPDIR/listening_services.txt"
LISTENING_COUNT=$(echo "$LISTENING_SERVICES" | grep -v "^$" | wc -l)
log_result "Network" "INFO" "Found $LISTENING_COUNT listening services. Review for any unnecessary services."

# Check for IPv6 status
IPV6_STATUS=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)
if [ "$IPV6_STATUS" = "1" ]; then
    log_result "Network" "PASS" "IPv6 is disabled"
else
    log_result "Network" "INFO" "IPv6 is enabled. Disable if not needed."
fi

# Check for IP forwarding
IP_FORWARD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
if [ "$IP_FORWARD" = "0" ]; then
    log_result "Network" "PASS" "IP forwarding is disabled"
else
    log_result "Network" "WARN" "IP forwarding is enabled. Disable if not needed."
fi

# Check for ICMP redirects
ICMP_REDIRECT=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)
if [ "$ICMP_REDIRECT" = "0" ]; then
    log_result "Network" "PASS" "ICMP redirects are disabled"
else
    log_result "Network" "WARN" "ICMP redirects are enabled. Disable for security."
fi

# Check for SYN cookies
SYN_COOKIES=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)
if [ "$SYN_COOKIES" = "1" ]; then
    log_result "Network" "PASS" "SYN cookies are enabled"
else
    log_result "Network" "WARN" "SYN cookies are disabled. Enable for protection against SYN flood attacks."
fi

# 7. AUTHENTICATION AND PASSWORDS
echo ""
echo "${BOLD}${BLUE}[+] AUTHENTICATION AND PASSWORDS${NORMAL}"

# Check for password policies
if [ -f /etc/security/pwquality.conf ]; then
    MINLEN=$(grep -Po '^minlen\s*=\s*\K\d+' /etc/security/pwquality.conf 2>/dev/null)
    if [ -n "$MINLEN" ] && [ "$MINLEN" -ge 8 ]; then
        log_result "Password" "PASS" "Password minimum length is set to $MINLEN characters"
    else
        log_result "Password" "WARN" "Password minimum length is not set or less than 8 characters"
    fi
    
    DICTCHECK=$(grep -Po '^dictcheck\s*=\s*\K\d+' /etc/security/pwquality.conf 2>/dev/null)
    if [ "$DICTCHECK" = "1" ]; then
        log_result "Password" "PASS" "Dictionary word check is enabled"
    else
        log_result "Password" "WARN" "Dictionary word check is not enabled"
    fi
else
    log_result "Password" "WARN" "Password quality configuration file not found"
fi

# Check for password aging
if [ -f /etc/login.defs ]; then
    PASS_MAX_DAYS=$(grep -Po '^PASS_MAX_DAYS\s+\K\d+' /etc/login.defs 2>/dev/null)
    if [ -n "$PASS_MAX_DAYS" ] && [ "$PASS_MAX_DAYS" -le 90 ]; then
        log_result "Password" "PASS" "Password maximum age is set to $PASS_MAX_DAYS days"
    else
        log_result "Password" "WARN" "Password maximum age is not set or greater than 90 days"
    fi
else
    log_result "Password" "WARN" "Login definitions file not found"
fi

# Check for accounts with empty passwords
EMPTY_PASS=$(cut -d: -f1,2 /etc/shadow | grep '::' | cut -d: -f1)
if [ -z "$EMPTY_PASS" ]; then
    log_result "Password" "PASS" "No accounts with empty passwords found"
else
    EMPTY_PASS_COUNT=$(echo "$EMPTY_PASS" | wc -l)
    log_result "Password" "WARN" "Found $EMPTY_PASS_COUNT accounts with empty passwords"
    echo "$EMPTY_PASS" > "$TMPDIR/empty_passwords.txt"
fi

# Check for accounts with non-expiring passwords
NON_EXPIRE=$(cat /etc/shadow | grep -v ':\*:' | grep -v ':\!:' | awk -F: '{if($5 == 99999) print $1}')
if [ -z "$NON_EXPIRE" ]; then
    log_result "Password" "PASS" "No accounts with non-expiring passwords found"
else
    NON_EXPIRE_COUNT=$(echo "$NON_EXPIRE" | wc -w)
    log_result "Password" "WARN" "Found $NON_EXPIRE_COUNT accounts with non-expiring passwords"
    echo "$NON_EXPIRE" > "$TMPDIR/non_expiring_passwords.txt"
fi

# 8. SYSTEM HARDENING
echo ""
echo "${BOLD}${BLUE}[+] SYSTEM HARDENING${NORMAL}"

# Check for core dumps
if grep -q "^* hard core 0" /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null; then
    log_result "System" "PASS" "Core dumps are restricted"
else
    log_result "System" "WARN" "Core dumps are not restricted"
fi

# Check for NX/DEP support
if grep -q -E "flags.*(pae|nx)" /proc/cpuinfo 2>/dev/null; then
    log_result "System" "PASS" "NX/DEP is supported by the CPU"
else
    log_result "System" "WARN" "NX/DEP is not supported by the CPU"
fi

# Check for ASLR
ASLR=$(sysctl -n kernel.randomize_va_space 2>/dev/null)
if [ "$ASLR" = "2" ]; then
    log_result "System" "PASS" "Address Space Layout Randomization (ASLR) is fully enabled"
elif [ "$ASLR" = "1" ]; then
    log_result "System" "WARN" "ASLR is only partially enabled"
else
    log_result "System" "WARN" "ASLR is disabled"
fi

# Check for module loading
if [ -f /etc/modprobe.d/blacklist.conf ]; then
    log_result "System" "PASS" "Module blacklisting is configured"
else
    log_result "System" "WARN" "No module blacklisting found"
fi

# Check for USB storage
if grep -q "^install usb-storage /bin/true" /etc/modprobe.d/* 2>/dev/null; then
    log_result "System" "PASS" "USB storage is disabled"
else
    log_result "System" "INFO" "USB storage is enabled. Consider disabling if not needed."
fi

# 9. LOGGING AND AUDITING
echo ""
echo "${BOLD}${BLUE}[+] LOGGING AND AUDITING${NORMAL}"

# Check for syslog/rsyslog/journald
if systemctl is-active --quiet rsyslog 2>/dev/null; then
    log_result "Logging" "PASS" "Rsyslog service is active"
elif systemctl is-active --quiet syslog 2>/dev/null; then
    log_result "Logging" "PASS" "Syslog service is active"
else
    log_result "Logging" "WARN" "No active syslog service found"
fi

# Check for auditd
if command -v auditd >/dev/null 2>&1; then
    if systemctl is-active --quiet auditd; then
        log_result "Logging" "PASS" "Audit daemon is active"
        
        # Check for specific audit rules
        if grep -q "time-change" /etc/audit/audit.rules 2>/dev/null; then
            log_result "Audit" "PASS" "Time change events are being audited"
        else
            log_result "Audit" "WARN" "Time change events are not being audited"
        fi
        
        if grep -q "logins" /etc/audit/audit.rules 2>/dev/null; then
            log_result "Audit" "PASS" "Login events are being audited"
        else
            log_result "Audit" "WARN" "Login events are not being audited"
        fi
    else
        log_result "Logging" "WARN" "Audit daemon is installed but not active"
    fi
else
    log_result "Logging" "WARN" "Audit daemon is not installed"
fi

# Check for syslog remote logging
if grep -q "^*.*[[:space:]]*@" /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null; then
    log_result "Logging" "PASS" "Remote logging is configured"
else
    log_result "Logging" "INFO" "Remote logging is not configured"
fi

# 10. SYSTEM SERVICES
echo ""
echo "${BOLD}${BLUE}[+] SYSTEM SERVICES${NORMAL}"

# Check for unnecessary services
POTENTIAL_UNNECESSARY="rpcbind nfs-server telnet vsftpd rsh-server"
for service in $POTENTIAL_UNNECESSARY; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        log_result "Services" "WARN" "$service is running. Consider disabling if not needed."
    else
        log_result "Services" "PASS" "$service is not running"
    fi
done

# Check for X server
if systemctl is-active --quiet display-manager 2>/dev/null; then
    log_result "Services" "INFO" "X server is running. Consider disabling if this is a server."
else
    log_result "Services" "PASS" "X server is not running"
fi

# Check for running cron
if systemctl is-active --quiet cron 2>/dev/null || systemctl is-active --quiet crond 2>/dev/null; then
    log_result "Services" "PASS" "Cron service is running"
    
    # Check for cron file permissions
    if [ "$(stat -c '%a' /etc/crontab 2>/dev/null)" = "600" ] || [ "$(stat -c '%a' /etc/crontab 2>/dev/null)" = "644" ]; then
        log_result "Services" "PASS" "Crontab file has secure permissions"
    else
        log_result "Services" "WARN" "Crontab file has insecure permissions"
    fi
else
    log_result "Services" "WARN" "Cron service is not running"
fi

# 11. MALWARE CHECKS
echo ""
echo "${BOLD}${BLUE}[+] MALWARE CHECKS${NORMAL}"

# Check for rootkits
if command -v rkhunter >/dev/null 2>&1; then
    log_result "Malware" "PASS" "Rootkit Hunter is installed"
else
    log_result "Malware" "WARN" "Rootkit Hunter is not installed"
fi

if command -v chkrootkit >/dev/null 2>&1; then
    log_result "Malware" "PASS" "ChkRootkit is installed"
else
    log_result "Malware" "WARN" "ChkRootkit is not installed"
fi

# Check for suspicious cron jobs
SUSPICIOUS_CRON=$(grep -r "curl\|wget\|nc\|ncat\|fetch\|python\|perl\|bash\|sh\|php" /etc/cron* /var/spool/cron/* 2>/dev/null)
if [ -n "$SUSPICIOUS_CRON" ]; then
    log_result "Malware" "WARN" "Found potentially suspicious cron jobs. Review them carefully."
    echo "$SUSPICIOUS_CRON" > "$TMPDIR/suspicious_cron.txt"
else
    log_result "Malware" "PASS" "No suspicious cron jobs found"
fi

# Check for suspicious shell history
SUSPICIOUS_HISTORY=$(grep -E "curl\s+.*\|.*sh|wget\s+.*\|.*sh|base64\s+--decode|curl\s+.*\.sh|wget\s+.*\.sh" ~/.bash_history ~/.zsh_history 2>/dev/null)
if [ -n "$SUSPICIOUS_HISTORY" ]; then
    log_result "Malware" "WARN" "Found potentially suspicious commands in shell history"
    echo "$SUSPICIOUS_HISTORY" > "$TMPDIR/suspicious_history.txt"
else
    log_result "Malware" "PASS" "No suspicious commands found in shell history"
fi

# 12. FILESYSTEM SECURITY
echo ""
echo "${BOLD}${BLUE}[+] FILESYSTEM SECURITY${NORMAL}"

# Check for nodev, nosuid, noexec options
MOUNT_OPTIONS=$(mount | grep -E '(/home|/tmp|/var/tmp|/dev/shm)' | grep -v "nodev" | wc -l)
if [ "$MOUNT_OPTIONS" -eq 0 ]; then
    log_result "Filesystem" "PASS" "Key filesystems have nodev option set"
else
    log_result "Filesystem" "WARN" "Some key filesystems are missing the nodev option"
fi

# Check for separate partitions
if mount | grep -q " /var "; then
    log_result "Filesystem" "PASS" "/var is on a separate partition"
else
log_result "Filesystem" "WARN" "/var is not on a separate partition"
fi

if mount | grep -q " /tmp "; then
    log_result "Filesystem" "PASS" "/tmp is on a separate partition"
else
    log_result "Filesystem" "WARN" "/tmp is not on a separate partition"
fi

if mount | grep -q " /home "; then
    log_result "Filesystem" "PASS" "/home is on a separate partition"
else
    log_result "Filesystem" "WARN" "/home is not on a separate partition"
fi

# Check for sticky bit on world-writable directories
STICKY_BIT=$(find / -type d -perm -0002 ! -perm -1000 -ls 2>/dev/null)
if [ -z "$STICKY_BIT" ]; then
    log_result "Filesystem" "PASS" "All world-writable directories have sticky bit set"
else
    log_result "Filesystem" "WARN" "Some world-writable directories don't have sticky bit set"
    echo "$STICKY_BIT" > "$TMPDIR/missing_sticky_bit.txt"
fi

# 13. BOOT SECURITY
echo ""
echo "${BOLD}${BLUE}[+] BOOT SECURITY${NORMAL}"

# Check for GRUB password
if [ -f /boot/grub/grub.cfg ] && grep -q "password" /boot/grub/grub.cfg 2>/dev/null; then
    log_result "Boot" "PASS" "GRUB password is set"
elif [ -f /boot/grub2/grub.cfg ] && grep -q "password" /boot/grub2/grub.cfg 2>/dev/null; then
    log_result "Boot" "PASS" "GRUB2 password is set"
else
    log_result "Boot" "WARN" "No GRUB password detected"
fi

# Check for single-user mode password
if grep -q "SINGLE=/sbin/sulogin" /etc/sysconfig/init 2>/dev/null; then
    log_result "Boot" "PASS" "Single-user mode requires authentication"
else
    log_result "Boot" "WARN" "Single-user mode may not require authentication"
fi

# Check for secure boot
if command -v mokutil >/dev/null 2>&1; then
    if mokutil --sb-state | grep -q "SecureBoot enabled"; then
        log_result "Boot" "PASS" "Secure Boot is enabled"
    else
        log_result "Boot" "WARN" "Secure Boot is disabled"
    fi
else
    log_result "Boot" "SKIP" "Cannot check Secure Boot status"
fi

# 14. USER ACCOUNTS
echo ""
echo "${BOLD}${BLUE}[+] USER ACCOUNTS${NORMAL}"

# Check for users with UID 0
ROOT_USERS=$(awk -F: '($3 == 0) {print $1}' /etc/passwd)
ROOT_COUNT=$(echo "$ROOT_USERS" | wc -w)
if [ "$ROOT_COUNT" -eq 1 ] && [ "$ROOT_USERS" = "root" ]; then
    log_result "Users" "PASS" "Only root has UID 0"
else
    log_result "Users" "WARN" "Multiple users have UID 0: $ROOT_USERS"
fi

# Check for dormant accounts
DORMANT_THRESHOLD=90
LAST_LOGINS=$(lastlog -t $DORMANT_THRESHOLD | grep -v "Never" | grep -v "Username" | awk '{print $1}')
if [ -n "$LAST_LOGINS" ]; then
    DORMANT_COUNT=$(echo "$LAST_LOGINS" | wc -w)
    log_result "Users" "WARN" "Found $DORMANT_COUNT dormant accounts not logged in for $DORMANT_THRESHOLD days"
    echo "$LAST_LOGINS" > "$TMPDIR/dormant_accounts.txt"
else
    log_result "Users" "PASS" "No dormant accounts found"
fi

# Check for sudoers file permissions
if [ -f /etc/sudoers ]; then
    SUDOERS_PERM=$(stat -c '%a' /etc/sudoers)
    if [ "$SUDOERS_PERM" -eq 440 ]; then
        log_result "Users" "PASS" "Sudoers file has secure permissions"
    else
        log_result "Users" "WARN" "Sudoers file has insecure permissions: $SUDOERS_PERM"
    fi
fi

# Check for NOPASSWD in sudoers
if grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
    log_result "Users" "WARN" "NOPASSWD directive found in sudoers files"
else
    log_result "Users" "PASS" "No NOPASSWD directive found in sudoers files"
fi

# 15. MEMORY PROTECTION
echo ""
echo "${BOLD}${BLUE}[+] MEMORY PROTECTION${NORMAL}"

# Check for kernel protection mechanisms
if [ -f /proc/sys/kernel/kptr_restrict ]; then
    KPTR=$(cat /proc/sys/kernel/kptr_restrict)
    if [ "$KPTR" -ge 1 ]; then
        log_result "Memory" "PASS" "Kernel pointer address restriction is enabled"
    else
        log_result "Memory" "WARN" "Kernel pointer address restriction is disabled"
    fi
fi

if [ -f /proc/sys/kernel/dmesg_restrict ]; then
    DMESG=$(cat /proc/sys/kernel/dmesg_restrict)
    if [ "$DMESG" -eq 1 ]; then
        log_result "Memory" "PASS" "Dmesg restriction is enabled"
    else
        log_result "Memory" "WARN" "Dmesg restriction is disabled"
    fi
fi

# Check for kernel.exec-shield
if sysctl -n kernel.exec-shield 2>/dev/null; then
    EXEC_SHIELD=$(sysctl -n kernel.exec-shield)
    if [ "$EXEC_SHIELD" -eq 1 ]; then
        log_result "Memory" "PASS" "Exec-shield is enabled"
    else
        log_result "Memory" "WARN" "Exec-shield is disabled"
    fi
else
    log_result "Memory" "INFO" "Exec-shield not available"
fi

# Check for kernel stack protection
if grep -q "stack" /proc/cpuinfo; then
    log_result "Memory" "PASS" "Kernel stack protection is available"
else
    log_result "Memory" "WARN" "Kernel stack protection is not available"
fi

# 16. INTEGRITY CHECKING
echo ""
echo "${BOLD}${BLUE}[+] INTEGRITY CHECKING${NORMAL}"

# Check for AIDE
if command -v aide >/dev/null 2>&1; then
    log_result "Integrity" "PASS" "AIDE is installed"
    if [ -f /var/lib/aide/aide.db.gz ]; then
        log_result "Integrity" "PASS" "AIDE database exists"
    else
        log_result "Integrity" "WARN" "AIDE database does not exist. Run 'aide --init'"
    fi
else
    log_result "Integrity" "WARN" "AIDE is not installed"
fi

# Check for Tripwire
if command -v tripwire >/dev/null 2>&1; then
    log_result "Integrity" "PASS" "Tripwire is installed"
else
    log_result "Integrity" "INFO" "Tripwire is not installed"
fi

# 17. ENCRYPTION
echo ""
echo "${BOLD}${BLUE}[+] ENCRYPTION${NORMAL}"

# Check for disk encryption
if command -v cryptsetup >/dev/null 2>&1; then
    if cryptsetup status | grep -q "ACTIVE"; then
        log_result "Encryption" "PASS" "Disk encryption is active"
    else
        log_result "Encryption" "WARN" "Disk encryption is not active"
    fi
else
    log_result "Encryption" "WARN" "Cryptsetup is not installed"
fi

# Check for TLS versions
if command -v openssl >/dev/null 2>&1; then
    OPENSSL_VERSION=$(openssl version | awk '{print $2}')
    log_result "Encryption" "INFO" "OpenSSL version: $OPENSSL_VERSION"
    
    if openssl ciphers -v | grep -qi "TLSv1.3"; then
        log_result "Encryption" "PASS" "TLS 1.3 is supported"
    else
        log_result "Encryption" "WARN" "TLS 1.3 is not supported"
    fi
else
    log_result "Encryption" "SKIP" "OpenSSL is not installed"
fi

# 18. GENERATE SUMMARY
echo ""
echo "${BOLD}${BLUE}[+] SCAN SUMMARY${NORMAL}"

# Append summary to report file
cat >> "$REPORT_FILE" << EOF
## Summary

- **Passed Checks:** $PASSED
- **Warning Checks:** $WARNINGS
- **Skipped Checks:** $SKIPPED

EOF

# Print summary
echo "${BOLD}${GREEN}[+] Scan Complete${NORMAL}"
echo "-----------------------------------------------------"
echo "Total checks passed: ${GREEN}$PASSED${NORMAL}"
echo "Total warnings: ${RED}$WARNINGS${NORMAL}"
echo "Total checks skipped: ${YELLOW}$SKIPPED${NORMAL}"
echo "-----------------------------------------------------"

# Save final report
REPORT_PATH="$(pwd)/system_hardening_report_$(date +%Y%m%d_%H%M%S).txt"
cp "$REPORT_FILE" "$REPORT_PATH"
echo "Detailed report saved to: $REPORT_PATH"

# Cleanup temp files
rm -rf "$TMPDIR"

echo ""
echo "${BOLD}${BLUE}[+] RECOMMENDATIONS${NORMAL}"
echo "1. Review all warnings and address them according to your security policy"
echo "2. Consider implementing additional security measures:"
echo "   - Regular security audits and penetration testing"
echo "   - User security awareness training"
echo "   - Implementing a robust backup strategy"
echo "   - Setting up a security incident response plan"
echo "3. Consult your Linux distribution's security hardening guide"
echo "4. Review the CIS Benchmarks for your specific distribution"
echo "5. Consider using automated configuration management tools"
echo "6. Feel free to edit this bash script to suit your needs"



exit 0
