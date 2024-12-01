#!/bin/bash

echo "-------------------------------------"
echo "Linux System Hardening Checker" 
echo             "by AA"
echo "-------------------------------------"

# Function to check and display the results
function check {
    echo -e "\n[INFO] Checking: $1"
    eval "$2"
    if [ $? -ne 0 ]; then
        echo -e "[WARNING] $3\n"
    else
        echo -e "[OK] $4\n"
    fi
}

# Function to determine the Linux distribution
function get_distro {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

# Get the distribution name
distro=$(get_distro)

echo -e "\n[INFO] Detected Distribution: $distro\n"

# 1. Check if SELinux/AppArmor is enabled
check "SELinux Status" \
    "if command -v sestatus >/dev/null 2>&1; then sestatus | grep 'SELinux status:' | grep -q 'enabled'; elif command -v apparmor_status >/dev/null 2>&1; then apparmor_status | grep -q 'apparmor is enabled'; else false; fi" \
    "SELinux/AppArmor is not enabled or not installed. Consider enabling SELinux or AppArmor for better security." \
    "SELinux/AppArmor is enabled."

# 2. Check for active firewall based on distro
if [ "$distro" == "ubuntu" ] || [ "$distro" == "debian" ]; then
    check "Firewall Status" \
        "systemctl is-active --quiet ufw" \
        "No active firewall found. Ensure ufw is installed and configured." \
        "UFW firewall is active."
elif [ "$distro" == "fedora" ] || [ "$distro" == "centos" ]; then
    check "Firewall Status" \
        "systemctl is-active --quiet firewalld" \
        "No active firewall found. Ensure firewalld is installed and configured." \
        "Firewalld is active."
else
    check "Firewall Status" \
        "iptables -L | grep -q 'Chain'" \
        "No active firewall found. Ensure iptables is installed and configured." \
        "Iptables is active."
fi

# 3. Check for SSH root login
check "SSH Root Login" \
    "grep -q '^PermitRootLogin no' /etc/ssh/sshd_config" \
    "Root login via SSH is allowed. Consider disabling it in /etc/ssh/sshd_config." \
    "Root login via SSH is disabled."

# 4. Check for password authentication in SSH
check "SSH Password Authentication" \
    "grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config" \
    "Password authentication in SSH is allowed. Consider using key-based authentication." \
    "Password authentication in SSH is disabled."

# 5. Check if system updates are available based on distro
echo -e "\n[INFO] Checking for system updates..."
if [ "$distro" == "fedora" ] || [ "$distro" == "centos" ]; then
    if ! dnf check-update > /dev/null 2>&1; then
        echo -e "[WARNING] System updates are available. Run 'sudo dnf update' to update your system.\n"
    else
        echo -e "[OK] System is up-to-date.\n"
    fi
elif [ "$distro" == "ubuntu" ] || [ "$distro" == "debian" ]; then
    if ! apt update > /dev/null 2>&1; then
        echo -e "[WARNING] System updates are available. Run 'sudo apt update' to update your system.\n"
    else
        echo -e "[OK] System is up-to-date.\n"
    fi
elif [ "$distro" == "arch" ]; then
    if ! pacman -Sy > /dev/null 2>&1; then
        echo -e "[WARNING] System updates are available. Run 'sudo pacman -Syu' to update your system.\n"
    else
        echo -e "[OK] System is up-to-date.\n"
    fi
else
    echo -e "[INFO] Unknown distro, skipping update check.\n"
fi

# 6. Check for world-writable files
echo -e "\n[INFO] Checking for world-writable files..."
WORLD_WRITABLE=$(find / -xdev -type f -perm -002 -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" 2>/dev/null)
if [ -n "$WORLD_WRITABLE" ]; then
    echo -e "[WARNING] Found world-writable files:\n$WORLD_WRITABLE\nConsider restricting permissions.\n"
else
    echo -e "[OK] No world-writable files found.\n"
fi

# 7. Check for unnecessary listening services
echo -e "\n[INFO] Checking for unnecessary listening services..."
LISTENING_SERVICES=$(ss -lntu)
echo "$LISTENING_SERVICES"
echo -e "[INFO] Review the above list to ensure only required services are running.\n"

# 8. Check for password policies
check "Password Policy" \
    "grep -q '^minlen=8' /etc/security/pwquality.conf" \
    "Weak password policy. Set minlen=8 or higher in /etc/security/pwquality.conf." \
    "Password policy enforces minimum length of 8 characters."

# 9. Check for core dumps
check "Core Dump Restriction" \
    "grep -q '^* hard core 0' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null" \
    "Core dumps are not restricted. Add '* hard core 0' to /etc/security/limits.conf to disable them." \
    "Core dumps are restricted."

# 10. Check for file permissions of /etc/passwd and /etc/shadow
echo -e "\n[INFO] Checking permissions for /etc/passwd and /etc/shadow..."
if [ "$(stat -c '%a' /etc/passwd)" -le 644 ] && [ "$(stat -c '%a' /etc/shadow)" -le 640 ]; then
    echo -e "[OK] File permissions for /etc/passwd and /etc/shadow are secure.\n"
else
    echo -e "[WARNING] File permissions for /etc/passwd or /etc/shadow are insecure. Adjust them using 'chmod'.\n"
fi

echo "-------------------------------------"
echo "Hardening Check Complete"
echo "-------------------------------------"

