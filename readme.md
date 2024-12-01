# SecuFix - Linux System Hardening Checker

SecuFix is a script designed to help system administrators and Linux users improve the security of their systems by checking a range of common hardening configurations. The script verifies key system settings and provides feedback on whether they are secure or require changes. It supports multiple Linux distributions including **Ubuntu**, **Debian**, **Fedora**, **CentOS**, and **Arch Linux**.

## Features

- **SELinux/AppArmor Check**: Verifies whether SELinux or AppArmor is enabled.
- **Firewall Check**: Ensures that a firewall is active and configured correctly (`ufw`, `firewalld`, or `iptables`).
- **SSH Configuration**: Checks whether SSH root login and password authentication are disabled for better security.
- **System Updates**: Verifies if your system is up-to-date using the relevant package manager (`dnf`, `apt`, or `pacman`).
- **World-Writable Files**: Scans for world-writable files, which could pose a security risk.
- **Listening Services**: Lists all listening services and helps you review unnecessary ones.
- **Password Policy**: Ensures that your password policy enforces a minimum length of 8 characters.
- **Core Dump Restriction**: Checks whether core dumps are restricted for security reasons.
- **File Permissions for Sensitive Files**: Verifies that important system files (`/etc/passwd`, `/etc/shadow`) have secure permissions.

## Supported Distributions

- **Ubuntu/Debian**
- **Fedora/CentOS**
- **Arch Linux**

The script automatically detects the Linux distribution and adjusts the checks accordingly, such as using `ufw` for Ubuntu/Debian or `firewalld` for Fedora.

## Prerequisites

- A Linux system running **Ubuntu**, **Debian**, **Fedora**, **CentOS**, or **Arch Linux**.
- `bash` installed (most Linux distributions include `bash` by default).
- Root or sudo access for checking system configurations.

## Installation

1. Clone or download this repository to your local machine:

    ```bash
    git clone https://github.com/yourusername/securifix.git
    cd securifix
    ```

2. Make the script executable:

    ```bash
    chmod +x SecuFix.sh
    ```

3. (Optional) Move the script to a directory in your `$PATH` for easy access, e.g., `/usr/local/bin/`:

    ```bash
    sudo mv SecuFix.sh /usr/local/bin/SecuFix
    ```

## Usage

To run the script, use the following command in your terminal:

```bash
sudo ./SecuFix.sh
