# SecuFix.sh v2 

**SecuFix.sh** is a comprehensive security audit and hardening script for Linux systems. It performs an in-depth analysis of your system configurations, verifying key security settings, and offering recommendations for improving the system's security posture. The audit includes checks for password policies, system hardening, logging, auditing, and much more.

P.S. It's a modified version of my last code, with a major update. I've added over 700 new lines of code, which has helped me learn more about Bash scripting and Linux systems. I'll update the features soon and fix some bugs. For now, I'll push it to GitHub. You're also more than welcome to edit, use, and publish it. - A.A


## Features
- **Password Security:**
  - Verifies maximum password age
  - Identifies accounts with empty or non-expiring passwords
- **System Hardening:**
  - Checks for core dump restrictions
  - Ensures ASLR (Address Space Layout Randomization) and NX/DEP are enabled
  - Verifies module blacklisting and USB storage restrictions
- **Logging and Auditing:**
  - Checks syslog/rsyslog status, auditd, and remote logging configuration
  - Verifies critical audit rules are set
- **System Services:**
  - Identifies unnecessary services (e.g., telnet, vsftpd)
  - Verifies that cron is running and checks file permissions
- **Malware Protection:**
  - Detects installed rootkit scanners (e.g., rkhunter, chkrootkit)
  - Scans for suspicious cron jobs and shell history entries
- **Filesystem Security:**
  - Ensures proper mount options (`nodev`, `nosuid`) for critical filesystems
  - Verifies separate partitions for `/home`, `/tmp`, `/var`
  - Ensures sticky bits are set on world-writable directories
- **Boot Security:**
  - Checks for a GRUB password
  - Verifies authentication requirements for single-user mode
  - Confirms Secure Boot is enabled (if applicable)
- **User Accounts:**
  - Ensures only the root account has UID 0
  - Identifies dormant user accounts and checks sudoers file permissions
- **Memory Protection:**
  - Ensures kernel memory protection mechanisms are enabled (e.g., stack protection, exec-shield)
- **Integrity Checking:**
  - Verifies installation and configuration of file integrity tools (e.g., AIDE, Tripwire)
- **Encryption:**
  - Verifies disk encryption status
  - Ensures TLS 1.3 support in OpenSSL

## Prerequisites
- **SecuFix.sh** requires `bash` and common Linux utilities like `grep`, `awk`, `sysctl`, and `systemctl`.
- It is recommended to run this script with `sudo` or root privileges to ensure full access to system configurations.

## Installation
1. Clone the repository to your local machine:
   ```bash
   git clone https://github.com/your-username/SecuFix.git
   ```
2. Navigate to the project directory:
   ```bash
   cd SecuFix
   ```
3. Make the script executable:
   ```bash
   chmod +x SecuFix.sh
   ```

## Usage
To run the script, simply execute it from the terminal:
```bash
./SecuFix.sh
```

The script will generate a detailed audit report, highlighting security vulnerabilities and areas requiring attention. The report is saved in a file named `SecuFix_report_YYYYMMDD_HHMMSS.txt` in the current working directory.

## Example Output:
```
[+] SYSTEM HARDENING
---------------------------------------
Core dumps are restricted: PASS
NX/DEP is supported by the CPU: PASS
...
[+] SCAN SUMMARY
---------------------------------------
Total checks passed: 45
Total warnings: 2
Total checks skipped: 3
...
```

## Report Details
- **Passed Checks**: Configurations that comply with best security practices.
- **Warning Checks**: Areas that may require further attention or modification.
- **Skipped Checks**: Checks that couldn't be completed due to missing tools or settings.

The full audit report will be saved in the current directory with a timestamped filename (e.g., `SecuFix_report_20250323_154500.txt`).
