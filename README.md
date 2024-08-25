
# Proxy Server Monitoring Dashboard - Task 1

 # Overview

 This project involves a Bash script that provides a real-time monitoring dashboard for
 a proxy server. The script displays various system metrics, such as CPU usage, memory
 usage, network statistics, disk usage, and service statuses. It updates the dashboard
 every few seconds and allows users to call specific parts of the dashboard using
 command-line switches

 # Features
 1. Top 10 Most Used Applications:
 Displays the top 10 applications consuming the most CPU and memory
 resources.

 2. Network Monitoring:
 Shows the number of concurrent connections to the server.
 Displays packet drops.
 Tracks the volume of network traffic (MB in and out).

 3. Disk Usage Monitoring:
 Displays disk space usage by mounted partitions.
 Highlights partitions using more than 80% of the available space

  4. System Load Monitoring:
 Shows the current load average for the system.
 Provides a breakdown of CPU usage (user, system, idle, etc.).

 5. Memory Usage Monitoring:
 Displays total, used, and free memory.
 Shows swap memory usage.

 6. Process Monitoring:
 Displays the number of active processes.
 Shows the top 5 processes in terms of CPU and memory usage.

 7. Service Monitoring:
 Monitors the status of essential services like 
iptables .

 8. Custom Dashboard:-cpu , 
sshd , 
nginx/apache ,
 Provides command-line switches to view specific parts of the dashboard
 (e.g., -memory , -network , etc.).
 
# Prerequisites
 
 A Unix-based operating system (Linux, macOS).
 
 Basic knowledge of shell scripting and system administration.
 
 sysstat and 
net-tools packages must be installed on your system

# Installation
 Step 1: Clone the Repository

 Clone this repository to your local machine using the following command:

 git clone 
https://github.com/prathi2n/technical-task.git 

cd devops-project

 Step 2: Make the Script Executable Ensure the monitoring script has executable
 permissions:

 chmod +x monitor_dashboard_task1.sh

 Step 3: Install Required Packages Install the necessary packages for the script to run
 effectively:

 On Debian/Ubuntu:

 sudo apt-get update 
 
 sudo apt-get install sysstat net-tool

 On CentOS/RHEL:

 sudo yum install sysstat net-tools
 
 # Usage
 Running the Full Monitoring Dashboard To run the full monitoring dashboard, execute
 the script without any arguments:
 
 ./monitor_dashboard_task1.sh
 
 This will display a real-time dashboard that updates every few seconds with current
 system metrics.
 
 Viewing Specific Parts of the Dashboard You can use the following command-line
 switches to view specific sections of the 


dashboard:

 CPU Usage and System Load:

 ./monitor_dashboard_task1.sh -cpu

 Memory Usage:

 ./monitor_dashboard_task1.sh -memory

 Network Statistics:

 ./monitor_dashboard_task1.sh -network

 Disk Usage:

 ./monitor_dashboard_task1.sh -disk

 Process Monitoring:

 ./monitor_dashboard_task1.sh -process

 Service Status:

 ./monitor_dashboard_task1.sh -Service

 # Examples Here are a few examples to demonstrate how to use the script:
 
 Display Only Memory Usage:
 
  ./monitor_dashboard_task1.sh -memory

Display Network Monitoring Information:

 ./monitor_dashboard_task1.sh -network

 View Active Processes and Top Consumers:

 ./monitor_dashboard_task1.sh -process

# Extending the Script This script is designed to be modular and easy to extend. 

You can add more monitoring functions or customize existing ones by adding new sections to the script. Feel free to modify and adapt it to suit your specific needs.
 


## Task 2: Script for Automating Security Audits and Server Hardening on Linux Server

 # Overview
 This Bash script automates security audits and server hardening on Linux servers. It
 is designed to perform a comprehensive set of checks and implement security best
 practices to ensure your server is secure against common vulnerabilities and
 misconfigurations. The script is modular, reusable, and customizable, making it
 suitable for running across multiple servers.

# Features

 User and Group Audits: Identifies users with root privileges (UID 0) and checks
 for users without passwords or with weak
 passwords.

 File and Directory Permissions Audits: Scans for world-writable files, files
 with SUID/SGID bits set, and checks 
.ssh directory permissions

 Service Audits: Lists running services and checks for unauthorized services.
 Verifies the configuration of critical services.

 Firewall and Network Security Audits: Verifies active firewall status, lists
 open ports, and checks for IP forwarding or insecure network configurations.

 IP and Network Configuration Checks: Identifies public and private IP addresses
 assigned to the server.

 Security Updates and Patching Audits: Checks for available security updates and
 ensures automatic updates are configured.

 Log Monitoring: Monitors logs for suspicious activities, such as too many
 failed login attempts.

 Server Hardening: Implements security measures such as configuring SSH for key
based authentication, disabling IPv6 if not required, securing the GRUB
 bootloader, and setting up firewall rules.

Custom Configuration File: Supports custom security checks and configurations
 via a configuration file.

 Summary Report: Generates a detailed summary report
 (s
 ecurity_audit_report.txt ) documenting all audit findings and hardening
 actions.

 # Prerequisites
 A Linux server or virtual machine with Bash shell access.

 Root or 
sudo privileges to execute certain commands.

 Basic understanding of Linux system administration and security best practices

  # Installation
 1. Clone the Repository: git clone 
 https://github.com/prathi2n/technical-task.git

 2. Make the Script Executable: chmod +x security_audit_hardening.sh
  
  # Usage 
  To run
 the script, use the following command: 
 
 sudo ./security_audit_hardening.sh •
 
 Running with sudo is recommended to ensure the script has the necessary
 permissions to perform security checks and apply hardening measures. 
 
 Output The
 script outputs the results of each audit section directly to the console. It
 also generates a summary report file (security_audit_report.txt) with detailed
 information about the findings and actions taken during the security audit and
 hardening process.  
 Example Command Output

 User and Group Audit:
 
 All Users: root user1 user2 ...
 
# File and Directory Permissions Audit:

 World-Writable Files: /var/tmp/samplefile.txt ...
 
 Service Audit:
 All Running Services: nginx.service loaded active running A high performance web
 server and a reverse proxy server ssh.service loaded active running OpenBSD Secure
 Shell server ...

 Report Generated: security_audit_report.txt Customization The script is designed to be
 modular and easily customizable: • Adding Custom Checks: You can add additional
 security checks or hardening steps by editing the script and adding new functions or
 modifying existing ones. • Configuration File: The script supports using a
 configuration file to define custom security checks and configurations based on server
 roles or organizational policies.


 Example Customization To add a custom check for a specific service:
 1. Open the script in a text editor.
 2. Add a new function, e.g., check_custom_service().
 3. Insert the custom logic and integrate it into the main function.

Contributing Contributions are welcome! If you have ideas for new features, bug fixes  or improvements, please open an issue or submit a pull request.
 


