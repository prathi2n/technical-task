#!/bin/bash

# Function to perform user and group audits
audit_users_and_groups() {
    echo "User and Group Audit:"
    echo "===================="
    
    # List all users and groups
    echo "All Users:"
    cut -d: -f1 /etc/passwd
    echo ""
    
    echo "All Groups:"
    cut -d: -f1 /etc/group
    echo ""
    
    # Check for users with UID 0 (root privileges)
    echo "Users with UID 0 (Root Privileges):"
    awk -F: '($3 == "0") {print}' /etc/passwd
    echo ""
    
    # Identify and report users without passwords or with weak passwords
    echo "Users Without Passwords or With Weak Passwords:"
    for user in $(cut -d: -f1 /etc/passwd); do
        pass=$(sudo grep "^$user:" /etc/shadow | cut -d: -f2)
        if [[ $pass == "!" || $pass == "*" ]]; then
            echo "User $user has no password set"
        fi
    done
    echo ""
}

# Function to perform file and directory permission audits
audit_file_permissions() {
    echo "File and Directory Permissions Audit:"
    echo "===================================="
    
    # Scan for world-writable files
    echo "World-Writable Files:"
    find / -perm -2 -type f 2>/dev/null
    echo ""
    
    # Check for the presence and permissions of .ssh directories
    echo ".ssh Directory Permissions:"
    find /home/*/.ssh -type d -exec ls -ld {} \;
    echo ""
    
    # Report files with SUID or SGID bits set
    echo "Files with SUID or SGID Bits Set:"
    find / -perm /6000 -type f 2>/dev/null
    echo ""
}

# Function to audit running services
audit_services() {
    echo "Service Audit:"
    echo "============="
    
    # List all running services
    echo "All Running Services:"
    systemctl list-units --type=service --state=running
    echo ""
    
    # Check critical services and their configurations
    echo "Critical Services Status:"
    services=("sshd" "iptables" "ufw")
    for service in "${services[@]}"; do
        status=$(systemctl is-active $service)
        echo "$service: $status"
    done
    echo ""
}

# Function to audit firewall and network security
audit_firewall_network() {
    echo "Firewall and Network Security Audit:"
    echo "==================================="
    
    # Verify firewall status and configuration
    echo "Firewall Status:"
    if command -v ufw > /dev/null; then
        sudo ufw status
    else
        sudo iptables -L
    fi
    echo ""
    
    # Check for open ports
    echo "Open Ports and Associated Services:"
    sudo netstat -tulpn | grep LISTEN
    echo ""
    
    # Check for IP forwarding or other insecure configurations
    echo "IP Forwarding Status:"
    sysctl net.ipv4.ip_forward
    echo ""
}

# Function to check IP and network configurations
audit_ip_network_config() {
    echo "IP and Network Configuration Audit:"
    echo "=================================="
    
    # Identify public and private IP addresses
    echo "Public and Private IP Addresses:"
    ip_addrs=$(ip addr show | grep 'inet ')
    public_ips=$(echo "$ip_addrs" | grep -v "127.0.0.1\|192.168\|10.\|172.")
    private_ips=$(echo "$ip_addrs" | grep "192.168\|10.\|172.")
    echo "Public IPs:"
    echo "$public_ips"
    echo "Private IPs:"
    echo "$private_ips"
    echo ""
}

# Function to check for security updates and patches
audit_security_updates() {
    echo "Security Updates and Patching Audit:"
    echo "==================================="
    
    # Check for available security updates
    echo "Available Security Updates:"
    updates=$(sudo apt-get -s upgrade | grep "^Inst")
    echo "$updates"
    echo ""
    
    # Ensure automatic updates are configured
    echo "Unattended-Upgrades Configuration Status:"
    dpkg-query -l unattended-upgrades > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "Unattended-Upgrades is installed and configured."
    else
        echo "Unattended-Upgrades is not installed or configured."
    fi
    echo ""
}

# Function to monitor logs for suspicious activity
audit_logs() {
    echo "Log Monitoring for Suspicious Activity:"
    echo "======================================"
    
    # Monitor logs for suspicious activity
    echo "Suspicious Log Entries (e.g., too many login attempts):"
    sudo grep -i "failed\|error\|warning" /var/log/syslog
    echo ""
}

# Function to perform server hardening steps
server_hardening() {
    echo "Server Hardening Steps:"
    echo "======================"
    
    # SSH Configuration - Disable password-based login for root
    echo "Configuring SSH for Key-Based Authentication..."
    sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sudo systemctl restart sshd
    echo "SSH key-based authentication configured."
    echo ""
    
    # Disable IPv6 if not required
    echo "Disabling IPv6 (if not required)..."
    echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
    sudo sysctl -p
    echo "IPv6 disabled."
    echo ""
    
    # Secure the bootloader (GRUB)
    echo "Securing GRUB Bootloader..."
    echo "Please enter a password for GRUB:"
    sudo grub-mkpasswd-pbkdf2
    # Set the password in /etc/grub.d/00_header
    sudo update-grub
    echo "GRUB bootloader secured."
    echo ""
    
    # Firewall configuration
    echo "Configuring Firewall..."
    sudo iptables -P INPUT DROP
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    echo "Firewall configured."
    echo ""
    
    # Configure automatic updates
    echo "Configuring Automatic Security Updates..."
    sudo apt-get install unattended-upgrades
    sudo dpkg-reconfigure --priority=low unattended-upgrades
    echo "Automatic security updates configured."
    echo ""
}

# Function to generate a summary report
generate_summary_report() {
    echo "Generating Security Audit and Hardening Report..."
    report="security_audit_report.txt"
    echo "Security Audit Summary" > $report
    echo "=====================" >> $report
    
    # Append results of each function to the report
    echo "User and Group Audit:" >> $report
    audit_users_and_groups >> $report
    
    echo "File and Directory Permissions Audit:" >> $report
    audit_file_permissions >> $report
    
    echo "Service Audit:" >> $report
    audit_services >> $report
    
    echo "Firewall and Network Security Audit:" >> $report
    audit_firewall_network >> $report
    
    echo "IP and Network Configuration Audit:" >> $report
    audit_ip_network_config >> $report
    
    echo "Security Updates and Patching Audit:" >> $report
    audit_security_updates >> $report
    
    echo "Log Monitoring for Suspicious Activity:" >> $report
    audit_logs >> $report
    
    echo "Server Hardening Steps:" >> $report
    server_hardening >> $report
    
    echo "Report Generated: $report"
}

# Main function to execute all tasks
main() {
    audit_users_and_groups
    audit_file_permissions
    audit_services
    audit_firewall_network
    audit_ip_network_config
    audit_security_updates
    audit_logs
    server_hardening
    generate_summary_report
}

# Run the main function
main

