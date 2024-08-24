#!/bin/bash

# Function to display top 10 most used applications (CPU & Memory)
display_top_apps() {
    echo "Top 10 CPU consuming applications:"
    ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 11
    echo ""
    echo "Top 10 Memory consuming applications:"
    ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -n 11
}

# Function to display network monitoring stats
display_network_monitor() {
    echo "Concurrent connections:"
    concurrent_connections=$(ss -t | grep ESTAB | wc -l)
    echo "$concurrent_connections"
    
    echo "Packet drops:"
    ip -s link | grep -A 2 "dropped"
    
    echo "Network traffic (MB):"
    ip -s link | awk '/RX:/{getline; print "In: " $1/1024/1024 " MB"}'
    ip -s link | awk '/TX:/{getline; print "Out: " $1/1024/1024 " MB"}'
}

# Function to display disk usage
display_disk_usage() {
    echo "Disk Usage:"
    df -h | awk '{ if($5 > 80) print $0; else print $0 }'
}

# Function to display system load
display_system_load() {
    echo "System Load:"
    uptime
    
    echo "CPU Usage Breakdown:"
    mpstat | grep -A 5 "%idle"
}

# Function to display memory usage
display_memory_usage() {
    echo "Memory Usage:"
    free -h
    
    echo "Swap Usage:"
    swapon -s
}

# Function to display process monitoring
display_process_monitoring() {
    echo "Active Processes:"
    ps aux | wc -l
    
    echo "Top 5 processes by CPU and Memory usage:"
    ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 6
}

# Function to display service monitoring
display_service_monitoring() {
    echo "Service Status:"
    for service in sshd nginx iptables; do
        systemctl is-active --quiet $service && echo "$service is running" || echo "$service is NOT running"
    done
}

# Function to handle custom dashboard
custom_dashboard() {
    case $1 in
        -cpu)
            display_system_load
            ;;
        -memory)
            display_memory_usage
            ;;
        -network)
            display_network_monitor
            ;;
        -disk)
            display_disk_usage
            ;;
        -process)
            display_process_monitoring
            ;;
        -service)
            display_service_monitoring
            ;;
        *)
            echo "Invalid option"
            ;;
    esac
}

# Main function to run the dashboard
main() {
    while true; do
        clear
        display_top_apps
        display_network_monitor
        display_disk_usage
        display_system_load
        display_memory_usage
        display_process_monitoring
        display_service_monitoring
        sleep 5
    done
}

# Handle command-line switches
if [ $# -eq 0 ]; then
    main
else
    custom_dashboard $1
fi

