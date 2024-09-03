import nmap
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Define IP range
ip_range = "192.168.{}.{}"
log_file = "scan_results.log"

# Function to log messages both to the console and to a file, with a full timestamp in square brackets
def log_message(message):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S.%f]")  # Full timestamp with microseconds in brackets
    log_entry = f"{timestamp} {message}"
    print(log_entry)  # Print to console
    with open(log_file, "a") as file:
        file.write(log_entry + "\n")  # Write to log file

# Check if an IP address has a reachable device on port 80 or 443
def is_device_reachable(ip):
    for port in [80, 443]:
        try:
            # Try to create a connection to the IP on port 80 or 443
            socket.create_connection((ip, port), timeout=1)
            return True
        except:
            continue
    return False

# Scan open ports on a given IP
def scan_ports(ip):
    if not is_device_reachable(ip):
        log_message(f"IP {ip} is not reachable on port 80 or 443, skipping...")
        return []

    scanner = nmap.PortScanner()
    log_message(f"Scanning IP: {ip} for open ports...")
    scanner.scan(ip, '1-65535')  # Scan all ports
    open_ports = []
    for proto in scanner[ip].all_protocols():
        ports = scanner[ip][proto].keys()
        for port in ports:
            if scanner[ip][proto][port]['state'] == 'open':
                open_ports.append(port)
    if open_ports:
        log_message(f"Open ports found on {ip}: {open_ports}")
    else:
        log_message(f"No open ports found on {ip}")
    return open_ports

# Check if the PHP CGI vulnerability exists
def check_vulnerability(ip, port):
    log_message(f"Checking {ip}:{port} for PHP CGI vulnerability... [Placeholder for your implementation]")

# Main function
def main():
    with ThreadPoolExecutor(max_workers=100) as executor:
        for i in range(256):
            for j in range(256):
                ip = ip_range.format(i, j)
                open_ports = scan_ports(ip)
                if open_ports:
                    for port in open_ports:
                        executor.submit(check_vulnerability, ip, port)

if __name__ == "__main__":
    main()

