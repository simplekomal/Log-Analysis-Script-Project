import re
import csv
from collections import defaultdict
import pandas as pd

# File paths
LOG_FILE = "sample.log"
output_file = "log_analysis_results.csv"  # Save the output to a CSV file
  # Set the output file to .xlsx

THRESHOLD = 10  # Configurable threshold for failed login attempts

def parse_log_file(log_file):
    """Parse the log file and extract useful information."""
    ip_requests = defaultdict(int)
    endpoint_access = defaultdict(int)
    failed_logins = defaultdict(int)

    with open(log_file, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.match(r'^([\d\.]+)', line)
            if ip_match:
                ip = ip_match.group(1)
                ip_requests[ip] += 1
            
            # Extract endpoint
            endpoint_match = re.search(r'\"[A-Z]+\s([^\s]+)\sHTTP', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_access[endpoint] += 1
            
            # Detect failed login attempts
            if '401' in line or 'Invalid credentials' in line:
                if ip_match:
                    failed_logins[ip] += 1

    return ip_requests, endpoint_access, failed_logins

import pandas as pd

import csv

def save_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, output_file):
    # Save the IP requests data
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['IP Address', 'Request Count'])  # Write header
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])
    
    # Save the most accessed endpoint
    with open(output_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Endpoint', 'Access Count'])  # Write header for this section
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

    # Save the suspicious activity
    with open(output_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['IP Address', 'Failed Login Count'])  # Write header for this section
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])


def main():
    # Parse log file
    ip_requests, endpoint_access, failed_logins = parse_log_file(LOG_FILE)
    
    # Sort requests per IP
    ip_requests = dict(sorted(ip_requests.items(), key=lambda x: x[1], reverse=True))
    print("Requests per IP:")
    for ip, count in ip_requests.items():
        print(f"{ip:<20} {count}")
    
    # Identify the most accessed endpoint
    most_accessed_endpoint = max(endpoint_access.items(), key=lambda x: x[1])
    print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    # Detect suspicious activity
    suspicious_activity = {ip: count for ip, count in failed_logins.items() if count > THRESHOLD}
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_activity.items():
        print(f"{ip:<20} {count}")
    
    # Save results to CSV
    save_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, output_file)

if __name__ == "__main__":
    main()
